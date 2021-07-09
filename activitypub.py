"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
from base64 import b64encode
import datetime
from hashlib import sha256
import logging

from google.cloud import ndb
from granary import as2, microformats2
import mf2util
from oauth_dropins.webutil import util
from oauth_dropins.webutil.handlers import cache_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import webapp2

import common
from models import Follower, MagicKey
from httpsig.requests_auth import HTTPSignatureAuth

CACHE_TIME = datetime.timedelta(seconds=15)

SUPPORTED_TYPES = (
    'Accept',
    'Announce',
    'Article',
    'Audio',
    'Create',
    'Delete',
    'Follow',
    'Image',
    'Like',
    'Note',
    'Undo',
    'Video',
)


def send(activity, inbox_url, user_domain):
    """Sends an ActivityPub request to an inbox.

    Args:
      activity: dict, AS2 activity
      inbox_url: string
      user_domain: string, domain of the bridgy fed user sending the request

    Returns:
      requests.Response
    """
    logging.info('Sending AP request from %s: %s', user_domain,
                 json_dumps(activity, indent=2))

    # prepare HTTP Signature (required by Mastodon)
    # https://w3c.github.io/activitypub/#authorization
    # https://tools.ietf.org/html/draft-cavage-http-signatures-07
    # https://github.com/tootsuite/mastodon/issues/4906#issuecomment-328844846
    acct = 'acct:%s@%s' % (user_domain, user_domain)
    key = MagicKey.get_or_create(user_domain)
    auth = HTTPSignatureAuth(secret=key.private_pem(), key_id=acct,
                             algorithm='rsa-sha256', sign_header='signature',
                             headers=('Date', 'Digest', 'Host'))

    # deliver to inbox
    body = json_dumps(activity).encode()
    headers = {
        'Content-Type': common.CONTENT_TYPE_AS2,
        # required for HTTP Signature
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
        'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        # required by Mastodon
        # https://github.com/tootsuite/mastodon/pull/14556#issuecomment-674077648
        'Digest': 'SHA-256=' + b64encode(sha256(body).digest()).decode(),
        'Host': util.domain_from_link(inbox_url),
    }
    return common.requests_post(inbox_url, data=body, auth=auth,
                                headers=headers)


class ActorHandler():
    """Serves /[DOMAIN], fetches its mf2, converts to AS Actor, and serves it."""

    @cache_response(CACHE_TIME)
    def get(self, domain):
        tld = domain.split('.')[-1]
        if tld in common.TLD_BLOCKLIST:
            self.error('', status=404)

        mf2 = util.fetch_mf2('http://%s/' % domain, gateway=True,
                             headers=common.HEADERS)
        # logging.info('Parsed mf2 for %s: %s', resp.url, json_dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, mf2['url'])
        logging.info('Representative h-card: %s', json_dumps(hcard, indent=2))
        if not hcard:
            self.error("""\
Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on %s""" % mf2['url'])

        key = MagicKey.get_or_create(domain)
        obj = self.postprocess_as2(as2.from_as1(microformats2.json_to_object(hcard)),
                                   key=key)
        obj.update({
            'inbox': f'{request.host_url}{domain}/inbox',
            'outbox': f'{request.host_url}{domain}/outbox',
            'following': f'{request.host_url}{domain}/following',
            'followers': f'{request.host_url}{domain}/followers',
        })
        logging.info('Returning: %s', json_dumps(obj, indent=2))

        self.response.headers.update({
            'Content-Type': common.CONTENT_TYPE_AS2,
            'Access-Control-Allow-Origin': '*',
        })
        self.response.write(json_dumps(obj, indent=2))


class InboxHandler():
    """Accepts POSTs to /[DOMAIN]/inbox and converts to outbound webmentions."""
    def post(self, domain):
        logging.info('Got: %s', self.request.body)

        # parse and validate AS2 activity
        try:
            activity = json_loads(self.request.body)
            assert activity
        except (TypeError, ValueError, AssertionError):
            self.error("Couldn't parse body as JSON", exc_info=True)

        obj = activity.get('object') or {}
        if isinstance(obj, str):
            obj = {'id': obj}

        type = activity.get('type')
        if type == 'Accept':  # eg in response to a Follow
            return  # noop
        if type == 'Create':
            type = obj.get('type')
        elif type not in SUPPORTED_TYPES:
            self.error('Sorry, %s activities are not supported yet.' % type,
                       status=501)

        # TODO: verify signature if there is one

        if type == 'Undo' and obj.get('type') == 'Follow':
            # skip actor fetch below; we don't need it to undo a follow
            return self.undo_follow(self.redirect_unwrap(activity))
        elif type == 'Delete':
            id = obj.get('id')

            # !!! temporarily disabled actually deleting Followers below because
            # mastodon.social sends Deletes for every Bridgy Fed account, all at
            # basically the same time, and we have many Follower objects, so we
            # have to do this table scan for each one, so the requests take a
            # long time and end up spawning extra App Engine instances that we
            # get billed for. and the Delete requests are almost never for
            # followers we have. TODO: revisit this and do it right.

            # if isinstance(id, str):
            #     # assume this is an actor
            #     # https://github.com/snarfed/bridgy-fed/issues/63
            #     for key in Follower.query().iter(keys_only=True):
            #         if key.id().split(' ')[-1] == id:
            #             key.delete()
            return

        # fetch actor if necessary so we have name, profile photo, etc
        for elem in obj, activity:
            actor = elem.get('actor')
            if actor and isinstance(actor, str):
                elem['actor'] = common.get_as2(actor).json()

        activity_unwrapped = self.redirect_unwrap(activity)
        if type == 'Follow':
            return self.accept_follow(activity, activity_unwrapped)

        # send webmentions to each target
        as1 = as2.to_as1(activity)
        self.send_webmentions(as1, proxy=True, protocol='activitypub',
                              source_as2=json_dumps(activity_unwrapped))

    def accept_follow(self, follow, follow_unwrapped):
        """Replies to an AP Follow request with an Accept request.

        Args:
          follow: dict, AP Follow activity
          follow_unwrapped: dict, same, except with redirect URLs unwrapped
        """
        logging.info('Replying to Follow with Accept')

        followee = follow.get('object')
        followee_unwrapped = follow_unwrapped.get('object')
        follower = follow.get('actor')
        if not followee or not followee_unwrapped or not follower:
            self.error('Follow activity requires object and actor. Got: %s' % follow)

        inbox = follower.get('inbox')
        follower_id = follower.get('id')
        if not inbox or not follower_id:
            self.error('Follow actor requires id and inbox. Got: %s', follower)

        # store Follower
        user_domain = util.domain_from_link(followee_unwrapped)
        Follower.get_or_create(user_domain, follower_id, last_follow=json_dumps(follow))

        # send AP Accept
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': util.tag_uri(self.request.host, 'accept/%s/%s' % (
                (user_domain, follow.get('id')))),
            'type': 'Accept',
            'actor': followee,
            'object': {
                'type': 'Follow',
                'actor': follower_id,
                'object': followee,
            }
        }
        resp = send(accept, inbox, user_domain)
        self.response.status_int = resp.status_code
        self.response.write(resp.text)

        # send webmention
        self.send_webmentions(as2.to_as1(follow), proxy=True, protocol='activitypub',
                              source_as2=json_dumps(follow_unwrapped))

    @ndb.transactional()
    def undo_follow(self, undo_unwrapped):
        """Replies to an AP Follow request with an Accept request.

        Args:
          undo_unwrapped: dict, AP Undo activity with redirect URLs unwrapped
        """
        logging.info('Undoing Follow')

        follow = undo_unwrapped.get('object', {})
        follower = follow.get('actor')
        followee = follow.get('object')
        if not follower or not followee:
            self.error('Undo of Follow requires object with actor and object. Got: %s' % follow)

        # deactivate Follower
        user_domain = util.domain_from_link(followee)
        follower_obj = Follower.get_by_id(Follower._id(user_domain, follower))
        if follower_obj:
            logging.info('Marking %s as inactive' % follower_obj.key)
            follower_obj.status = 'inactive'
            follower_obj.put()
        else:
            logging.warning('No Follower found for %s %s', user_domain, follower)


        # TODO send webmention with 410 of u-follow


ROUTES = [
    (r'/%s/?' % common.DOMAIN_RE, ActorHandler),
    (r'/%s/inbox' % common.DOMAIN_RE, InboxHandler),
]
