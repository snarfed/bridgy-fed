"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import datetime
import json
import logging
import string

import appengine_config

from granary import as2, microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import util
import webapp2

import common
from models import Follower, MagicKey, Response
from httpsig.requests_auth import HTTPSignatureAuth

SUPPORTED_TYPES = (
    'Announce',
    'Article',
    'Audio',
    'Create',
    'Follow',
    'Image',
    'Like',
    'Note',
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
    logging.info('Sending AP request from %s: %s', user_domain, activity)

    # prepare HTTP Signature (required by Mastodon)
    # https://w3c.github.io/activitypub/#authorization-lds
    # https://tools.ietf.org/html/draft-cavage-http-signatures-07
    # https://github.com/tootsuite/mastodon/issues/4906#issuecomment-328844846
    acct = 'acct:%s@%s' % (user_domain, user_domain)
    key = MagicKey.get_or_create(user_domain)
    auth = HTTPSignatureAuth(secret=key.private_pem(), key_id=acct,
                             algorithm='rsa-sha256')

    # deliver to inbox
    headers = {
        'Content-Type': common.CONTENT_TYPE_AS2,
        # required for HTTP Signature
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
        'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
    }
    return common.requests_post(inbox_url, json=activity, auth=auth, headers=headers)


class ActorHandler(webapp2.RequestHandler):
    """Serves /[DOMAIN], fetches its mf2, converts to AS Actor, and serves it."""

    def get(self, domain):
        url = 'http://%s/' % domain
        resp = common.requests_get(url)
        mf2 = mf2py.parse(resp.text, url=resp.url, img_with_alt=True)
        # logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, resp.url)
        logging.info('Representative h-card: %s', json.dumps(hcard, indent=2))
        if not hcard:
            common.error(self, """\
Couldn't find a <a href="http://microformats.org/wiki/representative-hcard-parsing">\
representative h-card</a> on %s""" % resp.url)

        key = MagicKey.get_or_create(domain)
        obj = common.postprocess_as2(as2.from_as1(microformats2.json_to_object(hcard)),
                                     key=key)
        obj.update({
            'inbox': '%s/%s/inbox' % (appengine_config.HOST_URL, domain),
        })
        logging.info('Returning: %s', json.dumps(obj, indent=2))

        self.response.headers.update({
            'Content-Type': common.CONTENT_TYPE_AS2,
            'Access-Control-Allow-Origin': '*',
        })
        self.response.write(json.dumps(obj, indent=2))


class InboxHandler(webapp2.RequestHandler):
    """Accepts POSTs to /[DOMAIN]/inbox and converts to outbound webmentions."""

    def post(self, domain):
        logging.info('Got: %s', self.request.body)

        # parse and validate AS2 activity
        try:
            activity = json.loads(self.request.body)
            assert activity
        except (TypeError, ValueError, AssertionError):
            common.error(self, "Couldn't parse body as JSON", exc_info=True)

        obj = activity.get('object') or {}
        if isinstance(obj, basestring):
            obj = {'id': obj}

        type = activity.get('type')
        if type == 'Create':
            type = obj.get('type')
        if type not in SUPPORTED_TYPES:
            common.error(self, 'Sorry, %s activities are not supported yet.' % type,
                         status=501)

        # TODO: verify signature if there is one

        # fetch actor if necessary so we have name, profile photo, etc
        if type in ('Announce', 'Like', 'Follow'):
            for elem in obj, activity:
                actor = elem.get('actor')
                if actor and isinstance(actor, basestring):
                    elem['actor'] = common.get_as2(actor).json()

        activity_unwrapped = common.redirect_unwrap(activity)
        if type == 'Follow':
            self.accept_follow(activity, activity_unwrapped)
            return

        # send webmentions to each target
        as1 = as2.to_as1(activity_unwrapped)
        common.send_webmentions(self, as1, proxy=True, protocol='activitypub',
                                source_as2=json.dumps(activity_unwrapped))

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
            common.error(self, 'Follow activity requires object and actor. Got: %s' % follow)

        inbox = follower.get('inbox')
        follower_id = follower.get('id')
        if not inbox or not follower_id:
            common.error(self, 'Follow actor requires id and inbox. Got: %s', follower)

        # store Follower
        user_domain = util.domain_from_link(followee_unwrapped)
        Follower.get_or_create(user_domain, follower_id, last_follow=json.dumps(follow))

        # send AP Accept
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': util.tag_uri(appengine_config.HOST, 'accept/%s/%s' % (
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
        common.send_webmentions(
            self, as2.to_as1(follow), proxy=True, protocol='activitypub',
            source_as2=json.dumps(follow_unwrapped))


app = webapp2.WSGIApplication([
    (r'/%s/?' % common.DOMAIN_RE, ActorHandler),
    (r'/%s/inbox' % common.DOMAIN_RE, InboxHandler),
], debug=appengine_config.DEBUG)
