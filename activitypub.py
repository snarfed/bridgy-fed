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
from models import MagicKey, Response
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

        if type == 'Follow':
            self.accept_follow(activity)
            return

        # fetch actor if necessary so we have name, profile photo, etc
        if type in ('Like', 'Announce'):
            for elem in obj, activity:
                actor = elem.get('actor')
                if actor and isinstance(actor, basestring):
                    elem['actor'] = common.get_as2(actor).json()

        # send webmentions to each target
        as1 = as2.to_as1(activity)
        source_as2 = json.dumps(common.redirect_unwrap(activity))
        common.send_webmentions(self, as1, proxy=True, protocol='activitypub',
                                source_as2=source_as2)

    def accept_follow(activity):
        logging.info('Sending Accept to inbox')

        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': activity['id'],
            'type': 'Accept',
            'actor': activity['object'],
            'object': {
              'type': 'Follow',
               'actor': activity['actor'],
               'object': activity['object'],
            }
        }

        # source domain - this is still wrong in so many ways ... :)
        source_domain = string.replace(activity['object'], 'https://fed.brid.gy/r/', '')
        source_domain = string.replace(source_domain, 'http://', '')
        source_domain = string.replace(source_domain, 'https://', '')
        logging.info('source domain ' + source_domain)

        # inbox url.
        target = activity['actor']
        actor = common.get_as2(target).json()
        inbox_url = actor.get('inbox')
        logging.info('Inbox url ' + inbox_url)

        acct = 'acct:%s@%s' % (source_domain, source_domain)
        key = MagicKey.get_or_create(source_domain)
        signature = HTTPSignatureAuth(secret=key.private_pem(), key_id=acct,
                                 algorithm='rsa-sha256')

        # deliver source object to target actor's inbox.
        headers = {
            'Content-Type': common.CONTENT_TYPE_AS2,
            # required for HTTP Signature
            # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
            'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'signature': signature,
        }
        resp = common.requests_post(inbox_url, json=activity_accept, headers=headers)
        self.response.write(resp.text)


app = webapp2.WSGIApplication([
    (r'/%s/?' % common.DOMAIN_RE, ActorHandler),
    (r'/%s/inbox' % common.DOMAIN_RE, InboxHandler),
], debug=appengine_config.DEBUG)
