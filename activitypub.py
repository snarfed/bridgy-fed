"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import json
import logging

import appengine_config

from granary import as2, microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import util
import webapp2

import common
from models import MagicKey


# https://www.w3.org/TR/activitypub/#retrieving-objects
CONTENT_TYPE_AS2 = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
CONTENT_TYPE_AS = 'application/activity+json'
CONNEG_HEADER = {
    'Accept': '%s; q=0.9, %s; q=0.8' % (CONTENT_TYPE_AS2, CONTENT_TYPE_AS),
}
SUPPORTED_TYPES = (
    'Announce',
    'Article',
    'Audio',
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
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

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
            'Content-Type': CONTENT_TYPE_AS2,
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

        type = activity.get('type')
        if type not in SUPPORTED_TYPES:
            common.error(self, 'Sorry, %s activities are not supported yet.' % type,
                         status=501)

        # TODO: verify signature if there is one

        # fetch actor if necessary so we have name, profile photo, etc
        if activity.get('type') in ('Like', 'Announce'):
            actor = activity.get('actor')
            if actor:
                activity['actor'] = common.requests_get(
                    actor, parse_json=True, headers=CONNEG_HEADER)

        # send webmentions to each target
        as1 = as2.to_as1(activity)
        common.send_webmentions(self, as1, protocol='activitypub',
                                source_as2=json.dumps(activity))


app = webapp2.WSGIApplication([
    (r'/%s/?' % common.DOMAIN_RE, ActorHandler),
    (r'/%s/inbox' % common.DOMAIN_RE, InboxHandler),
], debug=appengine_config.DEBUG)
