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
from webmentiontools import send

import common
from models import MagicKey, Response


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
            self.abort(400, """\
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
        try:
            activity = json.loads(self.request.body)
            assert activity
        except (TypeError, ValueError, AssertionError):
            msg = "Couldn't parse body as JSON"
            logging.error(msg, exc_info=True)
            self.abort(400, msg)

        type = activity.get('type')
        if type not in SUPPORTED_TYPES:
            common.error(self, '%s activities are not supported yet.' % type)

        # TODO: verify signature if there is one

        source = activity.get('url') or activity.get('id')
        obj = activity.get('object')
        obj_url = util.get_url(obj)

        targets = set(util.get_list(activity, 'inReplyTo'))
        if isinstance(obj, dict):
            if not source:
                source = obj_url or obj.get('id')
            targets |= util.get_list(obj, 'inReplyTo')

        if not source:
            self.abort(400, "Couldn't find source URL or id")

        if obj_url:
            targets.add(obj_url)

        if not targets:
            self.abort(400, "Couldn't find target URL (inReplyTo or object)")

        errors = []
        for target in targets:
            response = Response.get_or_insert(
                '%s %s' % (source, target), direction='in', protocol='activitypub',
                source_as2=json.dumps(activity))

            wm_source = (response.proxy_url() if type in ('Like', 'Announce')
                         else source)
            logging.info('Sending webmention from %s to %s', wm_source, target)
            wm = send.WebmentionSend(wm_source, target)
            if wm.send(headers=common.HEADERS):
                logging.info('Success: %s', wm.response)
                response.status = 'complete'
            else:
                logging.warning('Failed: %s', wm.error)
                errors.append(wm.error)
                response.status = 'error'
            response.put()

        if errors:
            msg = 'Errors:\n' + '\n'.join(json.dumps(e, indent=2) for e in errors)
            common.error(self, msg, errors[0].get('http_status') or 400)


app = webapp2.WSGIApplication([
    (r'/%s/?' % common.DOMAIN_RE, ActorHandler),
    (r'/%s/inbox' % common.DOMAIN_RE, InboxHandler),
], debug=appengine_config.DEBUG)
