"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import json
import logging

import appengine_config

from granary import microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import util
import webapp2
from webmentiontools import send

import common


# https://www.w3.org/TR/activitypub/#retrieving-objects
CONTENT_TYPE_AS2 = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
CONTENT_TYPE_AS = 'application/activity+json'
CONNEG_HEADER = {
    'Accept': '%s; q=0.9, %s; q=0.8' % (CONTENT_TYPE_AS2, CONTENT_TYPE_AS),
}
PUBLIC_AUDIENCE = 'https://www.w3.org/ns/activitystreams#Public'

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

        obj = microformats2.json_to_object(hcard)
        obj.update({
            'inbox': '%s/%s/inbox' % (self.request.host_url, domain),
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
            obj = json.loads(self.request.body)
        except (TypeError, ValueError):
            msg = "Couldn't parse body as JSON"
            logging.error(msg, exc_info=True)
            self.abort(400, msg)

        obj = obj.get('object') or obj
        source = obj.get('url')
        if not source:
            self.abort(400, "Couldn't find original post URL")

        targets = util.get_list(obj, 'inReplyTo') + util.get_list(obj, 'like')
        if not targets:
            self.abort(400, "Couldn't find target URL (inReplyTo or object)")

        errors = []
        for target in targets:
            logging.info('Sending webmention from %s to %s', source, target)
            wm = send.WebmentionSend(source, target)
            if wm.send(headers=common.HEADERS):
                logging.info('Success: %s', wm.response)
            else:
                logging.warning('Failed: %s', wm.error)
                errors.append(wm.error)

        if errors:
            self.abort(errors[0].get('http_status') or 400,
                'Errors:\n' + '\n'.join(json.dumps(e, indent=2) for e in errors))


app = webapp2.WSGIApplication([
    (r'/(%s)/?' % common.DOMAIN_RE, ActorHandler),
    (r'/(%s)/inbox' % common.DOMAIN_RE, InboxHandler),
], debug=appengine_config.DEBUG)
