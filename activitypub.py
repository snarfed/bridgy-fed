# coding=utf-8
"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import json
import logging

import appengine_config

from granary import microformats2
import mf2py
import mf2util
import requests
import webapp2


# https://www.w3.org/TR/activitypub/#retrieving-objects
CONTENT_TYPE = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
USER_AGENT = 'bridgy-activitypub (https://activitypub.brid.gy/)'


class ActorHandler(webapp2.RequestHandler):
    """Serves /[DOMAIN], fetches its mf2, converts to AS Actor, and serves it."""

    def get(self, domain):
        url = 'https://%s/' % domain
        resp = requests.get(url=url, headers={
            'User-Agent': USER_AGENT,
        })
        resp.raise_for_status()
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, resp.url)
        logging.info('Representative h-card: %s', json.dumps(hcard, indent=2))

        obj = microformats2.json_to_object(hcard)
        obj.update({
            'inbox': '%s/%s/inbox' % (self.request.host_url, domain),
        })
        logging.info('Returning: %s', json.dumps(obj, indent=2))

        self.response.headers.update({
            'Content-Type': CONTENT_TYPE,
            'Access-Control-Allow-Origin': '*',
        })
        self.response.write(json.dumps(obj, indent=2))


app = webapp2.WSGIApplication(
    [(r'/([^/]+\.[^/]+)/?', ActorHandler),
    ], debug=appengine_config.DEBUG)
