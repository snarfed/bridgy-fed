"""Handles inbound webmentions.
"""
import copy
import json
import logging

import appengine_config

from granary import microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import util
import webapp2

import activitypub
import common


class WebmentionHandler(webapp2.RequestHandler):
    """Handles inbound webmention, converts to ActivityPub inbox delivery."""

    def post(self):
        logging.info('Params: %s', self.request.params.items())
        source = util.get_required_param(self, 'source')
        target = util.get_required_param(self, 'target')

        # fetch source page, convert to ActivityStreams
        resp = common.requests_get(source)
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        entry = mf2util.find_first_entry(mf2, ['h-entry'])
        logging.info('First entry: %s', json.dumps(entry, indent=2))
        source_obj = microformats2.json_to_object(entry)
        logging.info('Converted to AS: %s', json.dumps(source_obj, indent=2))

        # fetch target page as AS object
        target_obj = common.requests_get(target, json=True,
                                         headers=activitypub.CONNEG_HEADER)

        # fetch actor as AS object
        actor_url = target_obj.get('actor') or target_obj.get('attributedTo')
        if not actor_url:
            self.abort(400, 'Target object has no actor or attributedTo')

        actor = common.requests_get(actor_url, json=True,
                                    headers=activitypub.CONNEG_HEADER)

        # deliver source object to target actor's inbox
        inbox_url = actor.get('inbox')
        if not inbox_url:
            self.abort(400, 'Target actor has no inbox')

        headers = copy.copy(common.HEADERS)
        headers['Content-Type'] = activitypub.CONTENT_TYPE_AS
        requests.post(inbox_url, json=source_obj, headers=headers)


app = webapp2.WSGIApplication([
    ('/webmention', WebmentionHandler),
], debug=appengine_config.DEBUG)
