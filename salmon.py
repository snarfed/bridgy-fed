"""Handles requests for Salmon endpoints: actors, inbox, etc.
"""
import json
import logging

import appengine_config

from oauth_dropins.webutil import util
import webapp2
from webmentiontools import send

import common


class SlapHandler(webapp2.RequestHandler):
    """Accepts POSTs to /[DOMAIN]/salmon and converts to outbound webmentions."""

    # TODO: unify with activitypub
    def post(self, domain):
        logging.info('Got: %s', self.request.body)
        try:
            pass # TODO
        except (TypeError, ValueError):
            msg = "Couldn't parse body as XML magic envelope"
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
    (r'/(?:acct)?@%s/salmon' % common.DOMAIN_RE, SlapHandler),
], debug=appengine_config.DEBUG)
