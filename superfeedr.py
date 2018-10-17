"""Superfeedr callback handlers.

Not really sure what this will be yet. Background:
https://github.com/snarfed/bridgy-fed/issues/18#issuecomment-430731476
https://documentation.superfeedr.com/publishers.html
"""
import logging

import webapp2

import appengine_config


class SuperfeedrHandler(webapp2.RequestHandler):
    """Superfeedr subscription callback handler.

    https://documentation.superfeedr.com/publishers.html#subscription-callback
    """

    def post(self):
        logging.info('Got:\n%s', self.request.body)
        self.response.status_int = 204

    get = post


app = webapp2.WSGIApplication([
    (r'/superfeedr/.*', SuperfeedrHandler),
], debug=appengine_config.DEBUG)
