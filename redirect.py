"""Simple endpoint that redirects to the embedded fully qualified URL.

Used to wrap ActivityPub ids with the fed.brid.gy domain so that Mastodon
accepts them. Background:

https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747
"""
import logging

import webapp2

import appengine_config
import common


class RedirectHandler(webapp2.RequestHandler):
    """301 redirects to the embedded fully qualified URL.

    e.g. redirects /r/https://foo.com/bar?baz to https://foo.com/bar?baz
    """

    def get(self):
        assert self.request.path_qs.startswith('/r/')
        to = self.request.path_qs[3:]
        if not to.startswith('http://') and not to.startswith('https://'):
            common.error(self, 'Expected fully qualified URL; got %s' % to)
        logging.info('redirecting to %s', to)
        self.redirect(to)


app = webapp2.WSGIApplication([
    (r'/r/.+', RedirectHandler),
], debug=appengine_config.DEBUG)
