"""Handles requests for WebFinger endpoints.

https://webfinger.net/

Largely based on webfinger-unofficial/user.py.
"""
import json
import logging

import appengine_config

from granary import microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import handlers, util
import webapp2

import common


class UserHandler(webapp2.RequestHandler):
    """TODO"""

    def get(self, username, domain):
        pass


app = webapp2.WSGIApplication([
    (r'/(?:acct)?([^@/])@%s/?' % common.DOMAIN_RE, UserHandler),
] + handlers.HOST_META_ROUTES, debug=appengine_config.DEBUG)
