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
import models


class UserHandler(handlers.XrdOrJrdHandler):
    """Serves /@[DOMAIN], fetches its mf2, converts to WebFinger, and serves."""

    def template_prefix(self):
        return 'templates/webfinger_user'

    def template_vars(self, domain):
        # TODO: unify with activitypub
        url = 'https://%s/' % domain
        resp = common.requests_get(url)
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, resp.url)
        logging.info('Representative h-card: %s', json.dumps(hcard, indent=2))

        key = models.MagicKey.get_or_create('@%s' % domain)
        props = hcard['properties']
        return {
            'urls': props['url'],
            'avatars': props['photo'],
            'magic_public_key': key.href(),
        }


app = webapp2.WSGIApplication([
    (r'/(?:acct)?@%s/?' % common.DOMAIN_RE, UserHandler),
] + handlers.HOST_META_ROUTES, debug=appengine_config.DEBUG)
