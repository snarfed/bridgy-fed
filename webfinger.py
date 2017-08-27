"""Handles requests for WebFinger endpoints.

https://webfinger.net/
https://tools.ietf.org/html/rfc7033

Largely based on webfinger-unofficial/user.py.

TODO: test:
* /.well-known/webfinger
* acct: URI handling
* user URL that redirects
"""
import json
import logging
import urlparse

import appengine_config

from granary import microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import handlers, util
import webapp2

import common
import models


class UserHandler(handlers.XrdOrJrdHandler):
    """Fetches a site's home page, converts its mf2 to WebFinger, and serves."""
    JRD_TEMPLATE = False

    def template_prefix(self):
        return 'templates/webfinger_user'

    def template_vars(self, domain):
        url = 'http://%s/' % domain

        # TODO: unify with activitypub
        resp = common.requests_get(url)
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, resp.url)
        logging.info('Representative h-card: %s', json.dumps(hcard, indent=2))
        if not hcard:
            common.error(self, """\
Couldn't find a <a href="http://microformats.org/wiki/representative-hcard-parsing">\
representative h-card</a> on %s""" % resp.url)

        uri = '@%s' % domain
        key = models.MagicKey.get_or_create(uri)
        props = hcard.get('properties', {})
        urls = util.dedupe_urls(props.get('url', []) + [resp.url])

        return util.trim_nulls({
            'subject': 'acct:' + uri,
            'aliases': urls,
            'magic_keys': [{'value': key.href()}],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': url,
            } for url in urls] + [{
                'rel': 'http://webfinger.net/rel/avatar',
                'href': url,
            } for url in props.get('photo', [])] + [{
                'rel': 'magic-public-key',
                'href': key.href(),
            }, {
                'rel': 'salmon',
                'href': '%s/@%s/salmon' % (self.request.host_url, domain),
            }]
        })


class WebfingerHandler(UserHandler):

    def is_jrd(self):
        return True

    def template_vars(self):
        resource = util.get_required_param(self, 'resource')
        try:
            username, domain = util.parse_acct_uri(resource)
            url = 'http://%s/' % domain
        except ValueError:
            url = resource
            domain = urlparse.urlparse(url).netloc
        if not domain:
            common.error(self, 'No domain found in resource %s' % url)

        return super(WebfingerHandler, self).template_vars(domain)


app = webapp2.WSGIApplication([
    (r'/(?:acct)?@%s/?' % common.DOMAIN_RE, UserHandler),
    ('/.well-known/webfinger', WebfingerHandler),
] + handlers.HOST_META_ROUTES, debug=appengine_config.DEBUG)
