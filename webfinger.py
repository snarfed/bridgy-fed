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
import urllib
import urlparse

import appengine_config

from bs4 import BeautifulSoup
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

    def template_vars(self, domain, url=None):
        if not url:
            url = 'http://%s/' % domain

        # TODO: unify with activitypub
        resp = common.requests_get(url)
        parsed = BeautifulSoup(resp.content, from_encoding=resp.encoding)
        mf2 = mf2py.parse(parsed, url=resp.url)
        # logging.debug('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        hcard = mf2util.representative_hcard(mf2, resp.url)
        logging.info('Representative h-card: %s', json.dumps(hcard, indent=2))
        if not hcard:
            common.error(self, """\
Couldn't find a <a href="http://microformats.org/wiki/representative-hcard-parsing">\
representative h-card</a> on %s""" % resp.url)

        acct = '%s@%s' % (common.USERNAME, domain)
        key = models.MagicKey.get_or_create(domain)
        props = hcard.get('properties', {})
        urls = util.dedupe_urls(props.get('url', []) + [resp.url])
        canonical_url = urls[0]

        # discover atom feed, if any
        atom = parsed.find('link', rel='alternate', type=common.ATOM_CONTENT_TYPE)
        if atom and atom['href']:
            atom = urlparse.urljoin(resp.url, atom['href'])
        else:
            atom = 'https://granary-demo.appspot.com/url?' + urllib.urlencode({
                'input': 'html',
                'output': 'atom',
                'url': resp.url,
                'hub': resp.url,
            })

        # discover PuSH, if any
        for link in resp.headers.get('Link', '').split(','):
            match = common.LINK_HEADER_RE.match(link)
            if match and match.group(2) == 'hub':
                hub = match.group(1)
            else:
                hub = 'https://bridgy-fed.superfeedr.com/'


        # generate webfinger content
        data = util.trim_nulls({
            'subject': 'acct:' + acct,
            'aliases': urls,
            'magic_keys': [{'value': key.href()}],
            'links': sum(([{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': url,
            }] for url in urls), []) + [{
                'rel': 'http://webfinger.net/rel/avatar',
                'href': url,
            } for url in props.get('photo', [])] + [{
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': canonical_url,
            },

            # ActivityPub
            {
                'rel': 'self',
                'type': 'application/activity+json',
                # use HOST_URL instead of e.g. request.host_url because it
                # sometimes lost port, e.g. http://localhost:8080 would become
                # just http://localhost. no clue how or why.
                'href': '%s/%s' % (appengine_config.HOST_URL, domain),
            }, {
                'rel': 'inbox',
                'type': 'application/activity+json',
                'href': '%s/%s/inbox' % (appengine_config.HOST_URL, domain),
            },

            # OStatus
            {
                'rel': 'http://schemas.google.com/g/2010#updates-from',
                'type': common.ATOM_CONTENT_TYPE,
                'href': atom,
            }, {
                'rel': 'hub',
                'href': hub,
            }, {
                'rel': 'magic-public-key',
                'href': key.href(),
            }, {
                'rel': 'salmon',
                'href': '%s/%s/salmon' % (appengine_config.HOST_URL, domain),
            }]
        })
        logging.info('Returning WebFinger data: %s', json.dumps(data, indent=2))
        return data


class WebfingerHandler(UserHandler):

    def is_jrd(self):
        return True

    def template_vars(self):
        resource = util.get_required_param(self, 'resource')
        try:
            _, domain = util.parse_acct_uri(resource)
        except ValueError:
            domain = urlparse.urlparse(resource).netloc or resource

        url = None
        if resource.startswith('http://') or resource.startswith('https://'):
            url = resource

        return super(WebfingerHandler, self).template_vars(domain, url=url)


app = webapp2.WSGIApplication([
    (r'/%s/?' % common.DOMAIN_RE, UserHandler),
    ('/.well-known/webfinger', WebfingerHandler),
] + handlers.HOST_META_ROUTES, debug=appengine_config.DEBUG)
