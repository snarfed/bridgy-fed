"""Handles requests for WebFinger endpoints.

https://webfinger.net/
https://tools.ietf.org/html/rfc7033

Largely based on webfinger-unofficial/user.py.
"""
import datetime
import logging
import urllib.parse
import urllib.parse

from granary.microformats2 import get_text
import mf2util
from oauth_dropins.webutil import handlers, util
from oauth_dropins.webutil.util import json_dumps
import webapp2

import common
import models

CACHE_TIME = datetime.timedelta(seconds=15)
NON_TLDS = frozenset(('html', 'json', 'php', 'xml'))


class UserHandler(common.Handler, handlers.XrdOrJrdHandler):
    """Fetches a site's home page, converts its mf2 to WebFinger, and serves."""
    JRD_TEMPLATE = False

    @handlers.cache_response(CACHE_TIME, headers=['Accept'])
    def get(self, *args, **kwargs):
        logging.debug(f'Headers: {list(self.request.headers.items())}')
        return super(UserHandler, self).get(*args, **kwargs)

    def template_prefix(self):
        return 'templates/webfinger_user'

    def template_vars(self, domain, url=None):
        assert domain

        if domain.split('.')[-1] in NON_TLDS:
            self.error("%s doesn't look like a domain" % domain, status=404)

        # find representative h-card. try url, then url's home page, then domain
        urls = ['http://%s/' % domain]
        if url:
            urls = [url, urllib.parse.urljoin(url, '/')] + urls

        for candidate in urls:
            resp = common.requests_get(candidate)
            parsed = util.parse_html(resp)
            mf2 = util.parse_mf2(parsed, url=resp.url)
            # logging.debug('Parsed mf2 for %s: %s', resp.url, json_dumps(mf2, indent=2))
            hcard = mf2util.representative_hcard(mf2, resp.url)
            if hcard:
                logging.info('Representative h-card: %s', json_dumps(hcard, indent=2))
                break
        else:
            self.error("""\
Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on %s""" % resp.url)

        logging.info('Generating WebFinger data for %s', domain)
        key = models.MagicKey.get_or_create(domain)
        props = hcard.get('properties', {})
        urls = util.dedupe_urls(props.get('url', []) + [resp.url])
        canonical_url = urls[0]

        acct = '%s@%s' % (domain, domain)
        for url in urls:
            if url.startswith('acct:'):
                urluser, urldomain = util.parse_acct_uri(url)
                if urldomain == domain:
                    acct = '%s@%s' % (urluser, domain)
                    logging.info('Found custom username: acct:%s', acct)
                    break

        # discover atom feed, if any
        atom = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        if atom and atom['href']:
            atom = urllib.parse.urljoin(resp.url, atom['href'])
        else:
            atom = 'https://granary.io/url?' + urllib.parse.urlencode({
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
            }] for url in urls if url.startswith("http")), []) + [{
                'rel': 'http://webfinger.net/rel/avatar',
                'href': get_text(url),
            } for url in props.get('photo', [])] + [{
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': canonical_url,
            },

            # ActivityPub
            {
                'rel': 'self',
                'type': common.CONTENT_TYPE_AS2,
                # WARNING: in python 2 sometimes request.host_url lost port,
                # http://localhost:8080 would become just http://localhost. no
                # clue how or why. pay attention here if that happens again.
                'href': '%s/%s' % (self.request.host_url, domain),
            }, {
                'rel': 'inbox',
                'type': common.CONTENT_TYPE_AS2,
                'href': '%s/%s/inbox' % (self.request.host_url, domain),
            },

            # OStatus
            {
                'rel': 'http://schemas.google.com/g/2010#updates-from',
                'type': common.CONTENT_TYPE_ATOM,
                'href': atom,
            }, {
                'rel': 'hub',
                'href': hub,
            }, {
                'rel': 'magic-public-key',
                'href': key.href(),
            }, {
                'rel': 'salmon',
                'href': '%s/%s/salmon' % (self.request.host_url, domain),
            }]
        })
        logging.info('Returning WebFinger data: %s', json_dumps(data, indent=2))
        return data


class WebfingerHandler(UserHandler):
    """Handles Webfinger requests.

    https://webfinger.net/

    Supports both JRD and XRD; defaults to JRD.
    https://tools.ietf.org/html/rfc7033#section-4
    """
    def template_vars(self):
        resource = util.get_required_param(self, 'resource')
        try:
            user, domain = util.parse_acct_uri(resource)
            if domain in common.DOMAINS:
                domain = user
        except ValueError:
            domain = urllib.parse.urlparse(resource).netloc or resource

        url = None
        if resource.startswith('http://') or resource.startswith('https://'):
            url = resource

        return super(WebfingerHandler, self).template_vars(domain, url=url)


ROUTES = [
    (r'/acct:%s/?' % common.DOMAIN_RE, UserHandler),
    ('/.well-known/webfinger', WebfingerHandler),
] + handlers.HOST_META_ROUTES
