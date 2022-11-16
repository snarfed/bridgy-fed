"""Handles requests for WebFinger endpoints.

https://webfinger.net/
https://tools.ietf.org/html/rfc7033
"""
import datetime
import logging
import re
import urllib.parse

from flask import render_template, request
from granary.microformats2 import get_text
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps

from app import app, cache
import common
import models

CACHE_TIME = datetime.timedelta(seconds=15)
NON_TLDS = frozenset(('html', 'json', 'php', 'xml'))

logger = logging.getLogger(__name__)


# TODO
# @cache.cached(
#     CACHE_TIME.total_seconds(),
#     make_cache_key=lambda domain: f'{request.path} {request.headers.get("Accept")}')

class User(flask_util.XrdOrJrd):
    """Fetches a site's home page, converts its mf2 to WebFinger, and serves."""
    def template_prefix(self):
        return 'webfinger_user'

    def template_vars(self, domain=None, url=None):
        logger.debug(f'Headers: {list(request.headers.items())}')

        if domain.split('.')[-1] in NON_TLDS:
            error(f"{domain} doesn't look like a domain", status=404)

        # find representative h-card. try url, then url's home page, then domain
        urls = [f'http://{domain}/']
        if url:
            urls = [url, urllib.parse.urljoin(url, '/')] + urls

        for candidate in urls:
            resp = common.requests_get(candidate)
            parsed = util.parse_html(resp)
            mf2 = util.parse_mf2(parsed, url=resp.url)
            # logger.debug(f'Parsed mf2 for {resp.url}: {json_dumps(mf2, indent=2)}')
            hcard = mf2util.representative_hcard(mf2, resp.url)
            if hcard:
                logger.info(f'Representative h-card: {json_dumps(hcard, indent=2)}')
                break
        else:
            error(f"didn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on {resp.url}")

        logger.info(f'Generating WebFinger data for {domain}')
        entity = models.Domain.get_or_create(domain)
        props = hcard.get('properties', {})
        urls = util.dedupe_urls(props.get('url', []) + [resp.url])
        canonical_url = urls[0]

        acct = f'{domain}@{domain}'
        for url in urls:
            if url.startswith('acct:'):
                urluser, urldomain = util.parse_acct_uri(url)
                if urldomain == domain:
                    acct = f'{urluser}@{domain}'
                    logger.info(f'Found custom username: acct:{acct}')
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
            'magic_keys': [{'value': entity.href()}],
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
                'href': f'{request.host_url}{domain}',
            }, {
                'rel': 'inbox',
                'type': common.CONTENT_TYPE_AS2,
                'href': f'{request.host_url}{domain}/inbox',
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
                'href': entity.href(),
            }, {
                'rel': 'salmon',
                'href': f'{request.host_url}{domain}/salmon',
            }]
        })
        logger.info(f'Returning WebFinger data: {json_dumps(data, indent=2)}')
        return data


class Webfinger(User):
    """Handles Webfinger requests.

    https://webfinger.net/

    Supports both JRD and XRD; defaults to JRD.
    https://tools.ietf.org/html/rfc7033#section-4
    """
    def template_vars(self):
        resource = flask_util.get_required_param('resource')
        try:
            user, domain = util.parse_acct_uri(resource)
            if domain in common.DOMAINS:
                domain = user
        except ValueError:
            domain = urllib.parse.urlparse(resource).netloc or resource

        url = None
        if resource.startswith('http://') or resource.startswith('https://'):
            url = resource

        return super().template_vars(domain=domain, url=url)


class HostMeta(flask_util.XrdOrJrd):
    """Renders and serves the /.well-known/host-meta file.

    Supports both JRD and XRD; defaults to XRD.
    https://tools.ietf.org/html/rfc6415#section-3
    """
    DEFAULT_TYPE = flask_util.XrdOrJrd.XRD

    def template_prefix(self):
        return 'host-meta'

    def template_vars(self):
        return {'host_uri': request.host_url}


@app.get('/.well-known/host-meta.xrds')
def host_meta_xrds():
    """Renders and serves the /.well-known/host-meta.xrds XRDS-Simple file."""
    return (render_template('host-meta.xrds', host_uri=request.host_url),
            {'Content-Type': 'application/xrds+xml'})


app.add_url_rule(f'/acct:<regex("{common.DOMAIN_RE}"):domain>',
                 view_func=User.as_view('actor_acct'))
app.add_url_rule('/.well-known/webfinger', view_func=Webfinger.as_view('webfinger'))
app.add_url_rule('/.well-known/host-meta', view_func=HostMeta.as_view('hostmeta'))
app.add_url_rule('/.well-known/host-meta.json', view_func=HostMeta.as_view('hostmeta-json'))
