"""Handles requests for WebFinger endpoints.

https://webfinger.net/
https://tools.ietf.org/html/rfc7033
"""
import datetime
import logging
import re
import urllib.parse

from flask import g, render_template, request
from granary import as2
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads

from activitypub import actor_id, address
import common
from flask_app import app, cache
from models import User
from web import Web

NON_TLDS = frozenset(('html', 'json', 'php', 'xml'))

logger = logging.getLogger(__name__)


class Actor(flask_util.XrdOrJrd):
    """Serves a user's WebFinger profile."""
    @flask_util.cached(cache, common.CACHE_TIME, headers=['Accept'])
    def dispatch_request(self, *args, **kwargs):
        return super().dispatch_request(*args, **kwargs)

    def template_prefix(self):
        return 'webfinger_user'

    def template_vars(self, domain=None, allow_indirect=False):
        """
        Args:
          domain: str, user domain
          allow_indirect: bool, whether this may be an indirect user, ie without
            an existing :class:`User`
        """
        logger.debug(f'Headers: {list(request.headers.items())}')

        if domain.split('.')[-1] in NON_TLDS:
            error(f"{domain} doesn't look like a domain", status=404)

        if allow_indirect:
            g.user = Web.get_or_create(domain)
        else:
            g.user = Web.get_by_id(domain)

        if not g.user:
            error(f'No user or web site found for {domain}', status=404)

        actor = g.user.to_as1() or {}
        homepage = g.user.homepage
        handle = address(g.user)

        logger.info(f'Generating WebFinger data for {domain}')
        logger.info(f'AS1 actor: {actor}')
        urls = util.dedupe_urls(util.get_list(actor, 'urls') +
                                util.get_list(actor, 'url') +
                                [homepage])
        logger.info(f'URLs: {urls}')
        canonical_url = urls[0]

        # generate webfinger content
        data = util.trim_nulls({
            'subject': 'acct:' + handle.lstrip('@'),
            'aliases': urls,
            'links':
            [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': url,
            } for url in urls if util.is_web(url)] +

            [{
                'rel': 'http://webfinger.net/rel/avatar',
                'href': url,
            } for url in util.get_urls(actor, 'image')] +

            [{
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': canonical_url,
            },

            # ActivityPub
            {
                'rel': 'self',
                'type': as2.CONTENT_TYPE,
                # WARNING: in python 2 sometimes request.host_url lost port,
                # http://localhost:8080 would become just http://localhost. no
                # clue how or why. pay attention here if that happens again.
                'href': actor_id(g.user),
            }, {
                # AP reads this and sharedInbox from the AS2 actor, not
                # webfinger, so strictly speaking, it's probably not needed here.
                'rel': 'inbox',
                'type': as2.CONTENT_TYPE,
                'href': actor_id(g.user, 'inbox'),
            }, {
                # https://www.w3.org/TR/activitypub/#sharedInbox
                'rel': 'sharedInbox',
                'type': as2.CONTENT_TYPE,
                'href': common.host_url('/ap/sharedInbox'),
            },

            # remote follow
            # https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020/11?u=snarfed
            # https://github.com/snarfed/bridgy-fed/issues/60#issuecomment-1325589750
            {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                'template': common.host_url(f'user/{domain}?url={{uri}}'),
            }]
        })

        logger.info(f'Returning WebFinger data: {json_dumps(data, indent=2)}')
        return data


class Webfinger(Actor):
    """Handles Webfinger requests.

    https://webfinger.net/

    Supports both JRD and XRD; defaults to JRD.
    https://tools.ietf.org/html/rfc7033#section-4
    """
    def template_vars(self):
        resource = flask_util.get_required_param('resource').strip()
        resource = resource.removeprefix(common.host_url())

        # handle Bridgy Fed actor URLs, eg https://fed.brid.gy/snarfed.org
        host = util.domain_from_link(common.host_url())
        if resource in ('', '/', f'acct:{host}', f'acct:@{host}'):
            error('Expected other domain, not fed.brid.gy')

        allow_indirect = False
        try:
            user, domain = util.parse_acct_uri(resource)
            if domain in common.DOMAINS:
                domain = user
                allow_indirect=True
        except ValueError:
            domain = urllib.parse.urlparse(resource).netloc or resource

        return super().template_vars(domain=domain, allow_indirect=allow_indirect)


class HostMeta(flask_util.XrdOrJrd):
    """Renders and serves the /.well-known/host-meta file.

    Supports both JRD and XRD; defaults to XRD.
    https://tools.ietf.org/html/rfc6415#section-3
    """
    DEFAULT_TYPE = flask_util.XrdOrJrd.XRD

    def template_prefix(self):
        return 'host-meta'

    def template_vars(self):
        return {'host_uri': common.host_url()}


@app.get('/.well-known/host-meta.xrds')
def host_meta_xrds():
    """Renders and serves the /.well-known/host-meta.xrds XRDS-Simple file."""
    return (render_template('host-meta.xrds', host_uri=common.host_url()),
            {'Content-Type': 'application/xrds+xml'})


app.add_url_rule(f'/acct:<regex("{common.DOMAIN_RE}"):domain>',
                 view_func=Actor.as_view('actor_acct'))
app.add_url_rule('/.well-known/webfinger', view_func=Webfinger.as_view('webfinger'))
app.add_url_rule('/.well-known/host-meta', view_func=HostMeta.as_view('hostmeta'))
app.add_url_rule('/.well-known/host-meta.json', view_func=HostMeta.as_view('hostmeta-json'))
