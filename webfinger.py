"""Handles requests for WebFinger endpoints.

* https://webfinger.net/
* https://tools.ietf.org/html/rfc7033
"""
import logging
from urllib.parse import urljoin, urlparse

from flask import g, render_template, request
from granary import as2
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error, flash, Found
from oauth_dropins.webutil.util import json_dumps, json_loads

import activitypub
import common
from common import LOCAL_DOMAINS, PRIMARY_DOMAIN, PROTOCOL_DOMAINS, SUPERDOMAIN
from flask_app import app, cache
from protocol import Protocol
from web import Web

SUBSCRIBE_LINK_REL = 'http://ostatus.org/schema/1.0/subscribe'

logger = logging.getLogger(__name__)


class Webfinger(flask_util.XrdOrJrd):
    """Serves a user's WebFinger profile.

    Supports both JRD and XRD; defaults to JRD.
    https://tools.ietf.org/html/rfc7033#section-4
    """
    @flask_util.cached(cache, common.CACHE_TIME, headers=['Accept'])
    def dispatch_request(self, *args, **kwargs):
        return super().dispatch_request(*args, **kwargs)

    def template_prefix(self):
        return 'webfinger_user'

    def template_vars(self):
        logger.debug(f'Headers: {list(request.headers.items())}')

        resource = flask_util.get_required_param('resource').strip()
        resource = resource.removeprefix(common.host_url())

        # handle Bridgy Fed actor URLs, eg https://fed.brid.gy/snarfed.org
        host = util.domain_from_link(common.host_url())
        if resource in ('', '/', f'acct:{host}', f'acct:@{host}'):
            error('Expected other domain, not *.brid.gy')

        allow_indirect = False
        cls = None
        try:
            user, id = util.parse_acct_uri(resource)
            cls = Protocol.for_bridgy_subdomain(id, fed='web')
            if cls:
                id = user
                allow_indirect = True
        except ValueError:
            id = urlparse(resource).netloc or resource

        if id == PRIMARY_DOMAIN or id in PROTOCOL_DOMAINS:
            cls = Web
        elif not cls:
            cls = Protocol.for_request(fed='web')

        if not cls:
            error('Unknown protocol')

        # is this a handle?
        if cls.owns_id(id) is False:
            logger.info(f'{id} is not a {cls.LABEL} id')
            handle = id
            id = None
            if cls.owns_handle(handle) is not False:
                logger.info('  ...might be a handle, trying to resolve')
                id = cls.handle_to_id(handle)

        if not id:
            error(f'{id} is not a valid {cls.LABEL} id')

        logger.info(f'Protocol {cls.LABEL}, user id {id}')

        # only allow indirect users if this id is "on" a brid.gy subdomain,
        # eg user.com@bsky.brid.gy but not user.com@user.com
        if allow_indirect:
            user = cls.get_or_create(id)
        else:
            user = cls.get_by_id(id)
            if user and not user.direct:
                error(f"{user.key} hasn't signed up yet", status=404)

        if not user or not user.is_enabled_to(activitypub.ActivityPub, user=user):
            error(f'No {cls.LABEL} user found for {id}', status=404)

        ap_handle = user.handle_as('activitypub')
        if not ap_handle:
            error(f'{cls.LABEL} user {id} has no handle', status=404)

        # backward compatibility for initial Web users whose AP actor ids are on
        # fed.brid.gy, not web.brid.gy
        subdomain = request.host.split('.')[0]
        if (user.LABEL == 'web'
                and subdomain not in (LOCAL_DOMAINS + (user.ap_subdomain,))):
            url = urljoin(f'https://{user.ap_subdomain}{common.SUPERDOMAIN}/',
                          request.full_path)
            raise Found(location=url)

        actor = user.obj.as1 if user.obj and user.obj.as1 else {}
        logger.info(f'Generating WebFinger data for {user.key}')
        logger.info(f'AS1 actor: {actor}')
        urls = util.dedupe_urls(util.get_list(actor, 'urls') +
                                util.get_list(actor, 'url') +
                                [user.web_url()])
        logger.info(f'URLs: {urls}')
        canonical_url = urls[0]

        # generate webfinger content
        actor_id = user.id_as(activitypub.ActivityPub)
        data = util.trim_nulls({
            'subject': 'acct:' + ap_handle.lstrip('@'),
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
                'type': as2.CONTENT_TYPE_LD_PROFILE,
                # WARNING: in python 2 sometimes request.host_url lost port,
                # http://localhost:8080 would become just http://localhost. no
                # clue how or why. pay attention here if that happens again.
                'href': actor_id,
            }, {
                # AP reads this and sharedInbox from the AS2 actor, not
                # webfinger, so strictly speaking, it's probably not needed here.
                'rel': 'inbox',
                'type': as2.CONTENT_TYPE_LD_PROFILE,
                'href': actor_id + '/inbox',
            }, {
                # https://www.w3.org/TR/activitypub/#sharedInbox
                'rel': 'sharedInbox',
                'type': as2.CONTENT_TYPE_LD_PROFILE,
                'href': common.subdomain_wrap(cls, '/ap/sharedInbox'),
            },

            # remote follow
            # https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020/11?u=snarfed
            # https://github.com/snarfed/bridgy-fed/issues/60#issuecomment-1325589750
            {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                # always use fed.brid.gy for UI pages, not protocol subdomain
                # TODO: switch to:
                # 'template': common.host_url(user.user_page_path('?url={uri}')),
                # the problem is that user_page_path() uses handle_or_id, which uses
                # custom username instead of domain, which may not be unique
                'template': f'https://{common.PRIMARY_DOMAIN}' +
                            user.user_page_path('?url={uri}'),
            }]
        })

        logger.info(f'Returning WebFinger data: {json_dumps(data, indent=2)}')
        return data


class HostMeta(flask_util.XrdOrJrd):
    """Renders and serves the ``/.well-known/host-meta`` file.

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
    """Renders and serves the ``/.well-known/host-meta.xrds`` XRDS-Simple file."""
    return (render_template('host-meta.xrds', host_uri=common.host_url()),
            {'Content-Type': 'application/xrds+xml'})


def fetch(addr):
    """Fetches and returns an address's WebFinger data.

    On failure, flashes a message and returns None.

    TODO: switch to raising exceptions instead of flashing messages and
    returning None

    Args:
      addr (str): a Webfinger-compatible address, eg ``@x@y``, ``acct:x@y``, or
        ``https://x/y``

    Returns:
      dict: fetched WebFinger data, or None on error
    """
    addr = addr.strip().strip('@')
    split = addr.split('@')
    if len(split) == 2:
        addr_domain = split[1]
        resource = f'acct:{addr}'
    elif util.is_web(addr):
        addr_domain = util.domain_from_link(addr, minimize=False)
        resource = addr
    else:
        flash('Enter a fediverse address in @user@domain.social format')
        return None

    try:
        resp = util.requests_get(
            f'https://{addr_domain}/.well-known/webfinger?resource={resource}')
    except BaseException as e:
        if util.is_connection_failure(e):
            flash(f"Couldn't connect to {addr_domain}")
            return None
        raise

    if not resp.ok:
        flash(f'WebFinger on {addr_domain} returned HTTP {resp.status_code}')
        return None

    try:
        data = resp.json()
    except ValueError as e:
        logger.warning(f'Got {e}', exc_info=True)
        flash(f'WebFinger on {addr_domain} returned non-JSON')
        return None

    logger.info(f'Got: {json_dumps(data, indent=2)}')
    return data


def fetch_actor_url(addr):
    """Fetches and returns a WebFinger address's ActivityPub actor URL.

    On failure, flashes a message and returns None.

    Args:
      addr (str): a Webfinger-compatible address, eg ``@x@y``, ``acct:x@y``, or
        ``https://x/y``

    Returns:
      str: ActivityPub actor URL, or None on error or not fouund
    """
    data = fetch(addr)
    if not data:
        return None

    for link in data.get('links', []):
        type = link.get('type', '').split(';')[0]
        if link.get('rel') == 'self' and type in as2.CONTENT_TYPES:
            return link.get('href')


app.add_url_rule('/.well-known/webfinger', view_func=Webfinger.as_view('webfinger'))
app.add_url_rule('/.well-known/host-meta', view_func=HostMeta.as_view('hostmeta'))
app.add_url_rule('/.well-known/host-meta.json', view_func=HostMeta.as_view('hostmeta-json'))
