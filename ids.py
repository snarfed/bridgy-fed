"""Translates user ids, handles, and object ids between protocols.

https://fed.brid.gy/docs#translate
"""
import logging
import re
from urllib.parse import urljoin, urlparse

from flask import request
from google.cloud.ndb.query import FilterNode, Query
from granary.bluesky import BSKY_APP_URL_RE, web_url_to_at_uri
from oauth_dropins.webutil import util

from common import (
    LOCAL_DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    subdomain_wrap,
    SUPERDOMAIN,
)
import models

logger = logging.getLogger(__name__)

# Protocols to check User.copies and Object.copies before translating
COPIES_PROTOCOLS = ('atproto',)

# Web user domains whose AP actor ids are on fed.brid.gy, not web.brid.gy, for
# historical compatibility. Loaded on first call to web_ap_subdomain().
#
# Maps string domain to string subdomain (bsky, fed, or web).
_NON_WEB_SUBDOMAIN_SITES = None


def web_ap_base_domain(user_domain):
    """Returns the full Bridgy Fed domain to use for a given Web user.

    Specifically, returns ``http://localhost/` if we're running locally,
    ``https://fed.brid.gy/`` if the given Web user has ``ap_subdomain='fed'``,
    otherwise ``https://web.brid.gy/``.

    Args:
      user_domain (str)

    Returns:
      str:
    """
    if request.host in LOCAL_DOMAINS:
        return request.host_url

    global _NON_WEB_SUBDOMAIN_SITES
    if _NON_WEB_SUBDOMAIN_SITES is None:
        _NON_WEB_SUBDOMAIN_SITES = {
            user.key.id(): user.ap_subdomain
            for user in Query('MagicKey',
                              filters=FilterNode('ap_subdomain', '!=', 'web'),
                              projection=['ap_subdomain'],
                              ).fetch()
        }
        logger.info(f'Loaded {len(_NON_WEB_SUBDOMAIN_SITES)} non-web.brid.gy Web users')

    subdomain = _NON_WEB_SUBDOMAIN_SITES.get(user_domain, 'web')
    return f'https://{subdomain}{SUPERDOMAIN}/'


def translate_user_id(*, id, from_, to):
    """Translate a user id from one protocol to another.

    TODO: unify with :func:`translate_object_id`.

    Args:
      id (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to``
    """
    assert id and from_ and to, (id, from_, to)
    assert from_.owns_id(id) is not False or from_.LABEL == 'ui', \
        (id, from_.LABEL, to.LABEL)

    parsed = urlparse(id)
    if from_.LABEL == 'web' and parsed.path.strip('/') == '':
        # home page; replace with domain
        id = parsed.netloc

    # bsky.app profile URL to DID
    if to.LABEL == 'atproto':
        if match := BSKY_APP_URL_RE.match(id):
            repo = match.group('id')
            if repo.startswith('did:'):
                return repo

            from atproto import ATProto
            try:
                return ATProto.handle_to_id(repo)
            except (AssertionError, ValueError) as e:
                logger.warning(e)
                return None

    if from_ == to:
        return id

    # follow use_instead
    user = from_.get_by_id(id)
    if user:
        id = user.key.id()

    if from_.LABEL in COPIES_PROTOCOLS or to.LABEL in COPIES_PROTOCOLS:
        if user:
            if copy := user.get_copy(to):
                return copy
        if orig := models.get_original(id):
            if isinstance(orig, to):
                return orig.key.id()

    match from_.LABEL, to.LABEL:
        case _, 'atproto' | 'nostr':
            logger.warning(f"Can't translate user id {id} to {to.LABEL} , haven't copied it there yet!")
            return None

        case 'web', 'activitypub':
            return urljoin(web_ap_base_domain(id), id)

        case 'activitypub', 'web':
            return id

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'eefake':
            return f'{to.LABEL}:u:{id}'
        case 'fake' | 'other', _:
            return id

    assert False, (id, from_.LABEL, to.LABEL)


def translate_handle(*, handle, from_, to, enhanced):
    """Translates a user handle from one protocol to another.

    Args:
      handle (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)
      enhanced (bool): whether to convert to an "enhanced" handle based on the
        user's domain

    Returns:
      str: the corresponding handle in ``to``
    """
    assert handle and from_ and to, (handle, from_, to)
    assert from_.owns_handle(handle) is not False or from_.LABEL == 'ui'

    if from_ == to:
        return handle

    match from_.LABEL, to.LABEL:
        case _, 'activitypub':
            domain = f'{from_.ABBREV}{SUPERDOMAIN}'
            if enhanced or handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
                domain = handle
            return f'@{handle}@{domain}'

        case _, 'atproto' | 'nostr':
            handle = handle.lstrip('@').replace('@', '.')
            return (handle if enhanced
                    else f'{handle}.{from_.ABBREV}{SUPERDOMAIN}')

        case 'activitypub', 'web':
            user, instance = handle.lstrip('@').split('@')
            # TODO: get this from the actor object's url field?
            return (f'https://{user}' if user == instance
                    else f'https://{instance}/@{user}')

        case _, 'web':
            return handle

        # only for unit tests
        case _, 'fake' | 'other' | 'eefake':
            return f'{to.LABEL}:handle:{handle}'

    assert False, (handle, from_.LABEL, to.LABEL)


def translate_object_id(*, id, from_, to):
    """Translates a user handle from one protocol to another.

    TODO: unify with :func:`translate_user_id`.

    Args:
      id (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to``
    """
    assert id and from_ and to, (id, from_, to)
    assert from_.owns_id(id) is not False or from_.LABEL == 'ui'

    # bsky.app profile URL to DID
    if to.LABEL == 'atproto':
        if match := BSKY_APP_URL_RE.match(id):
            repo = match.group('id')
            handle = None
            if not repo.startswith('did:'):
                handle = repo
                from atproto import ATProto
                try:
                    repo = ATProto.handle_to_id(repo)
                except (AssertionError, ValueError) as e:
                    logger.warning(e)
                    return None

            return web_url_to_at_uri(id, handle=handle, did=repo)

    if from_ == to:
        return id

    if from_.LABEL in COPIES_PROTOCOLS or to.LABEL in COPIES_PROTOCOLS:
        if obj := from_.load(id, remote=False):
            if copy := obj.get_copy(to):
                return copy
        if orig := models.get_original(id):
            return orig.key.id()

    match from_.LABEL, to.LABEL:
        case _, 'atproto' | 'nostr':
            logger.warning(f"Can't translate object id {id} to {to.LABEL} , haven't copied it there yet!")
            return id

        case 'web', 'activitypub':
            return urljoin(web_ap_base_domain(util.domain_from_link(id)), f'/r/{id}')

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/convert/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'eefake':
            return f'{to.LABEL}:o:{from_.ABBREV}:{id}'

    assert False, (id, from_.LABEL, to.LABEL)
