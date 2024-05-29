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
# populated in models.reset_protocol_properties
COPIES_PROTOCOLS = None

# Web user domains whose AP actor ids are on fed.brid.gy, not web.brid.gy, for
# historical compatibility. Loaded on first call to web_ap_base_domain().
#
# Maps string domain to string subdomain (bsky, fed, or web).
_NON_WEB_SUBDOMAIN_SITES = None

# Webfinger allows all sorts of characters that ATProto handles don't,
# notably _ and ~. Map those to -.
# ( : (colon) is mostly just used in the fake protocols in unit tests.)
# https://www.rfc-editor.org/rfc/rfc7565.html#section-7
# https://atproto.com/specs/handle
# https://github.com/snarfed/bridgy-fed/issues/982
# https://github.com/swicg/activitypub-webfinger/issues/9
ATPROTO_DASH_CHARS = ('_', '~', ':')


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
    if (request.host in LOCAL_DOMAINS and
            not (user_domain == PRIMARY_DOMAIN or user_domain in PROTOCOL_DOMAINS)):
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


def normalize_user_id(*, id, proto):
    """Normalizes a user id to its canonical representation in a given protocol.

    Examples:

    * Web:
      * user.com => user.com
      * www.user.com => user.com
      * https://user.com/ => user.com
    * ATProto:
      * did:plc:123 => did:plc:123
      * https://bsky.app/profile/did:plc:123 => did:plc:123

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the normalized user id
    """
    normalized = translate_user_id(id=id, from_=proto, to=proto)

    if proto.LABEL == 'web':
        normalized = util.domain_from_link(normalized)

    return normalized


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

    Raises:
      ValueError: if the user's handle is invalid, eg begins or ends with an
        underscore or dash
    """
    assert handle and from_ and to, (handle, from_, to)
    if not from_.LABEL == 'ui':
        if from_.owns_handle(handle, allow_internal=True) is False:
            raise ValueError(f'input handle {handle} is not valid for {from_.LABEL}')

    if from_ == to:
        return handle

    output = None
    match from_.LABEL, to.LABEL:
        case _, 'activitypub':
            domain = f'{from_.ABBREV}{SUPERDOMAIN}'
            if enhanced or handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
                domain = handle
            output = f'@{handle}@{domain}'

        case _, 'atproto':
            output = handle.lstrip('@').replace('@', '.')
            for from_char in ATPROTO_DASH_CHARS:
                output = output.replace(from_char, '-')

            if enhanced or handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
                pass
            else:
                output = f'{output}.{from_.ABBREV}{SUPERDOMAIN}'

        case 'activitypub', 'web':
            user, instance = handle.lstrip('@').split('@')
            # TODO: get this from the actor object's url field?
            output = (f'https://{user}' if user == instance
                    else f'https://{instance}/@{user}')

        case _, 'web':
            output = handle

        # only for unit tests
        case _, 'fake' | 'other' | 'eefake':
            output = f'{to.LABEL}:handle:{handle}'

    assert output, (handle, from_.LABEL, to.LABEL)
    # don't check Web handles because they're sometimes URLs, eg
    # @user@instance => https://instance/@user
    if to.LABEL != 'web' and to.owns_handle(output, allow_internal=True) is False:
        raise ValueError(f'translated handle {output} is not valid for {to.LABEL}')

    return output


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
