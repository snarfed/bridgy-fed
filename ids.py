"""Translates user ids, handles, and object ids between protocols.

https://fed.brid.gy/docs#translate
"""
import inspect
import logging
import re
from threading import Lock
from urllib.parse import urljoin, urlparse

from arroba.util import parse_at_uri
from cachetools import cached, LRUCache
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
    unwrap,
)
import models

logger = logging.getLogger(__name__)

# Protocols to check User.copies and Object.copies before translating
# populated in models.reset_protocol_properties
COPIES_PROTOCOLS = None

# Webfinger allows all sorts of characters that ATProto handles and Nostr usernames
# don't, notably _ and ~. Map those to -.
# ( : (colon) is mostly just used in the fake protocols in unit tests.)
# https://www.rfc-editor.org/rfc/rfc7565.html#section-7
# https://atproto.com/specs/handle
# https://github.com/snarfed/bridgy-fed/issues/982
# https://github.com/swicg/activitypub-webfinger/issues/9
DASH_CHARS = ('_', '~', ':')

# can't use translate_user_id because Web.owns_id checks valid_domain, which
# doesn't allow our protocol subdomains
BOT_ACTOR_AP_IDS = tuple(f'https://{domain}/{domain}' for domain in PROTOCOL_DOMAINS)
BOT_ACTOR_AP_HANDLES = tuple(f'@{domain}@{domain}' for domain in PROTOCOL_DOMAINS)

# if the path for a URL on a subdomain starts with this, it's our own web page/post,
# not the subdomain protocol's.
INTERNAL_PATH_PREFIX = '/internal/'

# Domains that we set custom Bluesky subdomain handles for. They redirect their
# /.well-known/atproto-did path to fed.brid.gy for ATProto handle resolution.
# https://github.com/snarfed/bridgy-fed/issues/1305
# https://fed.brid.gy/docs#bluesky-handle-api
ATPROTO_HANDLE_DOMAINS = (
    'music-social.com',
)


def validate(id, from_, to):
    """Validates args.

    Asserts that all args are non-None. If ``from_`` or ``to`` are instances,
    returns their classes.
    """
    assert id and from_ and to, (id, from_, to)

    if not inspect.isclass(from_):
        from_ = from_.__class__
    if not inspect.isclass(to):
        to = to.__class__

    return id, from_, to


@cached(LRUCache(10000), lock=Lock())
def web_ap_base_domain(user_domain):
    """Returns the full Bridgy Fed domain to use for a given Web user.

    Specifically, returns ``http://localhost/` if we're running locally,
    ``https://[ap_subdomain].brid.gy/`` for the Web entity for this domain if it
    exists, otherwise ``https://web.brid.gy/``.

    Args:
      user_domain (str)

    Returns:
      str:
    """
    if (request.host in LOCAL_DOMAINS and
            not (user_domain == PRIMARY_DOMAIN or user_domain in PROTOCOL_DOMAINS)):
        return request.host_url

    from web import Web
    if user := Web.get_by_id(user_domain):
        return f'https://{user.ap_subdomain}{SUPERDOMAIN}/'

    return f'https://web{SUPERDOMAIN}/'


def translate_user_id(*, id, from_, to):
    """Translate a user id from one protocol to another.

    *NOTE*: unlike :func:`translate_object_id`, if ``to`` is a ``HAS_COPIES`` protocol
    and has no copy object for ``id``, this function returns None, not ``id``!

    TODO: unify with :func:`translate_object_id`.

    Args:
      id (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to``
    """
    id, from_, to = validate(id, from_, to)

    # check for and handle our own subdomain-wrapped ids, eg
    # https://bsky.brid.gy/ap/did:plc:456
    from protocol import Protocol
    if domain_proto := Protocol.for_bridgy_subdomain(id, fed='web'):
        path = urlparse(id).path.strip('/').split('/')
        if (path[0] == from_.ABBREV
                or (from_.ABBREV == 'ap' and domain_proto.ABBREV == 'web'
                    and len(path) == 1)):
            id = unwrap(id)
            from_ = domain_proto

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
    user = from_.get_by_id(id, allow_opt_out=True)
    if user:
        id = user.key.id()
        if to.LABEL in COPIES_PROTOCOLS:
            if copy := user.get_copy(to):
                return copy

    if from_.LABEL in COPIES_PROTOCOLS:
        if orig := models.get_original_user_key(id):
            if orig.kind() == to._get_kind():
                return orig.id()

    match from_.LABEL, to.LABEL:
        case _, 'atproto' | 'nostr':
            logger.debug(f"Can't translate user id {id} to {to.LABEL} , haven't copied it there yet!")
            return None

        case 'web', 'activitypub':
            return urljoin(web_ap_base_domain(id), id)

        case 'activitypub', 'web':
            return id

        case _, 'activitypub' | 'web':
            from activitypub import ActivityPub
            if user and not user.is_enabled(ActivityPub):
                return user.web_url()
            return subdomain_wrap(from_, f'/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'efake':
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

    Note that :func:`profile_id` is a narrower inverse of this; it converts
    user ids to profile ids.

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the normalized user id
    """
    normalized = translate_user_id(id=id, from_=proto, to=proto)

    if proto.LABEL == 'web':
        normalized = util.domain_from_link(normalized)
    elif proto.LABEL == 'atproto' and id.startswith('at://'):
        normalized, _, _ = parse_at_uri(id)
    elif proto.LABEL == 'nostr':
        normalized = id.removeprefix('nostr:')
    elif proto.LABEL in ('fake', 'efake', 'other'):
        normalized = normalized.replace(':profile:', ':')

    return normalized


def profile_id(*, id, proto):
    """Returns the profile object id for a given user id.

    Examples:

    * Web: user.com => https://user.com/
    * ActivityPub: https://inst.ance/alice => https://inst.ance/alice
    * ATProto: did:plc:123 => at://did:plc:123/app.bsky.actor.profile/self

    Note that :func:`normalize_user_id` does the inverse of this, ie converts
    profile ids to user ids.

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the profile id
    """
    assert proto.owns_id(id) is not False, (id, proto.LABEL)

    match proto.LABEL:
        case 'atproto':
            return f'at://{id}/app.bsky.actor.profile/self'

        case 'web' if not (id.startswith('https://') or id.startswith('http://')):
            return f'https://{id}/'

        # only for unit tests
        case 'fake' if not id.startswith('fake:profile:'):
            return id.replace('fake:', 'fake:profile:')

        case _:
            return id


def translate_handle(*, handle, from_, to, enhanced):
    """Translates a user handle from one protocol to another.

    Args:
      handle (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)
      enhanced (bool): whether to convert to an "enhanced" handle based on the
        user's domain

    TODO: drop enhanced arg, always use if available?

    Returns:
      str: the corresponding handle in ``to``

    Raises:
      ValueError: if the user's handle is invalid, eg begins or ends with an
        underscore or dash
    """
    handle, from_, to = validate(handle, from_, to)

    if from_ == to:
        return handle

    if from_.LABEL != 'ui':
        if from_.owns_handle(handle, allow_internal=True) is False:
            raise ValueError(f'input handle {handle} is not valid for {from_.LABEL}')

    if from_.LABEL == 'nostr':
        # _ username is NIP-05 shortcut for just the domain itself
        # https://nips.nostr.com/5#showing-just-the-domain-as-an-identifier
        handle = handle.removeprefix('_@')

    # "flatten" [@]user@domain handles to just domain-like, eg user.domain,
    # and then append @[protocol domain], so we end up with user.domain@proto.brid.gy
    flattened = handle.lstrip('@').replace('@', '.')
    for from_char in DASH_CHARS:
        flattened = flattened.replace(from_char, '-')

    def flattened_user_at_domain():
        domain = f'{from_.ABBREV}{SUPERDOMAIN}'
        if enhanced or handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
            domain = flattened
        return f'{flattened}@{domain}'

    output = None
    match from_.LABEL, to.LABEL:
        case _, 'activitypub':
            output = '@' + flattened_user_at_domain()

        case _, 'atproto':
            if handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
                return handle

            if util.domain_or_parent_in(flattened, ATPROTO_HANDLE_DOMAINS):
                output = flattened
            else:
                output = flattened_user_at_domain().replace('@', '.')

        case _, 'nostr':
            if handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
                return f'_@{handle}'

            output = flattened_user_at_domain()

        case 'activitypub', 'web':
            user, instance = handle.lstrip('@').split('@')
            # TODO: get this from the actor object's url field?
            output = (f'https://{user}' if user == instance
                    else f'https://{instance}/@{user}')

        case _, 'web':
            output = handle

        # only for unit tests
        case _, 'fake' | 'other' | 'efake':
            output = f'{to.LABEL}:handle:{handle}'

    assert output, (handle, from_.LABEL, to.LABEL)
    # don't check Web handles because they're sometimes URLs, eg
    # @user@instance => https://instance/@user
    if to.LABEL != 'web' and to.owns_handle(output, allow_internal=True) is False:
        raise ValueError(f"{handle} translated to {to.PHRASE} is {output}, which isn't supported there")

    return output


def translate_object_id(*, id, from_, to):
    """Translates a user handle from one protocol to another.

    *NOTE*: unlike :func:`translate_user_id`, if ``to`` is a ``HAS_COPIES`` protocol
    and has no copy object for ``id``, this function returns ``id``, not None!

    TODO: unify with :func:`translate_user_id`.

    Args:
      id (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to``
    """
    id, from_, to = validate(id, from_, to)
    assert from_.owns_id(id) is not False or from_.LABEL == 'ui', (from_.LABEL, id)

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

    if to.LABEL in COPIES_PROTOCOLS:
        if obj := from_.load(id, remote=False):
            if copy := obj.get_copy(to):
                return copy

    if from_.LABEL in COPIES_PROTOCOLS:
        if orig := models.get_original_object_key(id):
            return orig.id()

    match from_.LABEL, to.LABEL:
        case _, 'atproto' | 'nostr':
            logger.debug(f"Can't translate object id {id} to {to.LABEL} , haven't copied it there yet!")
            return id

        case 'web', 'activitypub':
            return urljoin(web_ap_base_domain(util.domain_from_link(id)), f'/r/{id}')

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/convert/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'efake':
            return f'{to.LABEL}:o:{from_.ABBREV}:{id}'

    assert False, (id, from_.LABEL, to.LABEL)


def handle_as_domain(handle):
    """Converts a handle to domain-like format.

    Converts handle to domain format by removing leading @ and replacing
    @ with ., and replacing certain characters (_ ~ :) with -.

    For example:
    * ``@user@instance.com`` => ``user.instance.com``
    * ``user_name@instance.com`` => ``user-name.instance.com``
    * ``@alice@inst~test.com`` => ``alice.inst-test.com``

    Args:
      handle (str or None)

    Returns:
      str or None: if handle is None
    """
    if not handle:
        return None

    flattened = handle.lstrip('@').replace('@', '.')
    for char in DASH_CHARS:
        flattened = flattened.replace(char, '-')

    return flattened
