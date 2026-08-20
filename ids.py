"""Translates user ids, handles, and object ids between protocols.

https://fed.brid.gy/docs#translate
"""
from enum import auto, Enum
import inspect
import logging
import re
from threading import Lock
from urllib.parse import urljoin, urlparse

from arroba.util import parse_at_uri
from cachetools import cached, LRUCache
from flask import request
from google.cloud.ndb.key import _MAX_KEYPART_BYTES
from google.cloud.ndb.query import FilterNode, Query
from granary.bluesky import BSKY_APP_URL_RE, web_url_to_at_uri
import granary.farcaster
import granary.nostr
from webutil import util

from domains import (
    DOMAIN_RE,
    LOCAL_DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    subdomain_wrap,
    SUPERDOMAIN,
    unwrap,
)
import models

logger = logging.getLogger(__name__)

# Protocols to check User.copies and Object.copies before translating.
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
    'bandwagon.fm',
    'beeping.synth.download',
    'booping.synth.download',
    'explore.alt.store',
    'faithtree.social',
    'merping.synth.download',
    'mo-me.social',
    'music-social.com',
    'tags.pub',
    'wetdry.world',
    'xemele.social',
)

# https://github.com/snarfed/bridgy-fed/issues/314
WWW_DOMAINS = frozenset((
    'rako.space',
    'jvt.me',
))


class IdType(Enum):
    """Whether an id identifies a user or an object.

    Returned by :meth:`protocol.Protocol.id_type`.
    """
    USER = auto()
    OBJECT = auto()


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
    from protocol import Protocol

    id, from_, to = validate(id, from_, to)

    # check for and handle our own subdomain-wrapped ids, eg
    # https://bsky.brid.gy/ap/did:plc:456
    if domain_proto := Protocol.for_bridgy_subdomain(id, fed='web'):
        path = urlparse(id).path.strip('/').split('/')
        if (path[0] == from_.ABBREV
                or (from_.ABBREV == 'ap' and domain_proto.ABBREV == 'web'
                    and len(path) == 1)):
            id = unwrap(id)
            from_ = domain_proto

    if from_.owns_id(id) is False and from_.LABEL != 'ui':
        return id

    parsed = urlparse(id)
    if from_.LABEL == 'web' and parsed.path.strip('/') == '':
        # home page; replace with domain
        id = parsed.netloc

    if from_.LABEL == 'nostr':
        if granary.nostr.is_bech32(id):
            id = granary.nostr.uri_to_id(id)
        if not id.startswith('nostr:'):
            id = 'nostr:' + id

    if from_ == to:
        # same protocol: return the fully canonicalized id
        return normalize_user_id(id=id, proto=from_)

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
        case _, 'atproto' | 'nostr' | 'farcaster':
            logger.debug(f"Can't translate user id {id} to {to.LABEL}, haven't copied it there yet!")
            return None

        case 'web', 'activitypub':
            return urljoin(web_ap_base_domain(id), id)

        case 'activitypub', 'web':
            return id

        case 'farcaster', 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/{to.ABBREV}/{id.replace("://", ":")}')

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'efake':
            return f'{to.LABEL}:u:{id}'
        case 'fake' | 'other', _:
            return id

    assert False, (id, from_.LABEL, to.LABEL)


def normalize_user_id(*, id, proto):
    """Normalizes a user id to its canonical representation in a given protocol.

    TODO: what should this return if id is not a valid user id in proto?
    TODO: add and use new is_user_id function for this ^

    Examples:

    * Web:
      * user.com => user.com
      * www.user.com => user.com
      * https://user.com/ => user.com
    * ATProto:
      * did:plc:123 => did:plc:123
      * https://bsky.app/profile/did:plc:123 => did:plc:123
    * Farcaster:
      * 123 => farcaster://123
      * farcaster://@user => farcaster://123

    Note that :func:`profile_id` is a narrower inverse of this; it converts
    user ids to profile ids.

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the normalized user id
    """
    # Farcaster bare/external fids (eg 123, farcaster:123) aren't owned by
    # owns_id, but are still normalizable here, so handle before the guard below.
    if proto.LABEL == 'farcaster':
        if match := re.fullmatch(r'(farcaster:)?([0-9]+)', id):
            return granary.farcaster.uri(match.group(2))

        if ((match := granary.farcaster.FARCASTER_URI_RE.fullmatch(id))
                and not match['hash']):
            if match['fid']:
                return granary.farcaster.uri(match['fid'])
            elif match['username']:
                # TODO: look up in datastore first?
                return proto.handle_to_id(match['username'])

        return id

    if proto.owns_id(id) is False:
        return id

    if proto.LABEL == 'web':
        normalized = util.domain_from_link(id)
        if normalized in WWW_DOMAINS:
            return 'www.' + normalized
        return normalized

    elif proto.LABEL == 'atproto':
        # id = translate_user_id(id=id, from_=proto, to=proto)

        # bsky.app profile URL to DID
        if (match := BSKY_APP_URL_RE.match(id)) and not match['type']:
            repo = match.group('id')
            if repo.startswith('did:'):
                return repo

            from atproto import ATProto
            try:
                return ATProto.handle_to_id(repo)
            except (AssertionError, ValueError) as e:
                logger.warning(e)
                return None

        if id.startswith('at://'):
            repo, coll, tid = parse_at_uri(id)
            if repo and (not coll or coll == 'app.bsky.actor.profile'):
                return repo

    elif proto.LABEL == 'nostr':
        if granary.nostr.is_bech32(id):
            id = granary.nostr.uri_to_id(id)
        if not id.startswith('nostr:'):
            id = 'nostr:' + id

    elif proto.LABEL in ('fake', 'efake', 'other'):
        return id.replace(':profile:', ':')

    return id


def normalize_object_id(*, id, proto):
    """Normalizes an object id to its canonical representation in a given protocol.

    If ``id`` is a user id, and this protocol's profile objects have different ids
    than their user ids, returns the profile id.

    Examples:

    * Web:
      * https://user.com/... (over 1500 chars) => truncated at 1500 chars
      * user.com => https://user.com/
    * ATProto:
      * https://bsky.app/profile/did:plc:123/post/abc =>
        at://did:plc:123/app.bsky.feed.post/abc

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the normalized object id
    """
    id = translate_object_id(id=id, from_=proto, to=proto)

    if proto.LABEL == 'web':
        id = id.split('\n')[0]
        if len(id) > _MAX_KEYPART_BYTES:
            return models.maybe_truncate_key_id(id)
        elif DOMAIN_RE.fullmatch(id):
            return profile_id(id=id, proto=proto)

    elif proto.LABEL == 'nostr':
        if granary.nostr.is_bech32(id):
            id = granary.nostr.uri_to_id(id)
        if granary.nostr.ID_RE.match(id):
            return 'nostr:' + id

    elif proto.LABEL == 'fake':
        username = id.split(':', 1)[1]
        # TODO: this will cause hard-to-debug test failures if we ever use other
        # test Fake user usernames
        if username in ('alice', 'bob', 'eve', 'frank', 'user'):
            return profile_id(id=id, proto=proto)

    return id


def profile_id(*, id, proto):
    """Returns the profile object id for a given user id.

    Examples:

    * Web: user.com => https://user.com/
    * ActivityPub: https://inst.ance/alice => https://inst.ance/alice
    * ATProto: did:plc:123 => at://did:plc:123/app.bsky.actor.profile/self
    * Nostr: nostr:ab12 (pubkey) => nostr:cd34 (profile event)

    Note that :func:`normalize_user_id` does the inverse of this, ie converts
    profile ids to user ids.

    Args:
      id (str)
      proto (protocol.Protocol)

    Returns:
      str: the profile id
    """
    import nostr

    if proto.owns_id(id) is False:
        return id

    match proto.LABEL:
        case 'atproto' if id.startswith('did:'):
            return f'at://{id}/app.bsky.actor.profile/self'

        case 'web' if not (id.startswith('https://') or id.startswith('http://')):
            return f'https://{id}/'

        case 'nostr':
            if not id.startswith('nostr:'):
                id = 'nostr:' + id
            if ((user := nostr.Nostr.get_by_id(id, allow_opt_out=True))
                    and user.obj_key):
                return user.obj_key.id()

        # test data. fake users have different ids from their profile objects;
        # other and efake are the same.
        case 'fake':
            assert ':profile:' not in id
            return id.replace('fake:', 'fake:profile:')

        case _:
            return id


def translate_handle(*, from_, to, handle=None, short=False):
    """Translates a user's handle to another protocol.

    Args:
      from_ (models.User or protocol.Protocol subclass)
      to (protocol.Protocol)
      handle (str): required if ``from_`` is a ``Protocol`` subclass. Must be
        unset if ``from_`` is a ``User``.
      short (bool): whether to return the full handle or a shortened form.
        Default False. Currently only affects ActivityPub; returns just ``@[user]``
        instead of ``@[user]@[domain]``

    Returns:
      str: the corresponding handle in ``to``, or None if ``from_user`` has no
        handle

    Raises:
      ValueError: if the user's handle is invalid, eg begins or ends with an
        underscore or dash
    """
    # normalize to to class
    if not inspect.isclass(to):
        to = to.__class__

    from_user = None
    if isinstance(from_, models.User):
        from_user = from_
        assert handle is None
        handle = from_user.handle

    if not handle:
        return None

    if from_.LABEL == to.LABEL:
        if to.LABEL == 'activitypub' and short:
            return handle.rsplit('@', maxsplit=1)[0]
        elif to.LABEL in ('fake', 'other', 'efake'):
            return handle.replace('-', ':')
        return handle

    if from_.LABEL != 'ui':
        if from_.owns_handle(handle, allow_internal=True) is False:
            raise ValueError(f'input handle {handle} is not valid for {from_.LABEL}')

    bot_user = (handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS)

    # "flatten" [@]user@domain handles to just domain-like, eg user.domain,
    # and then append @[protocol domain], so we end up with user.domain@proto.brid.gy
    flattened = handle.lstrip('@').replace('@', '.')
    for from_char in DASH_CHARS:
        flattened = flattened.replace(from_char, '-')

    def flattened_user_at_domain():
        domain = f'{from_.ABBREV}{SUPERDOMAIN}'
        if bot_user:
            domain = flattened
        return f'{flattened}@{domain}'

    output = None
    match from_.LABEL, to.LABEL:
        case _, _ if handle.endswith(SUPERDOMAIN) and not bot_user:
            handle = handle.strip('@').removesuffix(SUPERDOMAIN)
            username, abbrev = handle.rsplit('@' if '@' in handle else '.', 1)
            if abbrev in ('fa', 'other', 'efake'):
                username = username.replace('-', ':')
            return translate_handle(handle=username, from_=models.PROTOCOLS[abbrev],
                                    to=to, short=short)

        case _, 'activitypub':
            if short:
                return '@' + flattened

            return '@' + flattened_user_at_domain()

        case _, 'atproto':
            if bot_user:
                return handle

            # first check DID doc
            if from_user and (did := from_user.get_copy('atproto')):
                from atproto import did_to_handle
                if handle := did_to_handle(did, remote=False):
                    return handle

            if util.domain_or_parent_in(flattened, ATPROTO_HANDLE_DOMAINS):
                output = flattened
            else:
                output = flattened_user_at_domain().replace('@', '.')

        case _, 'nostr':
            if bot_user:
                return handle

            output = flattened_user_at_domain()

        case _, 'farcaster':
            if bot_user:
                return handle

            # first check the copy's profile Object
            if from_user and (fid := from_user.get_copy('farcaster')):
                if profile := models.Object.get_by_id(fid):
                    if username := (profile.as1 or {}).get('username'):
                        return username

            output = flattened.replace('.', '-')

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
        raise ValueError(f"handle {handle} translated to {to.PHRASE} is {output}, which isn't supported there")

    return output


def translate_object_id(*, id, from_, to):
    """Translates a user handle from one protocol to another.

    Allows any ``id`` if ``from_`` is :class:`UIProtocol` or if ``id`` is ``ui:...``.

    *NOTE*: unlike :func:`translate_user_id`, if ``to`` is a ``HAS_COPIES`` protocol
    and has no copy object for ``id``, this function returns ``id``, not None!

    TODO: unify with :func:`translate_user_id`.

    Args:
      id (str)
      from_ (protocol.Protocol): the native protocol for ``id``
      to (protocol.Protocol): the protocol to convert to

    Returns:
      str: the corresponding id in ``to``
    """
    from protocol import Protocol
    from ui import UIProtocol

    id, from_, to = validate(id, from_, to)

    if UIProtocol.owns_id(id):
        # internal objects are ours, not their author's protocol's, so we always
        # serve them from fed.brid.gy, whoever their author is
        from_ = UIProtocol

    if from_.owns_id(id) is False and from_ != UIProtocol:
        return id

    # bsky.app profile URL to at:// URI
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
        case _, 'atproto' | 'nostr' | 'farcaster':
            logger.debug(f"Can't translate object id {id} to {to.LABEL}, haven't copied it there yet!")
            return id

        case 'web', 'activitypub':
            if Protocol.for_bridgy_subdomain(id, fed='web'):
                return id
            return urljoin(web_ap_base_domain(util.domain_from_link(id)), f'/r/{id}')

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_, f'/convert/{to.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other' | 'efake':
            return f'{to.LABEL}:o:{from_.ABBREV}:{id}'

    assert False, (id, from_.LABEL, to.LABEL)


def translate_id(*, id, from_, to, default=IdType.USER):
    """Translates an id from one protocol to another, user id or object id.

    Use this when you don't know which kind of id you have, eg the ``object`` of
    a ``block``, which may be either a user or a blocklist. Asks
    :meth:`protocol.Protocol.id_type` which kind ``id`` is, then hands off to
    :func:`translate_user_id` or :func:`translate_object_id`.

    https://github.com/snarfed/bridgy-fed/issues/2281

    Args:
      id (str)
      from_ (protocol.Protocol)
      to (protocol.Protocol)
      default (IdType): which kind to assume if ``from_`` can't tell from ``id``
        itself, eg all :class:`activitypub.ActivityPub` ids are http(s) URLs

    Returns:
      str: the corresponding id in ``to``
    """
    if (from_.id_type(id) or default) is IdType.OBJECT:
        return translate_object_id(id=id, from_=from_, to=to)

    return translate_user_id(id=id, from_=from_, to=to)


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

    flattened = handle.lower().lstrip('@').replace('@', '.')
    for char in DASH_CHARS:
        flattened = flattened.replace(char, '-')

    return flattened
