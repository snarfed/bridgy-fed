"""Translates user ids, handles, and object ids between protocols.

https://fed.brid.gy/docs#translate
"""
import logging
import re
from urllib.parse import urljoin, urlparse

from flask import request

from common import subdomain_wrap, LOCAL_DOMAINS, PRIMARY_DOMAIN, SUPERDOMAIN
import models

logger = logging.getLogger(__name__)

# Protocols to check User.copies and Object.copies before translating
COPIES_PROTOCOLS = ('atproto', 'fake', 'other', 'nostr')


def translate_user_id(*, id, from_proto, to_proto):
    """Translate a user id from one protocol to another.

    Args:
      id (str)
      from_proto (protocol.Protocol)
      to_proto (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to_proto``
    """
    assert id and from_proto and to_proto
    assert from_proto.owns_id(id) is not False or from_proto.LABEL == 'ui'

    parsed = urlparse(id)
    if from_proto.LABEL == 'web' and parsed.path.strip('/') == '':
        # home page; replace with domain
        id = parsed.netloc

    if from_proto == to_proto:
        return id

    # follow use_instead
    user = from_proto.get_by_id(id)
    if user:
        id = user.key.id()

    if from_proto.LABEL in COPIES_PROTOCOLS or to_proto.LABEL in COPIES_PROTOCOLS:
        if user:
            if copy := user.get_copy(to_proto):
                return copy
        if orig := models.get_original(id):
            if isinstance(orig, to_proto):
                return orig.key.id()

    match from_proto.LABEL, to_proto.LABEL:
        case _, 'atproto' | 'nostr':
            logger.warning(f"Can't translate user id {id} to {to_proto.LABEL} , haven't copied it there yet!")
            return None

        case 'web', 'activitypub':
            # special case web => AP for historical backward compatibility
            base = (request.host_url if request.host in LOCAL_DOMAINS
                    else f'https://{PRIMARY_DOMAIN}/')
            return urljoin(base, id)

        case 'activitypub', 'web':
            return id

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_proto, f'/{to_proto.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other':
            return f'{to_proto.LABEL}:u:{id}'
        case 'fake' | 'other', _:
            return id

    assert False, (id, from_proto, to_proto)


def translate_handle(*, handle, from_proto, to_proto, enhanced):
    """Translates a user handle from one protocol to another.

    Args:
      handle (str)
      from_proto (protocol.Protocol)
      to_proto (protocol.Protocol)
      enhanced (bool): whether to convert to an "enhanced" handle based on the
        user's domain

    Returns:
      str: the corresponding handle in ``to_proto``
    """
    assert handle and from_proto and to_proto
    assert from_proto.owns_handle(handle) is not False or from_proto.LABEL == 'ui'

    if from_proto == to_proto:
        return handle

    match from_proto.LABEL, to_proto.LABEL:
        case _, 'activitypub':
            domain = handle if enhanced else f'{from_proto.ABBREV}{SUPERDOMAIN}'
            return f'@{handle}@{domain}'

        case _, 'atproto' | 'nostr':
            handle = handle.lstrip('@').replace('@', '.')
            return (handle if enhanced
                    else f'{handle}.{from_proto.ABBREV}{SUPERDOMAIN}')

        case 'activitypub', 'web':
            user, instance = handle.lstrip('@').split('@')
            # TODO: get this from the actor object's url field?
            return (f'https://{user}' if user == instance
                    else f'https://{instance}/@{user}')

        case _, 'web':
            return handle

        # only for unit tests
        case _, 'fake':
            return f'fake:handle:{handle}'
        case _, 'other':
            return f'other:handle:{handle}'

    assert False, (id, from_proto, to_proto)


def translate_object_id(*, id, from_proto, to_proto):
    """Translates a user handle from one protocol to another.

    Args:
      id (str)
      from_proto (protocol.Protocol)
      to_proto (protocol.Protocol)

    Returns:
      str: the corresponding id in ``to_proto``
    """
    assert id and from_proto and to_proto
    assert from_proto.owns_id(id) is not False or from_proto.LABEL == 'ui'

    if from_proto == to_proto:
        return id

    if from_proto.LABEL in COPIES_PROTOCOLS or to_proto.LABEL in COPIES_PROTOCOLS:
        if obj := from_proto.load(id, remote=False):
            if copy := obj.get_copy(to_proto):
                return copy
        if orig := models.get_original(id):
            return orig.key.id()

    match from_proto.LABEL, to_proto.LABEL:
        case _, 'atproto' | 'nostr':
            logger.warning(f"Can't translate object id {id} to {to_proto.LABEL} , haven't copied it there yet!")
            return id

        case 'web', 'activitypub':
            # special case web => AP for historical backward compatibility
            base = (request.host_url if request.host in LOCAL_DOMAINS
                    else f'https://{PRIMARY_DOMAIN}')
            return urljoin(base, f'/r/{id}')

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_proto, f'/convert/{to_proto.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake' | 'other':
            return f'{to_proto.LABEL}:o:{from_proto.ABBREV}:{id}'

    assert False, (id, from_proto, to_proto)
