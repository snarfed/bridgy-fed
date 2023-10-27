"""Translates user ids, handles, and object ids between protocols.

https://fed.brid.gy/docs#translate
"""
import logging
import re

from common import subdomain_wrap, SUPERDOMAIN
import models

logger = logging.getLogger(__name__)


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
    assert from_proto.owns_id(id) is not False

    if from_proto == to_proto:
        return id

    match from_proto.LABEL, to_proto.LABEL:
        case _, 'atproto':
            user = from_proto.get_by_id(id)
            return user.atproto_did if user else None
        case 'atproto', _:
            user = models.get_for_copy(id)
            return user.key.id() if user else None
        case _, 'activitypub':
            return subdomain_wrap(from_proto, f'/ap/{id}')
        case 'activitypub', 'web':
            return id
        # only for unit tests
        case _, 'fake':
            return f'fake:{id}'
        case _, 'other':
            return f'other:{id}'
        case 'fake' | 'other', _:
            return id

    assert False, (id, from_proto, to_proto)


def translate_handle(*, handle, from_proto, to_proto):
    """Translates a user handle from one protocol to another.

    Args:
      handle (str)
      from_proto (protocol.Protocol)
      to_proto (protocol.Protocol)

    Returns:
      str: the corresponding handle in ``to_proto``
    """
    assert handle and from_proto and to_proto
    assert from_proto.owns_handle(handle) is not False

    if from_proto == to_proto:
        return handle

    match from_proto.LABEL, to_proto.LABEL:
        case _, 'activitypub':
            if True:  # basic
                return f'@{handle}@{from_proto.ABBREV}{SUPERDOMAIN}'
            else:  # enhanced (TODO)
                return f'@{handle}@{handle}'
        case _, 'atproto' | 'nostr':
            handle = handle.lstrip('@').replace('@', '.')
            if True:  # basic
                return f'{handle}.{from_proto.ABBREV}{SUPERDOMAIN}'
            else:  # enhanced (TODO)
                return handle
        case 'activitypub', 'web':
            user, instance = handle.lstrip('@').split('@')
            return f'instance/@user'  # TODO
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
    assert from_proto.owns_id(id) is not False

    if from_proto == to_proto:
        return id

    # fall back subdomain-wrapped /convert/ URLs
    match from_proto.LABEL, to_proto.LABEL:
        case ('atproto' | 'nostr', _) | (_, 'atproto' | 'nostr'):
            obj = from_proto.load(id, remote=False)
            if obj:
                for copy in obj.copies:
                    if copy.protocol in (to_proto.LABEL, to_proto.ABBREV):
                        return copy.uri
            orig = models.get_for_copy(id)
            if orig:
                return orig.key.id()
            logger.warning(f"Can't translate {id} to {to_proto} , haven't copied it to/from there yet!")
            return id

        case _, 'activitypub' | 'web':
            return subdomain_wrap(from_proto, f'convert/{to_proto.ABBREV}/{id}')

        # only for unit tests
        case _, 'fake':
            return f'fake:{from_proto.ABBREV}:{id}'
        case _, 'other':
            return f'other:{from_proto.ABBREV}:{id}'

    assert False, (id, from_proto, to_proto)
