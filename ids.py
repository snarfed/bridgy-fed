"""Convert ids and handles between protocols.

https://fed.brid.gy/docs#translate
"""
from granary.bluesky import Bluesky

from activitypub import ActivityPub
from atproto import ATProto
from common import host_url
from models import User
from protocol import Protocol, PROTOCOLS
from web import Web


def convert_id(*, id, from_proto, to_proto):
    """Converts an id (not necessarily handle) from one protocol to another.

    Args:
      id (str)
      from_proto (:class:`Protocol`)
      to_proto (:class:`Protocol`)

    Returns:
      str: the corresponding id in ``to_proto``
    """
    assert id and from_proto and to_proto
    assert from_proto != to_proto

    match (from_proto.LABEL, to_proto.LABEL):
        case (_, 'atproto'):
            user = from_proto.get_by_id(id)
            return user.atproto_did if user else None
        case ('atproto', _):
            user = from_proto.get_for_copy(id)
            return user.key.id() if user else None
        case (_, 'activitypub'):
            return host_url(f'{from_proto.ABBREV}/{ActivityPub.ABBREV}/{id}')
        case ('activitypub', 'web'):
            return id
        # fake protocol is only for unit tests
        case (_, 'fake'):
            return f'fake:{id}'
        case ('fake', _):
            return id

    assert False
