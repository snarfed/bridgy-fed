"""Nostr protocol implementation.

https://github.com/nostr-protocol/nostr
https://github.com/nostr-protocol/nips/blob/master/01.md
https://github.com/nostr-protocol/nips#list

Nostr Object key ids are NIP-21 nostr:... URIs.
https://nips.nostr.com/21
"""
import logging

from google.cloud import ndb
from granary import as1, nostr
from requests import RequestException
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import add, json_dumps, json_loads

import common
from common import (
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    DOMAINS,
    error,
    USER_AGENT,
)
import ids
from models import Object, PROTOCOLS, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)


class Nostr(User, Protocol):
    """Nostr class.

    Key id is bech32 npub id.
    https://github.com/nostr-protocol/nips/blob/master/19.md
    """
    ABBREV = 'nostr'
    PHRASE = 'Nostr'
    LOGO_HTML = '<img src="/static/nostr.png">'
    CONTENT_TYPE = 'application/json'
    HAS_COPIES = True
    REQUIRES_AVATAR = True
    REQUIRES_NAME = True
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + ('post', 'delete', 'undo')  # no update/edit (I think?)
        + ('follow', 'like', 'share', 'stop-following')
    )
    SUPPORTS_DMS = False  # NIP-17

    @ndb.ComputedProperty
    def handle(self):
        """TODO: NIP-05"""
        return None

    def web_url(self):
        return None  # TODO

    def id_uri(self):
        return f'nostr:{self.key.id()}'

    @classmethod
    def owns_id(cls, id):
        return id.startswith('nostr:') or bool(nostr.is_bech32(id))

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        if not handle:
            return False

        # TODO: implement allow_internal?
        return (handle.startswith('npub')
                or cls.is_user_at_domain(handle, allow_internal=True))

    @classmethod
    def handle_to_id(cls, handle):
        if cls.owns_handle(handle) is False:
            return None

        if handle.startswith('npub'):
            return handle

        # TODO: implement NIP-05 resolution
        return None

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        """TODO: which client? coracle?
        """
        return None

    @classmethod
    def target_for(cls, obj, shared=False):
        """Look up the author's relays and return one?
        """
        return None

    @classmethod
    def create_for(cls, user):
        """Creates a Nostr profile for a non-Nostr user.

        Args:
          user (models.User)
        """
        pass  # TODO

    @classmethod
    def set_username(to_cls, user, username):
        """check NIP-05 DNS, then update profile event with nip05?"""
        if not user.is_enabled(Nostr):
            raise ValueError("First, you'll need to bridge your account into Nostr by following this account.")

        npub = user.get_copy(Nostr)
        username = username.removeprefix('@')

        # TODO: implement NIP-05 setup
        logger.info(f'Setting Nostr NIP-05 for {user.key.id()} to {username}')
        pass

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj_id=None):
        """Sends an object to a relay.
        """
        # TODO: send to relay
        return False

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Tries to fetch a Nostr event from a relay.

        Args:
          obj (models.Object): with the id to fetch. Fills data into the ``as2``
            property.
          kwargs: ignored

        Returns:
          bool: True if the object was fetched and populated successfully,
          False otherwise
        """
        id = obj.key.id()
        if not cls.owns_id(id):
            logger.info(f"Nostr can't fetch {id}")
            return False

        # TODO: fetch from relay
        return False


    @classmethod
    def _convert(cls, obj, from_user=None):
        """Converts a :class:`models.Object` to a Nostr event.

        Args:
          obj (models.Object)
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          dict: JSON Nostr event
        """
        from_proto = PROTOCOLS.get(obj.source_protocol)

        # TODO: implement actual conversion
        if not obj.as1:
            return {}

        return {}  # TODO
