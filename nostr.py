"""Nostr protocol implementation.

https://github.com/nostr-protocol/nostr
https://github.com/nostr-protocol/nips/blob/master/01.md
https://github.com/nostr-protocol/nips#list

Nostr Object key ids are NIP-21 nostr:... URIs.
https://nips.nostr.com/21
"""
import logging

from google.cloud import ndb
from granary import as1
import granary.nostr
from granary.nostr import bech32_prefix_for, id_to_uri, uri_to_id
from requests import RequestException
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import add, json_dumps, json_loads
import secp256k1
from websockets.exceptions import ConnectionClosedOK
from websockets.sync.client import connect

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
    LOGO_HTML = '<img src="/static/nostr_logo.png">'
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
        if self.obj_key:
            return granary.nostr.Nostr.user_url(
                self.obj_key.id().removeprefix("nostr:"))

    def id_uri(self):
        return f'nostr:{self.key.id()}'

    @classmethod
    def owns_id(cls, id):
        return id.startswith('nostr:') or bool(granary.nostr.is_bech32(id))

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
        elif handle.startswith('npub'):
            return handle

        return granary.nostr.nip05_to_npub(handle)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        if not isinstance(user, cls) and user.obj:
            if nprofile := user.obj.get_copy(cls):
                return granary.nostr.Nostr.user_url(nprofile)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Look up the author's relays and return one?"""
        return None

    @classmethod
    def create_for(cls, user):
        """Creates a Nostr profile for a non-Nostr user.

        Args:
          user (models.User)
        """
        assert not isinstance(user, cls)

        if npub := user.get_copy(cls):
            return

        # generate keypair if necessary, store npub as copy in user
        if not user.nostr_key_bytes:
            logger.info(f'generating Nostr keypair for {user.key}')
            privkey = secp256k1.PrivateKey()
            user.nostr_key_bytes = privkey.private_key

        pubkey = granary.nostr.pubkey_from_privkey(user.nostr_key_bytes.hex())
        npub = id_to_uri('npub', pubkey)
        logger.info(f'adding Nostr copy user {npub} for {user.key}')
        user.add('copies', Target(uri=npub, protocol='nostr'))
        user.put()

        if user.obj and any(copy.protocol == 'nostr' for copy in user.obj.copies):
            return

        # create Nostr profile (kind 0 event) if necessary
        if not user.obj or not user.obj.as1:
            user.reload_profile()

        if user.obj and not user.obj.get_copy(cls):
            cls.send(user.obj, 'TODO relay', from_user=user)

    @classmethod
    def set_username(to_cls, user, username):
        """check NIP-05 DNS, then update profile event with nip05?"""
        if not user.is_enabled(to_cls):
            raise ValueError("First, you'll need to bridge your account into Nostr by following this account.")

        npub = user.get_copy(to_cls)
        username = username.removeprefix('@')

        # TODO: implement NIP-05 setup
        logger.info(f'Setting Nostr NIP-05 for {user.key.id()} to {username}')
        pass

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
    def _convert(to_cls, obj, from_user=None):
        """Converts a :class:`models.Object` to a Nostr event.

        Args:
          obj (models.Object)
          from_user (models.User): user this object is from

        Returns:
          dict: JSON Nostr event
        """
        privkey = None
        if from_user and from_user.nostr_key_bytes:
            privkey = granary.nostr.bech32_encode(
                'nsec', from_user.nostr_key_bytes.hex())

        translated = to_cls.translate_ids(obj.as1)
        return granary.nostr.from_as1(translated, privkey=privkey)

    @classmethod
    def send(to_cls, obj, relay_url, from_user=None, **kwargs):
        """Sends an event to a relay."""
        assert from_user
        assert from_user.nostr_key_bytes

        event = to_cls.convert(obj, from_user=from_user)
        pubkey = granary.nostr.pubkey_from_privkey(from_user.nostr_key_bytes.hex())
        assert event.get('pubkey') == pubkey, event
        assert event.get('sig'), event

        with connect(relay_url, open_timeout=util.HTTP_TIMEOUT,
                     close_timeout=util.HTTP_TIMEOUT) as websocket:
            try:
                websocket.send(json_dumps(['EVENT', event]))
                msg = websocket.recv(timeout=util.HTTP_TIMEOUT)
            except ConnectionClosedOK as cc:
                logger.warning(cc)
                return False

        event_uri = id_to_uri(bech32_prefix_for(event), event['id'])
        obj.add('copies', Target(uri=event_uri, protocol=to_cls.LABEL))
        return True
