"""Farcaster protocol implementation.

https://farcaster.xyz/
https://github.com/farcasterxyz/protocol/blob/main/docs/SPECIFICATION.md
https://snapchain.farcaster.xyz/
"""
import logging
import os

from google.cloud import ndb
from granary import as1
import granary.farcaster
from granary.farcaster import (
    FARCASTER_URI_RE,
    from_as1,
    hash_and_sign,
)
from granary.generated.farcaster.message_pb2 import (
    CastId,
    Message,
    MESSAGE_TYPE_USER_DATA_ADD,
)
from granary.generated.farcaster.request_response_pb2 import (
    FidRequest,
    SubmitBulkMessagesRequest,
)
import grpc
from webutil import util

from models import Target, User
from protocol import Protocol, STORE_AS1_TYPES

logger = logging.getLogger(__name__)

SNAPCHAIN_HOST = os.getenv('SNAPCHAIN_HOST', granary.farcaster.DEFAULT_SNAPCHAIN_HOST)
SNAPCHAIN_PORT = int(os.getenv('SNAPCHAIN_PORT', granary.farcaster.DEFAULT_SNAPCHAIN_PORT))

_client = None


def client():
    """Returns the cached :class:`granary.farcaster.Farcaster` client.

    Lazily constructs it on first use. gRPC channels (connections) are heavyweight,
    and designed for reuse, and the generated client stub is thread-safe, so we reuse
    it.

    https://grpc.github.io/grpc/python/grpc.html#grpc.Channel
    """
    global _client
    if _client is None:
        _client = granary.farcaster.Farcaster(host=SNAPCHAIN_HOST,
                                              port=SNAPCHAIN_PORT)
    return _client


class Farcaster(User, Protocol):
    """Farcaster class.

    Key id is string ``farcaster://[fid]`` URI.
    """
    ABBREV = 'fc'
    PHRASE = 'Farcaster'
    LOGO_EMOJI = '🏛️'
    LOGO_HTML = '<img src="/static/farcaster_logo.png">'
    CONTENT_TYPE = 'application/octet-stream'
    DEFAULT_TARGET = f'snapchain://{SNAPCHAIN_HOST}:{SNAPCHAIN_PORT}'
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    HAS_COPIES = True
    REQUIRES_AVATAR = True
    REQUIRES_NAME = True
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + ('block', 'follow', 'like', 'share', 'stop-following')
    )
    SUPPORTS_DMS = False
    HTML_PROFILES = False

    @ndb.ComputedProperty
    def handle(self):
        """Returns the Farcaster username from the user's profile."""
        # TODO: switch to self.obj.fc's USER_DATA_TYPE_USERNAME
        if self.obj and self.obj.as1:
            if username := self.obj.as1.get('username'):
                return username

        if self.key:
            return str(self.fid)

    @classmethod
    def owns_id(cls, id):
        return id and id.startswith('farcaster://')

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        if not handle:
            return False
        elif handle.endswith('.eth') or handle.endswith('.fcast.id'):
            return True
        elif granary.farcaster.HANDLE_RE.fullmatch(handle):
            return None

        return False

    @classmethod
    def handle_to_id(cls, handle):
        if cls.owns_handle(handle) is False:
            return None

        if fid := client().get_fid(handle):
            return granary.farcaster.uri(fid)

    @property
    def fid(self):
        """Returns this user's Farcaster FID as an integer.

        Returns:
          int
        """
        return int(self.key.id().removeprefix(('farcaster://')))

    def web_url(self):
        if self.key:
            return granary.farcaster.Farcaster.user_url(self.fid)

    def id_uri(self):
        return self.key.id()

    def is_profile(self, obj):
        if super().is_profile(obj):
            return True

        # a list of USER_DATA_ADD messages is a profile
        if obj and obj.farcaster:
            return all(Message.FromString(b).data.type == MESSAGE_TYPE_USER_DATA_ADD
                       for b in obj.farcaster)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        if not isinstance(user, cls):
            if uri := user.get_copy(cls):
                if match := FARCASTER_URI_RE.fullmatch(uri):
                    return granary.farcaster.Farcaster.user_url(int(match['fid']))

        return super().bridged_web_url_for(user, fallback=fallback)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns the snapchain hub URL as the target for the given object.

        Like ATProto, Farcaster delivery is indirect: we submit messages to a
        hub and they propagate via gossip.
        """
        if cls.owns_id(obj.key.id()) is not False:
            return cls.DEFAULT_TARGET

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Fetches a Farcaster object from a snapchain hub.

        Supports ``farcaster://[fid]`` (user profile) and
        ``farcaster://[fid]/0x[hash]`` (cast) ids.

        Args:
          obj (models.Object): with the id to fetch. Populates ``obj.farcaster``.
          kwargs: ignored

        Returns:
          bool
        """
        id = obj.key.id() if obj.key else None
        if not id or cls.owns_id(id) is False:
            logger.info(f"Farcaster can't fetch {id}")
            return False

        if not (match := FARCASTER_URI_RE.fullmatch(id)):
            return False

        fid = int(match['fid'])
        hash_hex = match['hash']

        try:
            if hash_hex:
                msg = client().hub.GetCast(
                    CastId(fid=fid, hash=bytes.fromhex(hash_hex)))
                obj.farcaster = [msg.SerializeToString()]
            else:
                resp = client().hub.GetUserDataByFid(FidRequest(fid=fid))
                if not resp.messages:
                    return False
                obj.farcaster = [m.SerializeToString() for m in resp.messages]

        except grpc.RpcError as e:
            logger.info(f'hub fetch of {id} failed: {e}')
            return False

        return True

    @classmethod
    def _convert(to_cls, obj, from_user=None, **kwargs):
        """Converts an :class:`Object` to one or more Farcaster :class:`Message`s.

        Args:
          obj (models.Object)
          from_user (models.User): user this object is from
          kwargs: unused

        Returns:
          list of :class:`Message`: multiple messages for actors, otherwise just a
            list with a single message
        """
        if obj.farcaster:
            return [Message.FromString(msg) for msg in obj.farcaster]

        if not obj.as1:
            return []

        translated = to_cls.translate_ids(obj.as1)
        # actors return a list of USER_DATA_ADD messages, other types a single Message
        msgs = from_as1(translated)
        if not isinstance(msgs, list):
            msgs = [msgs]

        if from_user:
            for msg in msgs:
                hash_and_sign(msg, from_user.farcaster_key())

        return msgs

    @classmethod
    def send(to_cls, obj, target, from_user=None, orig_obj_id=None):
        """Submits a Message to a snapchain hub.

        Converts ``obj`` to a Farcaster :class:`Message`, signs it, and submits
        it via the hub's ``SubmitMessage`` RPC. Adds the resulting
        ``farcaster://[fid]/0x[hash]`` URI to ``obj.copies``.

        Args:
          obj (models.Object): activity to send
          target (str): ignored; sends to the configured hub
          from_user (models.User): user (actor) this activity is from
          orig_obj_id (str): unused

        Returns:
          bool
        """
        assert obj
        assert from_user
        assert obj.source_protocol != 'farcaster'

        if not (msgs := to_cls.convert(obj, from_user=from_user)):
            return False

        for msg in msgs:
            if not msg.signature:
                # convert() didn't sign (eg no from_user); sign now
                hash_and_sign(msg, from_user.farcaster_key())

        try:
            resp = client().hub.SubmitBulkMessages(
                SubmitBulkMessagesRequest(messages=msgs))
        except grpc.RpcError as e:
            logger.warning(f'hub SubmitBulkMessages failed: {e}')
            return False

        if not resp.messages:
            logger.warning(f'no messages in response!')
            return False

        for msg in resp.messages:
            if msg.HasField('message_error'):
                logger.warning(f'hub SubmitBulkMessages error: {resp.message_error}')
                return False
            elif not msg.message.HasField('data'):
                logger.warning(f'response message missing data! {msg}')
                return False

        # add copy uri. for single-message types (cast/like/follow/...) we use
        # the hash; for multi-message profile updates we identify by fid only.
        if obj.type in STORE_AS1_TYPES:
            msg = resp.messages[0].message
            hash = msg.hash if len(msgs) == 1 else None
            copy_uri = granary.farcaster.uri(msg.data.fid, hash=hash)

            @ndb.transactional()
            def add_copy():
                o = obj.key.get(read_consistency=ndb.STRONG) or obj
                o.remove_copies_on(to_cls)
                o.add('copies', Target(uri=copy_uri, protocol=to_cls.LABEL))
                o.put()
            add_copy()

        return True
