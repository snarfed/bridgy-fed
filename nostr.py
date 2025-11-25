"""Nostr protocol implementation.

https://github.com/nostr-protocol/nostr
https://github.com/nostr-protocol/nips/blob/master/01.md
https://github.com/nostr-protocol/nips#list

Nostr Object key ids are NIP-21 nostr:... URIs.
https://nips.nostr.com/21
"""
from datetime import timezone
import logging
from urllib.parse import urlparse, urlunparse

from google.cloud import ndb
from google.cloud.ndb.query import OR
from granary import as1
import granary.nostr
from granary.nostr import (
    bech32_prefix_for,
    id_and_sign,
    id_to_uri,
    is_bech32,
    KIND_ARTICLE,
    KIND_CONTACTS,
    KIND_DELETE,
    KIND_GENERIC_REPOST,
    KIND_NOTE,
    KIND_PROFILE,
    KIND_REACTION,
    KIND_RELAYS,
    KIND_REPOST,
    ID_RE,
    nip05_to_npub,
    uri_to_id,
)
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import get_required_param
from oauth_dropins.webutil.models import StringIdModel
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import add, json_dumps, json_loads
from requests import RequestException
import secp256k1
from websockets.exceptions import ConnectionClosedOK
from websockets.sync.client import connect
from werkzeug.exceptions import NotFound

import common
from common import (
    DOMAIN_RE,
    DOMAINS,
    error,
    USER_AGENT,
)
from flask_app import app
import ids
from models import Follower, Object, PROTOCOLS, Target, User
from protocol import Protocol, STORE_AS1_TYPES
import web

logger = logging.getLogger(__name__)


class NostrRelay(StringIdModel):
    """The last ``created_at`` we've seen from a given relay.

    Key id is full relay URI, eg ``wss://nos.lol``. Used in ``nostr_hub``.

    https://nips.nostr.com/1#from-client-to-relay-sending-events-and-creating-subscriptions
    """
    since = ndb.IntegerProperty()
    ''
    created = ndb.DateTimeProperty(auto_now_add=True, tzinfo=timezone.utc)
    ''
    updated = ndb.DateTimeProperty(auto_now=True, tzinfo=timezone.utc)
    ''


class Nostr(User, Protocol):
    """Nostr class.

    Key id is hex pubkey with nostr: prefix.
    """
    ABBREV = 'nostr'
    PHRASE = 'Nostr'
    LOGO_EMOJI = '𓅦'  # ostrich-ish bird
    LOGO_HTML = '<img src="/static/nostr_logo.png">'
    CONTENT_TYPE = 'application/json'
    HAS_COPIES = True
    DEFAULT_TARGET = 'wss://nos.lol/'
    REQUIRES_AVATAR = True
    REQUIRES_NAME = True
    DEFAULT_ENABLED_PROTOCOLS = ()  # TODO: add back 'web' for launch?
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        # note that update is supported for actors and articles, but not notes
        # https://github.com/nostr-protocol/nips/issues/646
        # we override check_supported() below to check for this
        + tuple(as1.CRUD_VERBS)
        + ('follow', 'like', 'share', 'stop-following')
    )
    # only applies to incoming events, in nostr_hub.
    # TODO: add KIND_CONTACTS once we're ready to handle it.
    # https://github.com/snarfed/bridgy-fed/issues/2203
    SUPPORTED_KINDS = frozenset((
        KIND_ARTICLE, KIND_DELETE, KIND_GENERIC_REPOST, KIND_NOTE,
        KIND_PROFILE, KIND_REACTION, KIND_RELAYS, KIND_REPOST,
    ))
    SUPPORTS_DMS = False  # NIP-17
    HTML_PROFILES = False

    relays = ndb.KeyProperty(kind='Object')
    """NIP-65 kind 10002 event with this user's relays."""
    valid_nip05 = ndb.StringProperty()
    """NIP-05 identifier that we've resolved and verified."""

    def _pre_put_hook(self):
        """Validates that the id is a hex pubkey with nostr: prefix.

        ...and also that we aren't storing a private key for this user since we don't
        have their private key.
        """
        assert self.key.id().startswith('nostr:'), self.key.id()
        assert ID_RE.match(self.key.id().removeprefix('nostr:')), self.key.id()
        assert not self.nostr_key_bytes, self.key.id()
        return super()._pre_put_hook()

    def hex_pubkey(self):
        """Returns the user's hex-encoded Nostr public secp256k1 key.

        Returns:
          str:
        """
        return self.key.id().removeprefix('nostr:')

    def npub(self):
        """Returns the user's bech32-encoded ActivityPub public secp256k1 key.

        Returns:
          str:
        """
        return id_to_uri('npub', self.hex_pubkey()).removeprefix('nostr:')

    def id_uri(self):
        return id_to_uri('npub', self.hex_pubkey())

    @ndb.ComputedProperty
    def handle(self):
        """Returns the NIP-05 identity from the user's profile event."""
        if nip05 := self.nip_05():
            return nip05.removeprefix('_@')
        elif self.key:
            return self.npub()

    @ndb.ComputedProperty
    def status(self):
        if not self.obj or not self.obj.as1:
            return 'no-profile'

        # check NIP-05
        nip05 = self.nip_05()
        if not nip05:
            self.valid_nip05 = None
        elif nip05 != self.valid_nip05:
            self.valid_nip05 = None
            try:
                if nip05_to_npub(nip05) == self.npub():
                    logger.info(f'resolved valid NIP-05 {nip05} for {self.key}')
                    self.valid_nip05 = nip05
            except BaseException as e:
                code, _ = util.interpret_http_exception(e)
                if not code:
                    logger.info(e)

            if self.valid_nip05:
                # unset this NIP-05 on any other Nostr users that currently have it
                others = Nostr.query(Nostr.valid_nip05 == nip05).fetch()
                to_put = []
                for other in others:
                    if other.key.id() != self.key.id():
                        logger.info(f'removing NIP-05 {other.valid_nip05} from {other.key}')
                        other.valid_nip05 = None
                        to_put.append(other)
                ndb.put_multi(to_put)

        if not self.valid_nip05 or self.valid_nip05 != self.nip_05():
            return 'no-nip05'

        return super().status

    def nip_05(self):
        if not self.obj:
            return

        if self.obj.nostr:
            assert self.obj.nostr.get('kind') == KIND_PROFILE
            content = json_loads(self.obj.nostr.get('content', '{}'))
            if nip05 := content.get('nip05'):
                return nip05

        elif self.obj.as1:
            if username := self.obj.as1.get('username'):
                if '@' not in username:
                    username = '_@' + username
                return username

    def web_url(self):
        if self.key:
            return granary.nostr.Nostr.user_url(self.npub())

    def is_profile(self, obj):
        if super().is_profile(obj):
            return True

        if (obj and obj.nostr
                and obj.nostr.get('pubkey') == self.hex_pubkey()
                and obj.nostr.get('kind') == KIND_PROFILE):
            return True

    @classmethod
    def owns_id(cls, id):
        if id.startswith('nostr:'):
            return True
        elif is_bech32(id) or ID_RE.match(id):
            return None

        return False

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        if not handle:
            return False

        # TODO: implement allow_internal?
        if (handle.startswith('npub')
                or cls.is_user_at_domain(handle, allow_internal=True)):
            return True

        if web.is_valid_domain(handle):
            return None  # could be a _@ NIP-05

        return False

    @classmethod
    def handle_to_id(cls, handle):
        if cls.owns_handle(handle) is False:
            return None
        elif handle.startswith('npub'):
            return handle

        try:
            npub = nip05_to_npub(handle)
        except ValueError as e:
            logger.info(e)
            return None
        except BaseException as e:
            code, _ = util.interpret_http_exception(e)
            if code:
                return None
            raise

        return 'nostr:' + uri_to_id(npub)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        if not isinstance(user, cls):
            if id := user.get_copy(cls):
                return granary.nostr.Nostr.user_url(
                    id_to_uri('npub', id).removeprefix('nostr:'))

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns the first NIP-65 relay for the given object's author."""
        if obj and (id := as1.get_owner(obj.as1)) and id.startswith('nostr:'):
            if user := Nostr.get_or_create(id, allow_opt_out=True):
                if user.relays and (relays := user.relays.get()):
                    if relays.nostr:
                        for tag in relays.nostr.get('tags', []):
                            if tag[0] == 'r' and (len(tag) == 2 or tag[2] == 'write'):
                                return normalize_relay_uri(tag[1])

    @classmethod
    def check_supported(cls, obj, direction):
        """Update is only supported for actors and articles, not notes."""
        super().check_supported(obj, direction)

        if direction == 'send':
            if obj.type == 'update':
                if inner_type := as1.object_type(as1.get_object(obj.as1)):
                    if inner_type not in list(as1.ACTOR_TYPES) + ['article']:
                        error(f"Bridgy Fed for {cls.LABEL} doesn't support {obj.type} {inner_type} yet", status=204)

    @classmethod
    def create_for(cls, user):
        """Creates a Nostr profile for a non-Nostr user.

        Args:
          user (models.User)
        """
        assert not isinstance(user, cls)

        if npub := user.get_copy(cls):
            return

        logger.info(f'adding Nostr copy user {user.npub()} for {user.key}')
        user.add('copies', Target(uri='nostr:' + user.hex_pubkey(), protocol='nostr'))
        user.put()

        # create profile (kind 0) and relays (kind 10002) events if necessary
        if user.obj and user.obj.get_copy(Nostr):
            return

        if not user.obj.as1:
            user.reload_profile()
        cls.send(user.obj, cls.DEFAULT_TARGET, from_user=user)

    def reload_profile(self, **kwargs):
        """Reloads this user's kind 0 profile, NIP-65 relay list, and NIP-05 id.

        https://nips.nostr.com/1#kinds
        https://nips.nostr.com/65
        https://nips.nostr.com/5
        """
        client = granary.nostr.Nostr()
        relay = normalize_relay_uri(self.target_for(self.obj) or self.DEFAULT_TARGET)
        logger.debug(f'connecting to {relay}')
        with connect(relay, open_timeout=util.HTTP_TIMEOUT,
                     close_timeout=util.HTTP_TIMEOUT) as websocket:
            events = client.query(websocket, {
                'authors': [self.hex_pubkey()],
                'kinds': [KIND_PROFILE, KIND_RELAYS],
            })

        profile = relays = None
        for event in events:
            kind = event.get('kind')
            if kind == KIND_PROFILE and not profile:
                profile = Object.get_or_create('nostr:' + event['id'], nostr=event,
                                               source_protocol='nostr',
                                               authed_as=self.key.id())
                self.obj_key = profile.key
            elif kind == KIND_RELAYS and not relays:
                relays = Object.get_or_create('nostr:' + event['id'], nostr=event,
                                               source_protocol='nostr',
                                               authed_as=self.key.id())
                self.relays = relays.key

            if profile and relays:
                break

        # re-checks NIP-05 in status()
        self.put()

    @classmethod
    def set_username(to_cls, user, username):
        """check NIP-05 DNS, then update profile event with nip05?"""
        if not user.is_enabled(to_cls):
            raise ValueError("First, you'll need to bridge your account into Nostr by following this account.")

        npub = user.get_copy(to_cls)
        username = username.removeprefix('@')

        # TODO
        logger.info(f'Setting Nostr NIP-05 for {user.key.id()} to {username}')
        raise NotImplementedError()

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Fetches a Nostr event from a relay.

        Args:
          obj (models.Object): with the id to fetch. Fills data into the ``nostr``
            property.
          kwargs: ignored

        Returns:
          bool: True if the object was fetched and populated successfully,
            False otherwise
        """
        if not cls.owns_id(obj.key.id()):
            logger.info(f"Nostr can't fetch {obj.key.id()}")
            return False

        id = obj.key.id().removeprefix('nostr:')
        client = granary.nostr.Nostr()
        relay = normalize_relay_uri(cls.target_for(obj) or cls.DEFAULT_TARGET)
        assert relay
        logger.debug(f'connecting to {relay}')
        with connect(relay, open_timeout=util.HTTP_TIMEOUT,
                     close_timeout=util.HTTP_TIMEOUT) as websocket:
            events = client.query(websocket, {'ids': [id]})

        if not events:
            return False

        obj.nostr = events[0]
        return True

    @classmethod
    def _convert(to_cls, obj, from_user=None):
        """Converts a :class:`models.Object` to a Nostr event.

        Args:
          obj (models.Object)
          from_user (models.User): user this object is from

        Returns:
          dict: JSON Nostr event
        """
        if obj.nostr:
            return obj.nostr

        obj_as1 = obj.as1
        translated = to_cls.translate_ids(obj_as1)

        if from_user and from_user.is_profile(obj):
            # username gets set as nip05
            translated['username'] = from_user.handle_as(Nostr)

        # find first relay (target) for referenced user (follow of, in reply to,
        # repost of)
        if as1.object_type(obj_as1) in as1.CRUD_VERBS:
            obj_as1 = as1.get_object(obj_as1)

        remote_relay = ''
        if remote_obj := granary.nostr.Nostr().base_object(obj_as1):
            if id := remote_obj.get('id'):
                base_obj = Nostr.load(id)
                remote_relay = to_cls.target_for(base_obj) or ''

        # NIP-48 proxy tag with original protocol's id
        proxy_tag = None
        if ((orig_id := obj_as1.get('id')) and not orig_id.startswith('nostr:')
                and obj.source_protocol):
            proxy_tag = (orig_id, obj.source_protocol)

        # convert!
        privkey = from_user.nsec() if from_user else None
        event = granary.nostr.from_as1(translated, privkey=privkey,
                                       remote_relay=remote_relay,
                                       proxy_tag=proxy_tag)

        # for outbound follows (kind 3 events), include *all* followed users
        util.d(obj.type, obj.as1.get('actor'), from_user.key.id())
        if (from_user and obj.type == 'follow'
                and obj.as1.get('actor') == from_user.key.id()):
            logging.info(f"adding all of {from_user.key.id()}'s follows")
            # TODO: limit
            for follower in Follower.query(
                    Follower.from_ == from_user.key,
                    # Follower.to._kind == Nostr,
                    Follower.to >= ndb.Key('Nostr', chr(0)),
                    Follower.to < ndb.Key('Nosts', chr(0)),
                    Follower.status == 'active'):
                pubkey = follower.to.id().removeprefix('nostr:')
                util.add(event['tags'], ['p', pubkey, remote_relay or '', ''])

        # override d tag (if any) based on original protocol-native id, not
        # translated Nostr event id
        event_orig_ids = granary.nostr.from_as1(obj.as1)
        for tag in event_orig_ids['tags']:
            if len(tag) >= 2 and tag[0] == 'd':
                # override d tag with this one
                event['tags'] = [tag] + [t for t in event['tags'] if t[0] != 'd']
                if privkey:
                    event.pop('id', None)
                    event.pop('sig', None)
                    id_and_sign(event, privkey)
                else:
                    event['id'] = id_for(event)

        return event

    @classmethod
    def send(to_cls, obj, relay_url, from_user=None, **kwargs):
        """Sends an event to a relay.

        Events are immutable, so all operations happen by sending a new event,
        including updates and deletes. :meth:`granary.nostr.from_as1` translates all
        of those, so all we have to do here is convert and send the event.
        """
        relay_url = normalize_relay_uri(relay_url)
        assert obj
        assert from_user
        assert obj.source_protocol != 'nostr'

        if obj.type in ('post', 'update'):
            if not (obj := to_cls.load(as1.get_id(obj.as1, 'object'))):
                return False

        # store and reuse converted Nostr event across sends. granary.nostr.from_as1
        # sets created_at to now, so if we convert fresh each time, we'll generate
        # new events with different ids.
        if not obj.nostr:
            @ndb.transactional()
            def convert():
                nonlocal obj
                # read_consistency=ndb.STRONG shouldn't be necessary here, but oddly
                # it is, ndb seems to use cache inside txes even though it shouldn't
                # https://github.com/googleapis/python-ndb/issues/751
                # https://github.com/googleapis/python-ndb/issues/888 ?
                obj = obj.key.get(read_consistency=ndb.STRONG) or obj
                if not obj.nostr:
                    obj.nostr = to_cls.convert(obj, from_user=from_user)
                    obj.put()
            convert()

        event = obj.nostr
        assert event
        assert event.get('pubkey') == from_user.hex_pubkey(), (event, from_user.key)
        assert event.get('sig'), event
        id = event['id']

        events = [event]
        # if this is a profile event, add a relays event
        if event['kind'] == KIND_PROFILE:
            events.append(id_and_sign({
                'kind': KIND_RELAYS,
                'pubkey': from_user.hex_pubkey(),
                'tags': [['r', to_cls.DEFAULT_TARGET]],
                'content': '',
            }, from_user.nsec()))

        logger.debug(f'connecting to {relay_url}')
        with connect(relay_url, open_timeout=util.HTTP_TIMEOUT,
                     close_timeout=util.HTTP_TIMEOUT) as websocket:
            try:
                for event in events:
                    msg = ['EVENT', event]
                    logger.debug(f'{websocket.remote_address} <= {event}')
                    websocket.send(json_dumps(msg))

                    resp = websocket.recv(timeout=util.HTTP_TIMEOUT)
                    logger.debug(f'{websocket.remote_address} => {resp}')

                    resp = json_loads(resp)
                    if resp[:3] != ['OK', event['id'], True]:
                        logger.warning('relay rejected event!')
                        return False

            except ConnectionClosedOK as cc:
                logger.warning(cc)
                return False

        if obj.type in STORE_AS1_TYPES:
            ndb.transactional()
            def add_copy():
                # read_consistency=ndb.STRONG shouldn't be necessary here, but oddly
                # it is, ndb seems to use cache inside txes even though it shouldn't
                # https://github.com/googleapis/python-ndb/issues/751
                # https://github.com/googleapis/python-ndb/issues/888 ?
                o = obj.key.get(read_consistency=ndb.STRONG) or obj
                o.remove_copies_on(to_cls)
                o.add('copies', Target(uri='nostr:' + id, protocol=to_cls.LABEL))
                o.put()

            add_copy()

        return True


@app.get('/.well-known/nostr.json')
@flask_util.headers(common.CACHE_CONTROL)
def nip_05():
    """NIP-05 endpoint that serves handles for users bridged into Nostr.

    https://nips.nostr.com/5

    Query params:
      name (str): should only contain a-z0-9-_.

    Returns a JSON object with:
      names: {<name>: <pubkey hex>}
      relays: optional, {<pubkey hex>: [relay urls]}
    """
    name = get_required_param('name')

    if (proto := Protocol.for_request()) and proto != Nostr:
        user = proto.query(OR(proto.handle == name,
                              proto.handle_as_domain == name,
                              proto.key == ndb.Key(proto, name),
                              )).get()
        if user and user.is_enabled(Nostr):
            if uri := user.get_copy(Nostr):
                id = uri.removeprefix('nostr:')
                return {
                    'names': {name: id},
                    'relays': {id: [Nostr.DEFAULT_TARGET]},
                }

    raise NotFound()


def normalize_relay_uri(uri):
    """Returns a normalized relay URI.

    Right now, just adds a trailing slash if the URI has no path, and removes the port
    if it's explicitly provided and redundant, ie ``:443`` for ``wss://`` or ``:80``
    for ``ws://``.

    https://github.com/nostr-protocol/nips/issues/1876
    https://github.com/nostr-protocol/nips/issues/1198

    Args:
        uri (str)

    Returns:
        str: normalized URI
    """
    if not uri or Nostr.is_blocklisted(uri):
        return None

    parsed = urlparse(uri)

    # remove redundant port
    if ((parsed.scheme == 'wss' and parsed.port == 443)
            or (parsed.scheme == 'ws' and parsed.port == 80)):
        netloc = parsed.hostname
    else:
        netloc = parsed.netloc

    # add trailing slash if no path
    path = parsed.path or '/'

    return urlunparse(parsed._replace(netloc=netloc, path=path))
