"""Datastore model classes."""
from datetime import timedelta, timezone
import itertools
import json
import logging
import random
from threading import Lock
from urllib.parse import quote, urlparse

from arroba.datastore_storage import AtpRemoteBlob
from arroba.util import parse_at_uri
from Crypto.PublicKey import RSA
from flask import g, request
from google.cloud import ndb
from granary import as1, as2, bluesky, microformats2
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.models import (
    ComputedJsonProperty,
    JsonProperty,
    StringIdModel,
)
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from common import add, base64_to_long, long_to_base64, redirect_unwrap
import ids

# maps string label to Protocol subclass. populated by ProtocolUserMeta.
# seed with old and upcoming protocols that don't have their own classes (yet).
PROTOCOLS = {'ostatus': None}

# 2048 bits makes tests slow, so use 1024 for them
KEY_BITS = 1024 if DEBUG else 2048
PAGE_SIZE = 20

# auto delete old objects of these types via the Object.expire property
# https://cloud.google.com/datastore/docs/ttl
OBJECT_EXPIRE_TYPES = (
    'post',
    'update',
    'delete',
    'accept',
    'reject',
    'undo',
    None,
)
OBJECT_EXPIRE_AGE = timedelta(days=90)

logger = logging.getLogger(__name__)


class Target(ndb.Model):
    """:class:`protocol.Protocol` + URI pairs for identifying objects.

    These are currently used for:

    * delivery destinations, eg ActivityPub inboxes, webmention targets, etc.
    * copies of :class:`Object`\s and :class:`User`\s elsewhere,
      eg ``at://`` URIs for ATProto records, nevent etc bech32-encoded Nostr ids,
      ATProto user DIDs, etc.

    Used in :class:`google.cloud.ndb.model.StructuredProperty`\s inside
    :class:`Object` and :class:`User`\;
    not stored as top-level entities in the datastore.

    ndb implements this by hoisting each property here into a corresponding
    property on the parent entity, prefixed by the StructuredProperty name
    below, eg ``delivered.uri``, ``delivered.protocol``, etc.

    For repeated StructuredPropertys, the hoisted properties are all repeated on
    the parent entity, and reconstructed into StructuredPropertys based on their
    order.

    https://googleapis.dev/python/python-ndb/latest/model.html#google.cloud.ndb.model.StructuredProperty
    """
    uri = ndb.StringProperty(required=True)
    # choices is populated in app via reset_protocol_properties, after all User
    # subclasses are created, so that PROTOCOLS is fully populated
    protocol = ndb.StringProperty(choices=[], required=True)

    def __eq__(self, other):
        """Equality excludes Targets' :class:`Key`."""
        return self.uri == other.uri and self.protocol == other.protocol

    def __hash__(self):
        """Allow hashing so these can be dict keys."""
        return hash((self.protocol, self.uri))


class ProtocolUserMeta(type(ndb.Model)):
    """:class:`User` metaclass. Registers all subclasses in the ``PROTOCOLS`` global."""
    def __new__(meta, name, bases, class_dict):
        cls = super().__new__(meta, name, bases, class_dict)

        if hasattr(cls, 'LABEL') and cls.LABEL not in ('protocol', 'user'):
            for label in (cls.LABEL, cls.ABBREV) + cls.OTHER_LABELS:
                if label:
                    PROTOCOLS[label] = cls

        return cls


def reset_protocol_properties():
    """Recreates various protocol properties to include choices from ``PROTOCOLS``."""
    Target.protocol = ndb.StringProperty(
        'protocol', choices=list(PROTOCOLS.keys()), required=True)
    Object.source_protocol = ndb.StringProperty(
        'source_protocol', choices=list(PROTOCOLS.keys()))


def _validate_atproto_did(prop, val):
    if not val.startswith('did:plc:'):
        raise ValueError(f'Expected did:plc, got {val}')
    return val


class User(StringIdModel, metaclass=ProtocolUserMeta):
    """Abstract base class for a Bridgy Fed user.

    Stores some protocols' keypairs. Currently:

    * RSA keypair for ActivityPub HTTP Signatures
      properties: ``mod``, ``public_exponent``, ``private_exponent``, all
      encoded as base64url (ie URL-safe base64) strings as described in RFC
      4648 and section 5.1 of the Magic Signatures spec:
      https://tools.ietf.org/html/draft-cavage-http-signatures-12
    * *Not* K-256 signing or rotation keys for AT Protocol, those are stored in
      :class:`arroba.datastore_storage.AtpRepo` entities
    """
    obj_key = ndb.KeyProperty(kind='Object')  # user profile
    mod = ndb.StringProperty()
    use_instead = ndb.KeyProperty()
    atproto_did = ndb.StringProperty(validator=_validate_atproto_did)

    # Proxy copies of this user elsewhere, eg DIDs for ATProto records, bech32
    # npub Nostr ids, etc. Similar to rel-me links in microformats2, alsoKnownAs
    # in DID docs (and now AS2), etc.
    copies = ndb.StructuredProperty(Target, repeated=True)

    # whether this user signed up or otherwise explicitly, deliberately
    # interacted with Bridgy Fed. For example, if fediverse user @a@b.com looks
    # up @foo.com@fed.brid.gy via WebFinger, we'll create Users for both,
    # @a@b.com will be direct, foo.com will not.
    direct = ndb.BooleanProperty(default=False)

    # these are for ActivityPub HTTP Signatures
    public_exponent = ndb.StringProperty()
    private_exponent = ndb.StringProperty()

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    # OLD. some stored entities still have this; do not reuse.
    # actor_as2 = JsonProperty()

    def __init__(self, **kwargs):
        """Constructor.

        Sets :attr:`obj` explicitly because however
        :class:`google.cloud.ndb.model.Model` sets it doesn't work with
        ``@property`` and ``@obj.setter`` below.
        """
        obj = kwargs.pop('obj', None)
        super().__init__(**kwargs)

        if obj:
            self.obj = obj

    @classmethod
    def new(cls, **kwargs):
        """Try to prevent instantiation. Use subclasses instead."""
        raise NotImplementedError()

    def _post_put_hook(self, future):
        logger.info(f'Wrote {self.key}')

    @classmethod
    def get_by_id(cls, id):
        """Override :meth:`google.cloud.ndb.model.Model.get_by_id` to follow the
        ``use_instead`` property.
        """
        user = cls._get_by_id(id)
        if user and user.use_instead:
            logger.info(f'{user.key} use_instead => {user.use_instead}')
            return user.use_instead.get()

        return user

    @staticmethod
    def get_for_copy(copy_id):
        """Fetches a user with a given id in copies.

        Thin wrapper around :meth:`User.get_copies` that returns the first
        matching :class:`User`.
        """
        users = User.get_for_copies([copy_id])
        if users:
            return users[0]

    @staticmethod
    def get_for_copies(copy_ids):
        """Fetches users (across all protocols) for a given set of copies.

        Args:
          copy_ids (sequence of str)

        Returns:
          sequence of :class:`User` subclass instances
        """
        assert copy_ids
        return list(itertools.chain(*(
            cls.query(cls.copies.uri.IN(copy_ids))
            for cls in set(PROTOCOLS.values()) if cls)))

        # TODO: default to looking up copy_ids as key ids, across protocols? is
        # that useful anywhere?

    @classmethod
    @ndb.transactional()
    def get_or_create(cls, id, propagate=False, **kwargs):
        """Loads and returns a :class:`User`\. Creates it if necessary.

        Args:
          propagate (bool): whether to create copies of this user in push-based
            protocols, eg ATProto and Nostr.
        """
        assert cls != User
        user = cls.get_by_id(id)
        if user:
            # override direct from False => True if set
            # TODO: propagate more props into user?
            direct = kwargs.get('direct')
            if direct and not user.direct:
                logger.info(f'Setting {user.key} direct={direct}')
                user.direct = direct
                user.put()
            if not propagate:
                return user
        else:
            user = cls(id=id, **kwargs)

        if propagate:
            # force refresh user profile
            user.obj = cls.load(user.profile_id(), remote=True)

        if propagate and cls.LABEL != 'atproto' and not user.atproto_did:
            PROTOCOLS['atproto'].create_for(user)

        # generate keys for all protocols _except_ our own
        #
        # these can use urandom() and do nontrivial math, so they can take time
        # depending on the amount of randomness available and compute needed.
        if cls.LABEL != 'activitypub':
            key = RSA.generate(KEY_BITS, randfunc=random.randbytes if DEBUG else None)
            user.mod = long_to_base64(key.n)
            user.public_exponent = long_to_base64(key.e)
            user.private_exponent = long_to_base64(key.d)

        try:
            user.put()
        except AssertionError as e:
            error(f'Bad {cls.__name__} id {id} : {e}')

        logger.info(f'Created new {user}')
        return user

    @property
    def obj(self):
        """Convenience accessor that loads :attr:`obj_key` from the datastore."""
        if self.obj_key:
            if not hasattr(self, '_obj'):
                self._obj = self.obj_key.get()
            return self._obj

    @obj.setter
    def obj(self, obj):
        if obj:
            assert isinstance(obj, Object)
            assert obj.key
            self._obj = obj
            self.obj_key = obj.key
        else:
            self._obj = self.obj_key = None

    @classmethod
    def load_multi(cls, users):
        """Loads :attr:`obj` for multiple users in parallel.

        Args:
          users (sequence of User)
        """
        objs = ndb.get_multi(u.obj_key for u in users if u.obj_key)
        keys_to_objs = {o.key: o for o in objs if o}

        for u in users:
            u._obj = keys_to_objs.get(u.obj_key)

    def as2(self):
        """Returns this user as an AS2 actor."""
        return self.obj.as_as2() if self.obj else {}

    @ndb.ComputedProperty
    def handle(self):
        """This user's unique, human-chosen handle, eg ``@me@snarfed.org``.

        To be implemented by subclasses.
        """
        raise NotImplementedError()

    @ndb.ComputedProperty
    def readable_id(self):
        """DEPRECATED: replaced by handle. Kept for backward compatibility."""
        return None

    def handle_as(self, to_proto):
        """Returns this user's handle in a different protocol.

        Args:
          to_proto (str or Protocol)

        Returns:
          str
        """
        if isinstance(to_proto, str):
            to_proto = PROTOCOLS[to_proto]

        return ids.convert_handle(handle=self.handle, from_proto=self.__class__,
                                  to_proto=to_proto)

    def id_as(self, to_proto):
        """Returns this user's id in a different protocol.

        Args:
          to_proto (str or Protocol)

        Returns:
          str
        """
        if isinstance(to_proto, str):
            to_proto = PROTOCOLS[to_proto]

        return ids.convert_id(id=self.key.id(), from_proto=self.__class__,
                                  to_proto=to_proto)

    def handle_or_id(self):
        """Returns handle if we know it, otherwise id."""
        return self.handle or self.key.id()

    def public_pem(self):
        """
        Returns:
          bytes:
        """
        rsa = RSA.construct((base64_to_long(str(self.mod)),
                             base64_to_long(str(self.public_exponent))))
        return rsa.exportKey(format='PEM')

    def private_pem(self):
        """
        Returns:
          bytes:
        """
        assert self.mod and self.public_exponent and self.private_exponent, str(self)
        rsa = RSA.construct((base64_to_long(str(self.mod)),
                             base64_to_long(str(self.public_exponent)),
                             base64_to_long(str(self.private_exponent))))
        return rsa.exportKey(format='PEM')

    def name(self):
        """Returns this user's human-readable name, eg ``Ryan Barrett``."""
        if self.obj and self.obj.as1:
            name = self.obj.as1.get('displayName')
            if name:
                return name

        return self.handle_or_id()

    def web_url(self):
        """Returns this user's web URL (homepage), eg ``https://foo.com/``.

        To be implemented by subclasses.

        Returns:
          str
        """
        raise NotImplementedError()

    def is_web_url(self, url):
        """Returns True if the given URL is this user's web URL (homepage).

        Args:
          url (str)

        Returns:
          bool:
        """
        if not url:
            return False

        url = url.strip().rstrip('/')
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https', ''):
            return False

        this = self.web_url().rstrip('/')
        parsed_this = urlparse(this)

        return (url == this or url == parsed_this.netloc or
                parsed_url[1:] == parsed_this[1:])  # ignore http vs https

    def ap_address(self):
        """Returns this user's ActivityPub address, eg ``@me@foo.com``.

        Returns:
          str:
        """
        # TODO: use self.handle_as? need it to fall back to id?
        return f'@{self.handle_or_id()}@{self.ABBREV}{common.SUPERDOMAIN}'

    def ap_actor(self, rest=None):
        """Returns this user's ActivityPub/AS2 actor id.

        Eg ``https://atproto.brid.gy/ap/foo.com``.

        May be overridden by subclasses.

        Args:
          rest (str): optional, appended to URL path

        Returns:
          str
        """
        # must match the URL route for activitypub.actor()
        url = self.subdomain_url(f'/ap/{self.key.id()}')
        if rest:
            url += f'/{rest.lstrip("/")}'
        return url

    def profile_id(self):
        """Returns the id of this user's profile object in its native protocol.

        Examples:

        * Web: home page URL, eg ``https://me.com/``
        * ActivityPub: actor URL, eg ``https://instance.com/users/me``
        * ATProto: profile AT URI, eg ``at://did:plc:123/app.bsky.actor.profile/self``

        Defaults to this user's key id.

        Returns:
          str:
        """
        return self.key.id()

    def user_page_path(self, rest=None):
        """Returns the user's Bridgy Fed user page path."""
        path = f'/{self.ABBREV}/{self.handle_or_id()}'

        if rest:
            if not rest.startswith('?'):
                path += '/'
            path += rest

        return path

    def user_page_link(self):
        """Returns a pretty user page link with the user's name and profile picture."""
        actor = self.obj.as1 if self.obj and self.obj.as1 else {}
        img = util.get_url(actor, 'image') or ''
        return f'<a class="h-card u-author" href="{self.user_page_path()}"><img src="{img}" class="profile"> {self.name()}</a>'


class Object(StringIdModel):
    """An activity or other object, eg actor.

    Key name is the id. We synthesize ids if necessary.
    """
    STATUSES = ('new', 'in progress', 'complete', 'failed', 'ignored')
    LABELS = ('activity',
              # DEPRECATED, replaced by users, notify, feed
              'feed', 'notification', 'user')

    # Keys for user(s) who created or otherwise own this activity.
    #
    # DEPRECATED: this used to include all users related the activity, including
    # followers, but we've now moved those to the notify and feed properties.
    users = ndb.KeyProperty(repeated=True)
    # User keys who should see this activity in their user page, eg in reply to,
    # reaction to, share of, etc.
    notify = ndb.KeyProperty(repeated=True)
    # User keys who should see this activity in their feeds, eg followers of its
    # creator
    feed = ndb.KeyProperty(repeated=True)

    # DEPRECATED but still used read only to maintain backward compatibility
    # with old Objects in the datastore that we haven't bothered migrating.
    domains = ndb.StringProperty(repeated=True)

    status = ndb.StringProperty(choices=STATUSES)
    # choices is populated in app, after all User subclasses are created,
    # so that PROTOCOLS is fully populated
    # TODO: remove? is this redundant with the protocol-specific data fields below?
    source_protocol = ndb.StringProperty(choices=[])
    labels = ndb.StringProperty(repeated=True, choices=LABELS)

    # TODO: switch back to ndb.JsonProperty if/when they fix it for the web console
    # https://github.com/googleapis/python-ndb/issues/874
    as2 = JsonProperty()      # only one of the rest will be populated...
    bsky = JsonProperty()     # Bluesky / AT Protocol
    mf2 = JsonProperty()      # HTML microformats2 item (ie _not_ the top level
                              # parse object with items inside an 'items' field)
    our_as1 = JsonProperty()  # AS1 for activities that we generate or modify ourselves
    raw = JsonProperty()      # other standalone data format, eg DID document

    deleted = ndb.BooleanProperty()

    delivered = ndb.StructuredProperty(Target, repeated=True)
    undelivered = ndb.StructuredProperty(Target, repeated=True)
    failed = ndb.StructuredProperty(Target, repeated=True)

    # Copies of this object elsewhere, eg at:// URIs for ATProto records and
    # nevent etc bech32-encoded Nostr ids, where this object is the original.
    # Similar to u-syndication links in microformats2 and
    # upstream/downstreamDuplicates in AS1.
    copies = ndb.StructuredProperty(Target, repeated=True)

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    new = None
    changed = None
    """Protocol and subclasses set these in fetch if this :class:`Object` is
    new or if its contents have changed from what was originally loaded from the
    datastore. If either one is None, that means we don't know whether this
    :class:`Object` is new/changed.

    :attr:`changed` is populated by :meth:`activity_changed()`.
    """

    lock = None
    """Initialized in __init__, synchronizes property access, :meth:`put`s, etc."""

    @ComputedJsonProperty
    def as1(self):
        # TODO: bring back log or assert? we have prod entities that currently
        # fail this though.
        # assert (self.as2 is not None) ^ (self.bsky is not None) ^ (self.mf2 is not None), \
        #     f'{self.as2} {self.bsky} {self.mf2}'
        # if bool(self.as2) + bool(self.bsky) + bool(self.mf2) > 1:
        #     logger.warning(f'{self.key} has multiple! {bool(self.as2)} {bool(self.bsky)} {bool(self.mf2)}')

        owner = None

        if self.our_as1:
            obj = redirect_unwrap(self.our_as1)

        elif self.as2:
            obj = as2.to_as1(redirect_unwrap(self.as2))

        elif self.bsky:
            owner, _, _ = parse_at_uri(self.key.id())
            ATProto = PROTOCOLS['atproto']
            handle = ATProto(id=owner).handle
            obj = bluesky.to_as1(self.bsky, repo_did=owner, repo_handle=handle,
                                 pds=ATProto.target_for(self))

        elif self.mf2:
            obj = microformats2.json_to_object(self.mf2,
                                               rel_urls=self.mf2.get('rel-urls'))
            # postprocess: if no id, use url
            if url := util.get_url(obj):
                obj.setdefault('id', url)
            for field in 'author', 'actor', 'object':  # None is obj itself
                if url := util.get_url(obj, field):
                    as1.get_object(obj, field).setdefault('id', url)

        else:
            return None

        # populate id if necessary
        if self.key:
            obj.setdefault('id', self.key.id())

        # populate actor/author if necessary and available
        type = obj.get('objectType')
        owner_field = ('actor' if type == 'activity'
                       else 'author' if type not in as1.ACTOR_TYPES
                       else None)
        if owner_field and owner:
            logger.info(f'Replacing {owner_field} {obj.get(owner_field)}...')

            # load matching user, if any
            user = User.get_for_copy(owner)
            if user:
                if user.obj and user.obj.as1:
                    obj[owner_field] = {
                        **user.obj.as1,
                        'id': user.key.id(),
                    }
                else:
                    obj[owner_field] = user.key.id()
            else:
                obj[owner_field] = owner

            logger.info(f'  with {obj[owner_field]}')

        return obj

    @ndb.ComputedProperty
    def type(self):  # AS1 objectType, or verb if it's an activity
        if self.as1:
            return as1.object_type(self.as1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = Lock()

    def _object_ids(self):  # id(s) of inner objects
        if self.as1:
            return redirect_unwrap(as1.get_ids(self.as1, 'object'))

    object_ids = ndb.ComputedProperty(_object_ids, repeated=True)

    def _expire(self):
        """Maybe automatically delete this Object after 90d using a TTL policy.

        https://cloud.google.com/datastore/docs/ttl

        They recommend not indexing TTL properties:
        https://cloud.google.com/datastore/docs/ttl#ttl_properties_and_indexes
        """
        if self.type in OBJECT_EXPIRE_TYPES:
            return (self.updated or util.now()) + OBJECT_EXPIRE_AGE

    expire = ndb.ComputedProperty(_expire, indexed=False)

    def _pre_put_hook(self):
        assert '^^' not in self.key.id()

        if self.key.id().startswith('at://'):
            repo, _, _ = parse_at_uri(self.key.id())
            if not repo.startswith('did:'):
                # TODO: if we hit this, that means the AppView gave us an AT URI
                # with a handle repo/authority instead of DID. that's surprising!
                # ...if so, and if we need to handle it, add a new
                # arroba.did.canonicalize_at_uri() function, then use it here,
                # or before.
                raise ValueError(
                    f'at:// URI ids must have DID repos; got {self.key.id()}')

        if self.as1 and self.as1.get('objectType') == 'activity':
            # can't self.add because we're inside self.put, which has the lock
            add(self.labels, 'activity')
        elif 'activity' in self.labels:
            # ditto
            self.labels.remove('activity')

    def _post_put_hook(self, future):
        """Update :meth:`Protocol.load` cache."""
        # TODO: assert that as1 id is same as key id? in pre put hook?

        # log, pruning data fields
        props = util.trim_nulls({
            **self.to_dict(),
            'new': self.new,
            'changed': self.changed,
        })
        for prop in 'as2', 'bsky', 'mf2', 'our_as1', 'raw':
            if props.get(prop):
                props[prop] = "..."
        for prop in 'created', 'updated', 'as1', 'expire':
            props.pop(prop, None)

        logger.info(f'Wrote {self.key} {props}')

        if '#' not in self.key.id():
            import protocol  # TODO: actually fix this circular import
            # make a copy so that if we later modify this object in memory,
            # those modifications don't affect the cache.
            # NOTE: keep in sync with Protocol.load!
            protocol.objects_cache[self.key.id()] = Object(
                id=self.key.id(),
                # exclude computed properties
                **self.to_dict(exclude=['as1', 'expire', 'object_ids', 'type']))

    @classmethod
    def get_by_id(cls, id):
        """Override :meth:`google.cloud.ndb.model.Model.get_by_id` to un-escape
        ``^^`` to ``#``.

        Only needed for compatibility with historical URL paths, we're now back
        to URL-encoding ``#``\s instead.
        https://github.com/snarfed/bridgy-fed/issues/469
        See :meth:`proxy_url` for the inverse.
        """
        return super().get_by_id(id.replace('^^', '#'))

    @classmethod
    @ndb.transactional()
    def get_or_create(cls, id, **props):
        """Returns an :class:`Object` with the given property values.

        If a matching :class:`Object` doesn't exist in the datastore, creates it
        first. Only populates non-False/empty property values in props into the
        object. Also populates the :attr:`new` and :attr:`changed` properties.

        Returns:
          Object:
        """
        obj = cls.get_by_id(id)
        if obj:
            obj.new = False
            orig_as1 = obj.as1
        else:
            obj = Object(id=id)
            obj.new = True

        if set(props.keys()) & set(('our_as1', 'as2', 'mf2', 'bsky', 'raw')):
            obj.clear()
        obj.populate(**{
            k: v for k, v in props.items()
            if v and not isinstance(getattr(Object, k), ndb.ComputedProperty)
        })
        if not obj.new:
            obj.changed = obj.activity_changed(orig_as1)

        obj.put()
        return obj

    def put(self, **kwargs):
        """Stores this object. Uses ``self.lock``.
        """
        with self.lock:
            return super().put(**kwargs)

    def add(self, prop, val):
        """Adds a value to a multiply-valued property. Uses ``self.lock``.

        Args:
          prop (str)
          val
        """
        with self.lock:
            add(getattr(self, prop), val)

    def remove(self, prop, val):
        """Removes a value from a multiply-valued property. Uses ``self.lock``.

        Args:
          prop (str)
          val
        """
        with self.lock:
            getattr(self, prop).remove(val)

    def clear(self):
        """Clears all data properties."""
        for prop in 'our_as1', 'as2', 'bsky', 'mf2', 'raw':
            val = getattr(self, prop, None)
            # TODO: delete entirely?
            # if val:
            #     logger.warning(f'Wiping out existing {prop}: {json_dumps(val, indent=2)}')
            with self.lock:
                setattr(self, prop, None)

    def as_as2(self):
        """Returns this object as an AS2 dict."""
        return self.as2 or as2.from_as1(self.as1) or {}

    def as_bsky(self, fetch_blobs=False):
        """Returns this object as a Bluesky record.

        Args:
          fetch_blobs (bool): whether to fetch images and other blobs, store
            them in :class:`arroba.datastore_storage.AtpRemoteBlob`\s if they
            don't already exist, and fill them into the returned object.
        """
        if self.bsky:
            return self.bsky

        elif self.as1:
            blobs = {}  # maps str URL to dict blob object
            if fetch_blobs:
                for obj in self.as1, as1.get_object(self.as1):
                    for url in util.get_urls(self.as1, 'image'):
                        if url not in blobs:
                            blob = AtpRemoteBlob.get_or_create(
                                url=url, get_fn=util.requests_get)
                            blobs[url] = blob.as_object()

            return bluesky.from_as1(self.as1, blobs=blobs)

        return {}

    def activity_changed(self, other_as1):
        """Returns True if this activity is meaningfully changed from ``other_as1``.

        ...otherwise False.

        Used to populate :attr:`changed`.

        Args:
          other_as1 (dict): AS1 object, or none
        """
        return (as1.activity_changed(self.as1, other_as1)
                if self.as1 and other_as1
                else bool(self.as1) != bool(other_as1))

    def proxy_url(self):
        """Returns the Bridgy Fed proxy URL to render this post as HTML.

        Note that some webmention receivers are struggling with the ``%23``\s
        (URL-encoded ``#``\s) in these paths:

        * https://github.com/snarfed/bridgy-fed/issues/469
        * https://github.com/pfefferle/wordpress-webmention/issues/359

        See :meth:`get_by_id()` for the inverse.
        """
        # TODO: fix this circular import
        from protocol import Protocol

        id = quote(self.key.id(), safe=':/')
        if not self.source_protocol:
            logger.warning(f'!!! No source_protocol for {id} !!!')
        protocol = PROTOCOLS.get(self.source_protocol) or Protocol
        return protocol.subdomain_url(f'convert/web/{id}')

    def actor_link(self):
        """Returns a pretty actor link with their name and profile picture."""
        attrs = {'class': 'h-card u-author'}

        if (self.source_protocol in ('web', 'webmention', 'ui') and g.user
                and (g.user.key in self.users or g.user.key.id() in self.domains)):
            # outbound; show a nice link to the user
            return g.user.user_page_link()

        actor = {}
        if self.as1:
            actor = (util.get_first(self.as1, 'actor')
                     or util.get_first(self.as1, 'author')
                     or {})
        if isinstance(actor, str):
            return common.pretty_link(actor, attrs=attrs)

        url = util.get_first(actor, 'url') or ''
        name = actor.get('displayName') or actor.get('username') or ''
        image = util.get_url(actor, 'image')
        if not image:
            return common.pretty_link(url, text=name, attrs=attrs)

        return f"""\
        <a class="h-card u-author" href="{url}" title="{name}">
          <img class="profile" src="{image}" />
          {util.ellipsize(name, chars=40)}
        </a>"""


class Follower(ndb.Model):
    """A follower of a Bridgy Fed user."""
    STATUSES = ('active', 'inactive')

    # these are both subclasses of User
    from_ = ndb.KeyProperty(name='from', required=True)
    to = ndb.KeyProperty(required=True)

    follow = ndb.KeyProperty(Object)  # last follow activity
    status = ndb.StringProperty(choices=STATUSES, default='active')

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    # OLD. some stored entities still have these; do not reuse.
    # src = ndb.StringProperty()
    # dest = ndb.StringProperty()
    # last_follow = JsonProperty()

    def _pre_put_hook(self):
        if self.from_.kind() == 'Fake' and self.to.kind() == 'Fake':
            return

        # we're a bridge! stick with bridging.
        assert self.from_.kind() != self.to.kind(), f'from {self.from_} to {self.to}'

    def _post_put_hook(self, future):
        # log, pruning data fields
        props = util.trim_nulls(self.to_dict())
        if props.get('follow'):
            props['follow'] = "..."
        for prop in 'created', 'updated':
            props.pop(prop, None)

        logger.info(f'Wrote {self.key} {props}')

    @classmethod
    @ndb.transactional()
    def get_or_create(cls, *, from_, to, **kwargs):
        """Returns a Follower with the given ``from_`` and ``to`` users.

        If a matching :class:`Follower` doesn't exist in the datastore, creates
        it first.

        Args:
          from_ (User)
          to (User)

        Returns:
          Follower:
        """
        assert from_
        assert to

        follower = Follower.query(Follower.from_ == from_.key,
                                  Follower.to == to.key,
                                  ).get()
        if not follower:
            follower = Follower(from_=from_.key, to=to.key, **kwargs)
            follower.put()
        elif kwargs:
            # update existing entity with new property values, eg to make an
            # inactive Follower active again
            for prop, val in kwargs.items():
                setattr(follower, prop, val)
            follower.put()

        return follower

    @staticmethod
    def fetch_page(collection):
        """Fetches a page of Followers for the current user.

        Wraps :func:`fetch_page`. Paging uses the ``before`` and ``after`` query
        parameters, if available in the request.

        Args:
          collection (str): ``followers`` or ``following``

        Returns:
          (list of Follower, str, str) tuple: results, annotated with an extra
          ``user`` attribute that holds the follower or following :class:`User`,
          and new str query param values for ``before`` and ``after`` to fetch
          the previous and next pages, respectively
        """
        assert collection in ('followers', 'following'), collection

        filter_prop = Follower.to if collection == 'followers' else Follower.from_
        query = Follower.query(
            Follower.status == 'active',
            filter_prop == g.user.key,
        ).order(-Follower.updated)

        followers, before, after = fetch_page(query, Follower)
        users = ndb.get_multi(f.from_ if collection == 'followers' else f.to
                              for f in followers)
        User.load_multi(u for u in users if u)

        for f, u in zip(followers, users):
            f.user = u

        return followers, before, after


def fetch_page(query, model_class):
    """Fetches a page of results from a datastore query.

    Uses the ``before`` and ``after`` query params (if provided; should be
    ISO8601 timestamps) and the queried model class's ``updated`` property to
    identify the page to fetch.

    Populates a ``log_url_path`` property on each result entity that points to a
    its most recent logged request.

    Args:
      query (google.cloud.ndb.query.Query)
      model_class (class)

    Returns:
      (list of Object or Follower, str, str) tuple: (results, new_before,
      new_after), where new_before and new_after are query param values for
      ``before`` and ``after`` to fetch the previous and next pages,
      respectively
    """
    # if there's a paging param ('before' or 'after'), update query with it
    # TODO: unify this with Bridgy's user page
    def get_paging_param(param):
        val = request.values.get(param)
        if val:
            try:
                dt = util.parse_iso8601(val.replace(' ', '+'))
            except BaseException as e:
                error(f"Couldn't parse {param}, {val!r} as ISO8601: {e}")
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt

    before = get_paging_param('before')
    after = get_paging_param('after')
    if before and after:
        error("can't handle both before and after")
    elif after:
        query = query.filter(model_class.updated >= after).order(model_class.updated)
    elif before:
        query = query.filter(model_class.updated < before).order(-model_class.updated)
    else:
        query = query.order(-model_class.updated)

    query_iter = query.iter()
    results = sorted(itertools.islice(query_iter, 0, PAGE_SIZE),
                     key=lambda r: r.updated, reverse=True)

    # calculate new paging param(s)
    has_next = results and query_iter.probably_has_next()
    new_after = (
        before if before
        else results[0].updated if has_next and after
        else None)
    if new_after:
        new_after = new_after.isoformat()

    new_before = (
        after if after else
        results[-1].updated if has_next
        else None)
    if new_before:
        new_before = new_before.isoformat()

    return results, new_before, new_after
