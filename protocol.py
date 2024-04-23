"""Base protocol class and common code."""
import copy
from datetime import timedelta
import logging
import re
from threading import Lock
from urllib.parse import urljoin

from cachetools import cached, LRUCache
from flask import g, request
from google.cloud import ndb
from google.cloud.ndb import OR
from google.cloud.ndb.model import _entity_to_protobuf
from granary import as1
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.flask_util import cloud_tasks_only
from oauth_dropins.webutil import models
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
import werkzeug.exceptions

import common
from common import (
    add,
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    DOMAINS,
    error,
    PROTOCOL_DOMAINS,
    subdomain_wrap,
)
from flask_app import app
from ids import translate_object_id, translate_user_id
from models import Follower, get_originals, Object, PROTOCOLS, Target, User

SUPPORTED_TYPES = (
    'accept',
    'article',
    'audio',
    'block',
    'comment',
    'delete',
    'follow',
    'image',
    'like',
    'note',
    'post',
    'share',
    'stop-following',
    'undo',
    'update',
    'video',
)

OBJECT_REFRESH_AGE = timedelta(days=30)

# activity ids that we've already handled and can now ignore.
# used in Protocol.receive
seen_ids = LRUCache(100000)
seen_ids_lock = Lock()

# objects that have been loaded in Protocol.load
objects_cache = LRUCache(5000)
objects_cache_lock = Lock()

logger = logging.getLogger(__name__)


class Protocol:
    """Base protocol class. Not to be instantiated; classmethods only.

    Attributes:
      LABEL (str): human-readable lower case name
      OTHER_LABELS (list of str): label aliases
      ABBREV (str): lower case abbreviation, used in URL paths
      PHRASE (str): human-readable name or phrase. Used in phrases like
        ``Follow this person on {PHRASE}``
      LOGO_HTML (str): logo emoji or ``<img>`` tag
      CONTENT_TYPE (str): MIME type of this protocol's native data format,
        appropriate for the ``Content-Type`` HTTP header.
      HAS_FOLLOW_ACCEPTS (bool): whether this protocol supports explicit
        accept/reject activities in response to follows, eg ActivityPub
      DEFAULT_ENABLED_PROTOCOLS (list of str): labels of other protocols that
        are automatically enabled for this protocol to bridge into
    """
    ABBREV = None
    PHRASE = None
    OTHER_LABELS = ()
    LOGO_HTML = ''
    CONTENT_TYPE = None
    HAS_FOLLOW_ACCEPTS = False
    DEFAULT_ENABLED_PROTOCOLS = ()

    def __init__(self):
        assert False

    @classmethod
    @property
    def LABEL(cls):
        return cls.__name__.lower()

    @staticmethod
    def for_request(fed=None):
        """Returns the protocol for the current request.

        ...based on the request's hostname.

        Args:
          fed (str or protocol.Protocol): protocol to return if the current
            request is on ``fed.brid.gy``

        Returns:
          Protocol: protocol, or None if the provided domain or request hostname
          domain is not a subdomain of ``brid.gy`` or isn't a known protocol
        """
        return Protocol.for_bridgy_subdomain(request.host, fed=fed)

    @staticmethod
    def for_bridgy_subdomain(domain_or_url, fed=None):
        """Returns the protocol for a brid.gy subdomain.

        Args:
          domain_or_url (str)
          fed (str or protocol.Protocol): protocol to return if the current
            request is on ``fed.brid.gy``

        Returns:
          class: :class:`Protocol` subclass, or None if the provided domain or request
          hostname domain is not a subdomain of ``brid.gy`` or isn't a known
          protocol
        """
        domain = (util.domain_from_link(domain_or_url, minimize=False)
                  if util.is_web(domain_or_url)
                  else domain_or_url)

        if domain == common.PRIMARY_DOMAIN or domain in common.LOCAL_DOMAINS:
            return PROTOCOLS[fed] if isinstance(fed, str) else fed
        elif domain and domain.endswith(common.SUPERDOMAIN):
            label = domain.removesuffix(common.SUPERDOMAIN)
            return PROTOCOLS.get(label)

    @classmethod
    def is_enabled_to(from_cls, to_cls, user=None):
        """Returns True if two protocols, and optionally a user, can be bridged.

        Reasons this might return False:
        * We haven't turned on bridging these two protocols yet.
        * The user is opted out.
        * The user is on a domain that's opted out.
        * The from protocol requires opt in, and the user hasn't opted in.

        Args:
          from_cls (Protocol subclass)
          to_cls (Protocol subclass)
          user (:class:`models.User` or str): optional, user or id

        Returns:
          bool:
        """
        if from_cls == to_cls:
            return True

        from_label = from_cls.LABEL
        to_label = to_cls.LABEL

        if DEBUG and (from_label in ('fake', 'other')
                      or (to_label in ('fake', 'other') and from_label != 'eefake')):
            return True

        user_id = None
        if isinstance(user, User):
            user_id = user.key.id() if user.key else None
        elif isinstance(user, str):
            user_id = user
            user = from_cls.get_by_id(user_id, allow_opt_out=True)

        if user:
            if user.status == 'opt-out':
                return False
            elif to_label in user.enabled_protocols:
                return True

        if to_label in from_cls.DEFAULT_ENABLED_PROTOCOLS:
            return True

        return False

    @classmethod
    def owns_id(cls, id):
        """Returns whether this protocol owns the id, or None if it's unclear.

        To be implemented by subclasses.

        IDs are string identities that uniquely identify users, and are intended
        primarily to be machine readable and usable. Compare to handles, which
        are human-chosen, human-meaningful, and often but not always unique.

        Some protocols' ids are more or less deterministic based on the id
        format, eg AT Protocol owns ``at://`` URIs. Others, like http(s) URLs,
        could be owned by eg Web or ActivityPub.

        This should be a quick guess without expensive side effects, eg no
        external HTTP fetches to fetch the id itself or otherwise perform
        discovery.

        Returns False if the id's domain is in :const:`common.DOMAIN_BLOCKLIST`.

        Args:
          id (str)

        Returns:
          bool or None:
        """
        return False

    @classmethod
    def owns_handle(cls, handle):
        """Returns whether this protocol owns the handle, or None if it's unclear.

        To be implemented by subclasses.

        Handles are string identities that are human-chosen, human-meaningful,
        and often but not always unique. Compare to IDs, which uniquely identify
        users, and are intended primarily to be machine readable and usable.

        Some protocols' handles are more or less deterministic based on the id
        format, eg ActivityPub (technically WebFinger) handles are
        ``@user@instance.com``. Others, like domains, could be owned by eg Web,
        ActivityPub, AT Protocol, or others.

        This should be a quick guess without expensive side effects, eg no
        external HTTP fetches to fetch the id itself or otherwise perform
        discovery.

        Args:
          handle (str)

        Returns:
          bool or None
        """
        return False

    @classmethod
    def handle_to_id(cls, handle):
        """Converts a handle to an id.

        To be implemented by subclasses.

        May incur network requests, eg DNS queries or HTTP requests.

        Args:
          handle (str)

        Returns:
          str: corresponding id, or None if the handle can't be found
        """
        raise NotImplementedError()

    @classmethod
    def key_for(cls, id):
        """Returns the :class:`google.cloud.ndb.Key` for a given id's :class:`models.User`.

        To be implemented by subclasses. Canonicalizes the id if necessary.

        If called via `Protocol.key_for`, infers the appropriate protocol with
        :meth:`for_id`. If called with a concrete subclass, uses that subclass
        as is.

        Returns:
          google.cloud.ndb.Key: matching key, or None if the given id is not a
          valid :class:`User` id for this protocol.
        """
        if cls == Protocol:
            proto = Protocol.for_id(id)
            return proto.key_for(id) if proto else None

        # load user so that we follow use_instead
        existing = cls.get_by_id(id, allow_opt_out=True)
        if existing:
            if existing.status == 'opt-out':
                return None
            return existing.key

        return cls(id=id).key

    @cached(LRUCache(20000), lock=Lock())
    @staticmethod
    def for_id(id, remote=True):
        """Returns the protocol for a given id.

        Args:
          id (str)
          remote (bool): whether to perform expensive side effects like fetching
            the id itself over the network, or other discovery.

        Returns:
          Protocol subclass: matching protocol, or None if no single known
          protocol definitively owns this id
        """
        logger.info(f'Determining protocol for id {id}')
        if not id:
            return None

        # step 1: check for our per-protocol subdomains
        if util.is_web(id):
            by_subdomain = Protocol.for_bridgy_subdomain(id)
            if by_subdomain:
                logger.info(f'  {by_subdomain.LABEL} owns id {id}')
                return by_subdomain

        # step 2: check if any Protocols say conclusively that they own it
        # sort to be deterministic
        protocols = sorted(set(p for p in PROTOCOLS.values() if p),
                           key=lambda p: p.LABEL)
        candidates = []
        for protocol in protocols:
            owns = protocol.owns_id(id)
            if owns:
                logger.info(f'  {protocol.LABEL} owns id {id}')
                return protocol
            elif owns is not False:
                candidates.append(protocol)

        if len(candidates) == 1:
            logger.info(f'  {candidates[0].LABEL} owns id {id}')
            return candidates[0]

        # step 3: look for existing Objects in the datastore
        obj = Protocol.load(id, remote=False)
        if obj and obj.source_protocol:
            logger.info(f'  {obj.key} owned by source_protocol {obj.source_protocol}')
            return PROTOCOLS[obj.source_protocol]

        # step 4: fetch over the network, if necessary
        if not remote:
            return None

        for protocol in candidates:
            logger.info(f'Trying {protocol.LABEL}')
            try:
                if protocol.load(id, local=False, remote=True):
                    logger.info(f'  {protocol.LABEL} owns id {id}')
                    return protocol
            except werkzeug.exceptions.BadGateway:
                # we tried and failed fetching the id over the network.
                # this depends on ActivityPub.fetch raising this!
                return None
            except werkzeug.exceptions.HTTPException as e:
                # internal error we generated ourselves; try next protocol
                pass
            except Exception as e:
                code, _ = util.interpret_http_exception(e)
                if code:
                    # we tried and failed fetching the id over the network
                    return None
                raise

        logger.info(f'No matching protocol found for {id} !')
        return None

    @staticmethod
    def for_handle(handle):
        """Returns the protocol for a given handle.

        May incur expensive side effects like resolving the handle itself over
        the network or other discovery.

        Args:
          handle (str)

        Returns:
          (Protocol subclass, str) tuple: matching protocol and optional id (if
          resolved), or ``(None, None)`` if no known protocol owns this handle
        """
        # TODO: normalize, eg convert domains to lower case
        logger.info(f'Determining protocol for handle {handle}')
        if not handle:
            return (None, None)

        # step 1: check if any Protocols say conclusively that they own it.
        # sort to be deterministic.
        protocols = sorted(set(p for p in PROTOCOLS.values() if p),
                           key=lambda p: p.LABEL)
        candidates = []
        for proto in protocols:
            owns = proto.owns_handle(handle)
            if owns:
                logger.info(f'  {proto.LABEL} owns handle {handle}')
                return (proto, None)
            elif owns is not False:
                candidates.append(proto)

        if len(candidates) == 1:
            logger.info(f'  {candidates[0].LABEL} owns handle {handle}')
            return (candidates[0], None)

        # step 2: look for matching User in the datastore
        for proto in candidates:
            user = proto.query(proto.handle == handle).get()
            if user:
                if user.status == 'opt-out':
                    return (None, None)
                logger.info(f'  user {user.key} owns handle {handle}')
                return (proto, user.key.id())

        # step 3: resolve handle to id
        for proto in candidates:
            id = proto.handle_to_id(handle)
            if id:
                logger.info(f'  {proto.LABEL} resolved handle {handle} to id {id}')
                return (proto, id)

        return (None, None)

    @classmethod
    def bridged_web_url_for(cls, user):
        """Returns the web URL for a user's bridged profile in this protocol.

        For example, for Web user ``alice.com``, :meth:`ATProto.bridged_web_url_for`
        returns ``https://bsky.app/profile/alice.com.web.brid.gy``

        Args:
          user (models.User)

        Returns:
          str, or None if there isn't a canonical URL
        """
        return None

    @classmethod
    def actor_key(cls, obj):
        """Returns the :class:`User`: key for a given object's author or actor.

        Args:
          obj (models.Object)

        Returns:
          google.cloud.ndb.key.Key or None:
        """
        owner = as1.get_owner(obj.as1)
        if owner:
            return cls.key_for(owner)

    @classmethod
    def create_for(cls, user):
        """Creates a copy user in this protocol.

        Should add the copy user to :attr:`copies`.

        Args:
          user (models.User): original source user. Shouldn't already have a
            copy user for this protocol in :attr:`copies`.
        """
        raise NotImplementedError()

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj=None):
        """Sends an outgoing activity.

        To be implemented by subclasses.

        Args:
          obj (models.Object): with activity to send
          url (str): destination URL to send to
          from_user (models.User): user (actor) this activity is from
          orig_obj (models.Object): the "original object" that this object
            refers to, eg replies to or reposts or likes

        Returns:
          bool: True if the activity is sent successfully, False if it is
          ignored or otherwise unsent due to protocol logic, eg no webmention
          endpoint, protocol doesn't support the activity type. (Failures are
          raised as exceptions.)

        Raises:
          werkzeug.HTTPException if the request fails
        """
        raise NotImplementedError()

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Fetches a protocol-specific object and populates it in an :class:`Object`.

        Errors are raised as exceptions. If this method returns False, the fetch
        didn't fail but didn't succeed either, eg the id isn't valid for this
        protocol, or the fetch didn't return valid data for this protocol.

        To be implemented by subclasses.

        Args:
          obj (models.Object): with the id to fetch. Data is filled into one of
            the protocol-specific properties, eg ``as2``, ``mf2``, ``bsky``.
          kwargs: subclass-specific

        Returns:
          bool: True if the object was fetched and populated successfully,
          False otherwise

        Raises:
          werkzeug.HTTPException: if the fetch fails
        """
        raise NotImplementedError()

    @classmethod
    def convert(cls, obj, from_user=None):
        """Converts an :class:`Object` to this protocol's data format.

        For example, an HTML string for :class:`Web`, or a dict with AS2 JSON
        and ``application/activity+json`` for :class:`ActivityPub`.

        To be implemented by subclasses. Implementations should generally call
        :meth:`Protocol.translate_ids` (as their own class) before converting to
        their format.

        Args:
          obj (models.Object):
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          converted object in the protocol's native format, often a dict
        """
        raise NotImplementedError()

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns an :class:`Object`'s delivery target (endpoint).

        To be implemented by subclasses.

        Examples:

        * If obj has ``source_protocol`` ``web``, returns its URL, as a
          webmention target.
        * If obj is an ``activitypub`` actor, returns its inbox.
        * If obj is an ``activitypub`` object, returns it's author's or actor's
          inbox.

        Args:
          obj (models.Object):
          shared (bool): optional. If True, returns a common/shared
            endpoint, eg ActivityPub's ``sharedInbox``, that can be reused for
            multiple recipients for efficiency

        Returns:
          str: target endpoint, or None if not available.
        """
        raise NotImplementedError()

    @classmethod
    def is_blocklisted(cls, url, allow_internal=False):
        """Returns True if we block the given URL and shouldn't deliver to it.

        Default implementation here, subclasses may override.

        Args:
          url (str):
          allow_internal (bool): whether to return False for internal domains
            like ``fed.brid.gy``, ``bsky.brid.gy``, etc

        Returns: bool:
        """
        blocklist = DOMAIN_BLOCKLIST
        if not allow_internal:
            blocklist += DOMAINS
        return util.domain_or_parent_in(util.domain_from_link(url), blocklist)

    @classmethod
    def translate_ids(to_cls, obj):
        """Translates all ids in an AS1 object to a specific protocol.

        Infers source protocol for each id value separately.

        For example, if ``proto`` is :class:`ActivityPub`, the ATProto URI
        ``at://did:plc:abc/coll/123`` will be converted to
        ``https://bsky.brid.gy/ap/at://did:plc:abc/coll/123``.

        Wraps these AS1 fields:

        * ``id``
        * ``actor``
        * ``author``
        * ``object``
        * ``object.actor``
        * ``object.author``
        * ``object.id``
        * ``object.inReplyTo``
        * ``tags.[objectType=mention].url``

        This is the inverse of :meth:`models.Object.resolve_ids`. Much of the
        same logic is duplicated there!

        TODO: unify with :meth:`Object.resolve_ids`,
        :meth:`models.Object.normalize_ids`.

        Args:
          to_proto (Protocol subclass)
          obj (dict): AS1 object or activity (not :class:`models.Object`!)

        Returns:
          dict: wrapped version of ``obj``
        """
        assert to_cls != Protocol
        if not obj:
            return obj

        outer_obj = copy.deepcopy(obj)
        inner_obj = outer_obj['object'] = as1.get_object(outer_obj)

        def translate(elem, field, fn):
            elem[field] = as1.get_object(elem, field)
            id = elem[field].get('id')
            if id and util.domain_from_link(id) not in DOMAINS:
                from_cls = Protocol.for_id(id)
                # TODO: what if from_cls is None? relax translate_object_id,
                # make it a noop if we don't know enough about from/to?
                if from_cls and from_cls != to_cls:
                    elem[field]['id'] = fn(id=id, from_=from_cls, to=to_cls)
            if elem[field].keys() == {'id'}:
                elem[field] = elem[field]['id']

        type = as1.object_type(outer_obj)
        translate(outer_obj, 'id',
                  translate_user_id if type in as1.ACTOR_TYPES
                  else translate_object_id)

        inner_is_actor = (as1.object_type(inner_obj) in as1.ACTOR_TYPES
                          or type in ('follow', 'stop-following'))
        translate(inner_obj, 'id',
                  translate_user_id if inner_is_actor else translate_object_id)

        for o in outer_obj, inner_obj:
            translate(o, 'inReplyTo', translate_object_id)
            for field in 'actor', 'author':
                translate(o, field, translate_user_id)
            for tag in as1.get_objects(o, 'tags'):
                if tag.get('objectType') == 'mention':
                    translate(tag, 'url', translate_user_id)

        outer_obj = util.trim_nulls(outer_obj)
        if outer_obj.get('object', {}).keys() == {'id'}:
            outer_obj['object'] = inner_obj['id']

        return outer_obj

    @classmethod
    def receive(from_cls, obj, authed_as=None, internal=False):
        """Handles an incoming activity.

        If ``obj``'s key is unset, ``obj.as1``'s id field is used. If both are
        unset, raises :class:`werkzeug.exceptions.BadRequest`.

        Args:
          obj (models.Object)
          authed_as (str): authenticated actor id who sent this activity
          internal (bool): whether to allow activity ids on internal domains

        Returns:
          (str, int) tuple: (response body, HTTP status code) Flask response

        Raises:
          werkzeug.HTTPException: if the request is invalid
        """
        # check some invariants
        assert from_cls != Protocol
        assert isinstance(obj, Object), obj
        logger.info(f'From {from_cls.LABEL}: {obj.key} AS1: {json_dumps(obj.as1, indent=2)}')

        if not obj.as1:
            error('No object data provided')

        id = None
        if obj.key and obj.key.id():
            id = obj.key.id()

        if not id:
            id = obj.as1.get('id')
            obj.key = ndb.Key(Object, id)

        if not id:
            error('No id provided')
        elif from_cls.is_blocklisted(id, allow_internal=internal):
            error(f'Activity {id} is blocklisted')

        # short circuit if we've already seen this activity id.
        # (don't do this for bare objects since we need to check further down
        # whether they've been updated since we saw them last.)
        if obj.as1.get('objectType') == 'activity' and 'force' not in request.values:
            with seen_ids_lock:
                already_seen = id in seen_ids
                seen_ids[id] = True

            if (already_seen
                    or (obj.new is False and obj.changed is False)
                    or (obj.new is None and obj.changed is None
                        and from_cls.load(id, remote=False))):
                msg = f'Already handled this activity {id}'
                logger.info(msg)
                return msg, 204

        # load actor user, check authorization
        actor = as1.get_owner(obj.as1)
        if not actor:
            error('Activity missing actor or author', status=400)

        if authed_as:
            assert isinstance(authed_as, str)
            if util.is_web(actor) and re.match(DOMAIN_RE, authed_as):
                authed_as = f'https://{authed_as}/'
            # TODO: handle domain vs URL for web users, eg
            # "actor https://tiffwhite.me/ isn't authed user tiffwhite.me"
            if actor != authed_as:
                logger.warning(f"actor {actor} isn't authed user {authed_as}")

        from_user = from_cls.get_or_create(id=actor)
        if not from_user:
            error(f'Actor {actor} is opted out', status=204)

        # update copy ids to originals
        obj.resolve_ids()

        # write Object to datastore
        orig = obj
        obj = Object.get_or_create(id, **orig.to_dict(), actor=actor)
        if orig.new is not None:
            obj.new = orig.new
        if orig.changed is not None:
            obj.changed = orig.changed

        # if this is a post, ie not an activity, wrap it in a create or update
        obj = from_cls.handle_bare_object(obj)
        obj.add('users', from_user.key)

        if obj.type not in SUPPORTED_TYPES:
            error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

        inner_obj_as1 = as1.get_object(obj.as1)
        if obj.as1.get('verb') in ('post', 'update', 'delete'):
            if inner_owner := as1.get_owner(inner_obj_as1):
                if inner_owner_key := from_cls.key_for(inner_owner):
                    obj.add('users', inner_owner_key)

        obj.source_protocol = from_cls.LABEL
        obj.put()

        # store inner object
        inner_obj_id = inner_obj_as1.get('id')
        if obj.type in ('post', 'update') and inner_obj_as1.keys() > set(['id']):
            Object.get_or_create(inner_obj_id, our_as1=inner_obj_as1,
                                 source_protocol=from_cls.LABEL, actor=actor)

        actor = as1.get_object(obj.as1, 'actor')
        actor_id = actor.get('id')

        # handle activity!

        # accept, eg in response to a follow. only send if the destination
        # supports accepts.
        if obj.type == 'accept':
            to_cls = Protocol.for_id(inner_obj_id)
            if not to_cls or not to_cls.HAS_FOLLOW_ACCEPTS:
                return 'OK'  # noop

        elif obj.type == 'stop-following':
            # TODO: unify with handle_follow?
            # TODO: handle multiple followees
            if not actor_id or not inner_obj_id:
                error(f'Undo of Follow requires actor id and object id. Got: {actor_id} {inner_obj_id} {obj.as1}')

            # deactivate Follower
            from_ = from_cls.key_for(actor_id)
            to_cls = Protocol.for_id(inner_obj_id)
            to = to_cls.key_for(inner_obj_id)
            follower = Follower.query(Follower.to == to,
                                      Follower.from_ == from_,
                                      Follower.status == 'active').get()
            if follower:
                logger.info(f'Marking {follower} inactive')
                follower.status = 'inactive'
                follower.put()
            else:
                logger.warning(f'No Follower found for {from_} => {to}')

            # fall through to deliver to followee
            # TODO: do we convert stop-following to webmention 410 of original
            # follow?

        elif obj.type in ('update', 'like', 'share'):  # require object
            if not inner_obj_id:
                error("Couldn't find id of object to update")

            # fall through to deliver to followers

        elif obj.type == 'delete':
            if not inner_obj_id:
                error("Couldn't find id of object to delete")

            logger.info(f'Marking Object {inner_obj_id} deleted')
            Object.get_or_create(inner_obj_id, deleted=True)

            # if this is an actor, deactivate its followers/followings
            # https://github.com/snarfed/bridgy-fed/issues/63
            deleted_user = from_cls.key_for(id=inner_obj_id)
            if deleted_user:
                logger.info(f'Deactivating Followers from or to = {inner_obj_id}')
                followers = Follower.query(OR(Follower.to == deleted_user,
                                              Follower.from_ == deleted_user)
                                           ).fetch()
                for f in followers:
                    f.status = 'inactive'
                ndb.put_multi(followers)

            # fall through to deliver to followers

        elif obj.type == 'block':
            proto = Protocol.for_bridgy_subdomain(inner_obj_id)
            if not proto:
                logger.info("Ignoring block, target isn't one of our protocol domains")
                return 'OK', 200

            from_user.disable_protocol(proto)
            return 'OK', 200

        elif obj.type == 'post':
            to_cc = (as1.get_ids(inner_obj_as1, 'to')
                     + as1.get_ids(inner_obj_as1, 'cc'))
            content = inner_obj_as1.get('content', '').strip().lower()
            if len(to_cc) == 1:
                logger.info(f'got DM to {to_cc}: {content}')
                proto = Protocol.for_bridgy_subdomain(to_cc[0])
                if proto:
                    if content in ('yes', 'ok'):
                        from_user.enable_protocol(proto)
                    elif content == 'no':
                        from_user.disable_protocol(proto)
                    return 'OK', 200

        # fetch actor if necessary
        if actor and actor.keys() == set(['id']):
            logger.info('Fetching actor so we have name, profile photo, etc')
            actor_obj = from_cls.load(actor['id'])
            if actor_obj and actor_obj.as1:
                obj.our_as1 = {**obj.as1, 'actor': actor_obj.as1}

        # fetch object if necessary so we can render it in feeds
        if (obj.type == 'share'
                and inner_obj_as1.keys() == set(['id'])
                and from_cls.owns_id(inner_obj_id)):
            logger.info('Fetching object so we can render it in feeds')
            inner_obj = from_cls.load(inner_obj_id)
            if inner_obj and inner_obj.as1:
                obj.our_as1 = {
                    **obj.as1,
                    'object': {
                        **inner_obj_as1,
                        **inner_obj.as1,
                    }
                }

        if obj.type == 'follow':
            proto = Protocol.for_bridgy_subdomain(inner_obj_id)
            if proto:
                # follow of one of our protocol users; enable that protocol.
                # foll through so that we send an accept.
                from_user.enable_protocol(proto)

            from_cls.handle_follow(obj)

        # deliver to targets
        return from_cls.deliver(obj, from_user=from_user)

    @classmethod
    def handle_follow(from_cls, obj):
        """Handles an incoming follow activity.

        Sends an ``Accept`` back, but doesn't send the ``Follow`` itself. That
        happens in :meth:`deliver`.

        Args:
          obj (models.Object): follow activity
        """
        logger.info('Got follow. Loading users, storing Follow(s), sending accept(s)')

        # Prepare follower (from) users' data
        from_as1 = as1.get_object(obj.as1, 'actor')
        from_id = from_as1.get('id')
        if not from_id:
            error(f'Follow activity requires actor. Got: {obj.as1}')

        from_obj = from_cls.load(from_id)
        if not from_obj:
            error(f"Couldn't load {from_id}")

        if not from_obj.as1:
            from_obj.our_as1 = from_as1
            from_obj.put()

        from_key = from_cls.key_for(from_id)
        if not from_key:
            error(f'Invalid {from_cls} user key: {from_id}')
        obj.users = [from_key]
        from_user = from_cls.get_or_create(id=from_key.id(), obj=from_obj)

        # Prepare followee (to) users' data
        to_as1s = as1.get_objects(obj.as1)
        if not to_as1s:
            error(f'Follow activity requires object(s). Got: {obj.as1}')

        # Store Followers
        for to_as1 in to_as1s:
            to_id = to_as1.get('id')
            if not to_id:
                error(f'Follow activity requires object(s). Got: {obj.as1}')

            logger.info(f'Follow {from_id} => {to_id}')

            to_cls = Protocol.for_id(to_id)
            if not to_cls:
                error(f"Couldn't determine protocol for {to_id}")
            elif from_cls == to_cls and from_cls.LABEL != 'fake':
                logger.info(f'Skipping same-protocol Follower {from_id} => {to_id}')
                continue

            to_obj = to_cls.load(to_id)
            if to_obj and not to_obj.as1:
                to_obj.our_as1 = to_as1
                to_obj.put()

            to_key = to_cls.key_for(to_id)
            if not to_key:
                logger.info(f'Skipping invalid {from_cls} user key: {from_id}')
                continue

            # If followee user is already direct, follower may not know they're
            # interacting with a bridge. if followee user is indirect though,
            # follower should know, so they're direct.
            to_user = to_cls.get_or_create(id=to_key.id(), obj=to_obj, direct=False)
            follower_obj = Follower.get_or_create(to=to_user, from_=from_user,
                                                  follow=obj.key, status='active')
            obj.add('notify', to_key)
            from_cls.maybe_accept_follow(follower=from_user, followee=to_user,
                                         follow=obj)

    @classmethod
    def maybe_accept_follow(_, follower, followee, follow):
        """Sends an accept activity for a follow.

        ...if the follower protocol handles accepts. Otherwise, does nothing.

        Args:
          follower: :class:`models.User`
          followee: :class:`models.User`
          follow: :class:`models.Object`
        """
        if followee.HAS_FOLLOW_ACCEPTS:
            return

        # send accept. note that this is one accept for the whole
        # follow, even if it has multiple followees!
        id = f'{followee.key.id()}/followers#accept-{follow.key.id()}'
        accept = Object.get_or_create(id, our_as1={
            'id': id,
            'objectType': 'activity',
            'verb': 'accept',
            'actor': followee.key.id(),
            'object': follow.as1,
        })

        from_target = follower.target_for(follower.obj)
        if not from_target:
            error(f"Couldn't find delivery target for follower {follower}")

        sent = follower.send(accept, from_target, from_user=followee)
        if sent:
            accept.populate(
                delivered=[Target(protocol=follower.LABEL, uri=from_target)],
                status='complete',
            )
            accept.put()

    @classmethod
    def handle_bare_object(cls, obj):
        """If obj is a bare object, wraps it in a create or update activity.

        Checks if we've seen it before.

        Args:
          obj (models.Object)

        Returns:
          models.Object: ``obj`` if it's an activity, otherwise a new object
        """
        if obj.type not in set(('note', 'article', 'comment')) | as1.ACTOR_TYPES:
            return obj

        obj_actor = as1.get_owner(obj.as1)
        now = util.now().isoformat()

        # this is a raw post; wrap it in a create or update activity
        if obj.changed:
            logger.info(f'Content has changed from last time at {obj.updated}! Redelivering to all inboxes')
            id = f'{obj.key.id()}#bridgy-fed-update-{now}'
            update_as1 = {
                'objectType': 'activity',
                'verb': 'update',
                'id': id,
                'actor': obj_actor,
                'object': {
                    # Mastodon requires the updated field for Updates, so
                    # add a default value.
                    # https://docs.joinmastodon.org/spec/activitypub/#supported-activities-for-statuses
                    # https://socialhub.activitypub.rocks/t/what-could-be-the-reason-that-my-update-activity-does-not-work/2893/4
                    # https://github.com/mastodon/documentation/pull/1150
                    'updated': now,
                    **obj.as1,
                },
            }
            logger.info(f'Wrapping in update: {json_dumps(update_as1, indent=2)}')
            return Object(id=id, our_as1=update_as1,
                          source_protocol=obj.source_protocol)

        create_id = f'{obj.key.id()}#bridgy-fed-create'
        create = cls.load(create_id, remote=False)
        if (obj.new or not create or create.status != 'complete'
                # HACK: force query param here is specific to webmention
                or 'force' in request.form):
            if create:
                logger.info(f'Existing create {create.key} status {create.status}')
            else:
                logger.info(f'No existing create activity')
            create_as1 = {
                'objectType': 'activity',
                'verb': 'post',
                'id': create_id,
                'actor': obj_actor,
                'object': obj.as1,
                'published': now,
            }
            logger.info(f'Wrapping in post: {json_dumps(create_as1, indent=2)}')
            return Object.get_or_create(create_id, our_as1=create_as1,
                                        source_protocol=obj.source_protocol)

        error(f'{obj.key.id()} is unchanged, nothing to do', status=204)

    @classmethod
    def deliver(from_cls, obj, from_user):
        """Delivers an activity to its external recipients.

        Args:
          obj (models.Object): activity to deliver
          from_user (models.User): user (actor) this activity is from
        """
        # find delivery targets
        targets = from_cls.targets(obj)  # maps Target to Object or None

        if not targets:
            obj.status = 'ignored'
            obj.put()
            error(r'No targets, nothing to do ¯\_(ツ)_/¯', status=204)

        # sort targets so order is deterministic for tests, debugging, etc
        sorted_targets = sorted(targets.items(), key=lambda t: t[0].uri)
        obj.populate(
            status='in progress',
            delivered=[],
            failed=[],
            undelivered=[t for t, _ in sorted_targets],
        )
        obj.put()
        logger.info(f'Delivering to: {obj.undelivered}')

        # enqueue send task for each targets
        user = from_user.key.urlsafe()
        for i, (target, orig_obj) in enumerate(sorted_targets):
            orig_obj = orig_obj.key.urlsafe() if orig_obj else ''
            common.create_task(queue='send', obj=obj.key.urlsafe(),
                               url=target.uri, protocol=target.protocol,
                               orig_obj=orig_obj, user=user)

        return 'OK', 202

    @classmethod
    def targets(cls, obj):
        """Collects the targets to send a :class:`models.Object` to.

        Targets are both objects - original posts, events, etc - and actors.

        Args:
          obj (models.Object)

        Returns:
          dict: maps :class:`models.Target` to original (in response to)
          :class:`models.Object`, if any, otherwise None
        """
        logger.info('Finding recipients and their targets')

        target_uris = sorted(set(as1.targets(obj.as1)))
        logger.info(f'Raw targets: {target_uris}')
        orig_obj = None
        targets = {}  # maps Target to Object or None
        owner = as1.get_owner(obj.as1)

        in_reply_to_owners = []
        in_reply_tos = as1.get_ids(as1.get_object(obj.as1), 'inReplyTo')
        for in_reply_to in in_reply_tos:
            if protocol := Protocol.for_id(in_reply_to):
                if in_reply_to_obj := protocol.load(in_reply_to):
                    if reply_owner := as1.get_owner(in_reply_to_obj.as1):
                        in_reply_to_owners.append(reply_owner)
        is_self_reply = False

        for id in sorted(target_uris):
            protocol = Protocol.for_id(id)
            if not protocol:
                logger.info(f"Can't determine protocol for {id}")
                continue
            elif protocol.is_blocklisted(id):
                logger.info(f'{id} is blocklisted')
                continue

            orig_obj = protocol.load(id)
            if not orig_obj or not orig_obj.as1:
                logger.info(f"Couldn't load {id}")
                continue

            # deliver self-replies to followers
            # https://github.com/snarfed/bridgy-fed/issues/639
            if owner == as1.get_owner(orig_obj.as1):
                is_self_reply = True
                logger.info(f'Looks like a self reply! Delivering to all followers')

            if protocol == cls and cls.LABEL != 'fake':
                logger.info(f'Skipping same-protocol target {id}')
                continue
            elif id in in_reply_to_owners:
                logger.info(f'Skipping mention of in-reply-to author')
                continue

            target = protocol.target_for(orig_obj)
            if not target:
                # TODO: surface errors like this somehow?
                logger.error(f"Can't find delivery target for {id}")
                continue

            logger.info(f'Target for {id} is {target}')
            targets[Target(protocol=protocol.LABEL, uri=target)] = orig_obj
            orig_user = protocol.actor_key(orig_obj)
            if orig_user:
                logger.info(f'Recipient is {orig_user}')
                obj.add('notify', orig_user)

        logger.info(f'Direct targets: {targets.keys()}')

        # deliver to followers, if appropriate
        user_key = cls.actor_key(obj)
        if not user_key:
            logger.info("Can't tell who this is from! Skipping followers.")
            return targets

        is_reply = obj.type == 'comment' or in_reply_tos
        if (obj.type in ('post', 'update', 'delete', 'share')
                and (is_self_reply or not is_reply)):
            logger.info(f'Delivering to followers of {user_key}')
            followers = Follower.query(Follower.to == user_key,
                                       Follower.status == 'active'
                                       ).fetch()
            users = [u for u in ndb.get_multi(f.from_ for f in followers) if u]
            User.load_multi(users)

            # which object should we add to followers' feeds, if any
            feed_obj = None
            if obj.type == 'share':
                feed_obj = obj
            else:
                inner = as1.get_object(obj.as1)
                # don't add profile updates to feeds
                if not (obj.type == 'update'
                        and inner.get('objectType') in as1.ACTOR_TYPES):
                    inner_id = inner.get('id')
                    if inner_id:
                        feed_obj = cls.load(inner_id)

            for user in users:
                if feed_obj:
                    feed_obj.add('feed', user.key)

                # TODO: should we pass remote=False through here to Protocol.load?
                target = user.target_for(user.obj, shared=True) if user.obj else None
                if not target:
                    # TODO: surface errors like this somehow?
                    logger.error(f'Follower {user.key} has no delivery target')
                    continue

                # normalize URL (lower case hostname, etc)
                target = util.dedupe_urls([target])[0]

                # HACK: use last target object from above for reposts, which
                # has its resolved id
                targets[Target(protocol=user.LABEL, uri=target)] = \
                    orig_obj if obj.as1.get('verb')  == 'share' else None

            if feed_obj:
                feed_obj.put()

        # de-dupe targets, discard same-domain
        candidates = {t.uri: (t, obj) for t, obj in targets.items()}
        targets = {}
        source_domains = [
            util.domain_from_link(url) for url in
            (obj.as1.get('id'), obj.as1.get('url'), as1.get_owner(obj.as1))
            if util.is_web(url)
        ]
        for url in sorted(util.dedupe_urls(candidates.keys())):
            if util.is_web(url) and util.domain_from_link(url) in source_domains:
                logger.info(f'Skipping same-domain target {url}')
            else:
                target, obj = candidates[url]
                targets[target] = obj

        return targets

    @classmethod
    def load(cls, id, remote=None, local=True, **kwargs):
        """Loads and returns an Object from memory cache, datastore, or HTTP fetch.

        Sets the :attr:`new` and :attr:`changed` attributes if we know either
        one for the loaded object, ie local is True and remote is True or None.

        Note that :meth:`Object._post_put_hook` updates the cache.

        Args:
          id (str)
          remote (bool): whether to fetch the object over the network. If True,
            fetches even if we already have the object stored, and updates our
            stored copy. If False and we don't have the object stored, returns
            None. Default (None) means to fetch over the network only if we
            don't already have it stored.
          local (bool): whether to load from the datastore before
            fetching over the network. If False, still stores back to the
            datastore after a successful remote fetch.
          kwargs: passed through to :meth:`fetch()`

        Returns:
          models.Object: loaded object, or None if it isn't fetchable, eg a
          non-URL string for Web, or ``remote`` is False and it isn't in the
          cache or datastore

        Raises:
          requests.HTTPError: anything that :meth:`fetch` raises
        """
        assert id
        assert local or remote is not False
        # logger.debug(f'Loading Object {id} local={local} remote={remote}')

        obj = orig_as1 = None
        with objects_cache_lock:
            cached = objects_cache.get(id)
            if cached:
                # make a copy so that if the client modifies this entity in
                # memory, those modifications aren't applied to the cache
                # until they explicitly put() the modified entity.
                # NOTE: keep in sync with Object._post_put_hook!
                # logger.debug('  got from cache')
                obj = Object(id=cached.key.id(), **cached.to_dict(
                    # computed properties
                    exclude=['as1', 'expire', 'object_ids', 'type']))

        if local and not obj:
            obj = Object.get_by_id(id)
            if not obj:
                # logger.debug(f' not in datastore')
                pass
            elif obj.as1 or obj.raw or obj.deleted:
                # logger.debug('  got from datastore')
                obj.new = False
                if remote is not True:
                    with objects_cache_lock:
                        objects_cache[id] = obj

        if remote is False:
            return obj
        elif remote is None and obj:
            if obj.updated < util.as_utc(util.now() - OBJECT_REFRESH_AGE):
                # logger.debug(f'  last updated {obj.updated}, refreshing')
                pass
            else:
                return obj

        if obj:
            orig_as1 = obj.as1
            obj.clear()
            obj.new = False
        else:
            obj = Object(id=id)
            if local:
                # logger.debug('  not in datastore')
                obj.new = True
                obj.changed = False

        fetched = cls.fetch(obj, **kwargs)
        if not fetched:
            return None

        # https://stackoverflow.com/a/3042250/186123
        size = len(_entity_to_protobuf(obj)._pb.SerializeToString())
        if size > models.MAX_ENTITY_SIZE:
            logger.warning(f'Object is too big! {size} bytes is over {models.MAX_ENTITY_SIZE}')
            return None

        obj.resolve_ids()
        obj.normalize_ids()

        if obj.new is False:
            obj.changed = obj.activity_changed(orig_as1)

        if obj.source_protocol not in (cls.LABEL, cls.ABBREV):
            if obj.source_protocol:
                logger.warning(f'Object {obj.key.id()} changed protocol from {obj.source_protocol} to {cls.LABEL} ?!')
            obj.source_protocol = cls.LABEL
            obj.put()

        with objects_cache_lock:
            objects_cache[id] = obj
        return obj


@app.post('/queue/receive')
@cloud_tasks_only
def receive_task():
    """Task handler for a newly received :class:`models.Object`.

    Calls :meth:`Protocol.receive` with the form parameters.

    Parameters:
      obj (url-safe google.cloud.ndb.key.Key): :class:`models.Object` to handle
      authed_as (str): passed to :meth:`Protocol.receive`

    TODO: migrate incoming webmentions and AP inbox deliveries to this. The
    difficulty is that parts of :meth:`protocol.Protocol.receive` depend on
    setup in :func:`web.webmention` and :func:`activitypub.inbox`, eg
    :class:`models.Object` with ``new`` and ``changed``, HTTP request details,
    etc. See stash for attempt at this for :class:`web.Web`.
    """
    form = request.form.to_dict()
    logger.info(f'Params: {list(form.items())}')

    obj = ndb.Key(urlsafe=form['obj']).get()
    assert obj
    obj.new = True

    authed_as = form.get('authed_as')

    try:
        return PROTOCOLS[obj.source_protocol].receive(obj=obj, authed_as=authed_as)
    except ValueError as e:
        logger.warning(e, exc_info=True)
        error(e, status=304)


@app.post('/queue/send')
@cloud_tasks_only
def send_task():
    """Task handler for sending an activity to a single specific destination.

    Calls :meth:`Protocol.send` with the form parameters.

    Parameters:
      protocol (str): :class:`Protocol` to send to
      url (str): destination URL to send to
      obj (url-safe google.cloud.ndb.key.Key): :class:`models.Object` to send
      orig_obj (url-safe google.cloud.ndb.key.Key): optional "original object"
        :class:`models.Object` that this object refers to, eg replies to or
        reposts or likes
      user (url-safe google.cloud.ndb.key.Key): :class:`models.User` (actor)
        this activity is from
    """
    form = request.form.to_dict()
    logger.info(f'Params: {list(form.items())}')

    # prepare
    url = form['url']
    protocol = form['protocol']
    target = Target(uri=url, protocol=protocol)

    obj = ndb.Key(urlsafe=form['obj']).get()
    logger.info(f'Sending {obj.key.id()} AS1: {json_dumps(obj.as1, indent=2)}')

    if (target not in obj.undelivered and target not in obj.failed
            and 'force' not in request.values):
        logger.info(f"{url} not in {obj.key.id()} undelivered or failed, giving up")
        return r'¯\_(ツ)_/¯', 204

    user = None
    if user_key := form.get('user'):
        user = ndb.Key(urlsafe=user_key).get()
    orig_obj = (ndb.Key(urlsafe=form['orig_obj']).get()
                if form.get('orig_obj') else None)

    # send
    sent = None
    try:
        sent = PROTOCOLS[protocol].send(obj, url, from_user=user, orig_obj=orig_obj)
    except BaseException as e:
        code, body = util.interpret_http_exception(e)
        if not code and not body:
            logger.info(str(e), exc_info=True)

    if sent is False:
        logger.info(f'Failed sending {obj.key.id()} to {url}')

    # write results to Object
    @ndb.transactional()
    def update_object(obj_key):
        obj = obj_key.get()
        if target in obj.undelivered:
            obj.remove('undelivered', target)

        if sent is None:
            obj.add('failed', target)
        else:
            if target in obj.failed:
                obj.remove('failed', target)
            if sent:
                obj.add('delivered', target)

        if not obj.undelivered:
            obj.status = ('complete' if obj.delivered
                          else 'failed' if obj.failed
                          else 'ignored')
        obj.put()

    update_object(obj.key)

    return '', 200 if sent else 304
