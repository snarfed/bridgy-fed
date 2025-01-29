"""Base protocol class and common code."""
import copy
from datetime import datetime, timedelta, timezone
import logging
import os
import re
from threading import Lock
from urllib.parse import urljoin, urlparse

from cachetools import cached, LRUCache
from flask import request
from google.cloud import ndb
from google.cloud.ndb import OR
from google.cloud.ndb.model import _entity_to_protobuf
from granary import as1, as2
from granary.source import html_to_text
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.flask_util import cloud_tasks_only
from oauth_dropins.webutil import models
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
from requests import RequestException
import werkzeug.exceptions
from werkzeug.exceptions import BadGateway, HTTPException

import common
from common import (
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    report_error,
    subdomain_wrap,
)
import dms
import ids
from ids import (
    BOT_ACTOR_AP_IDS,
    normalize_user_id,
    translate_object_id,
    translate_user_id,
)
import memcache
from models import (
    DM,
    Follower,
    Object,
    PROTOCOLS,
    PROTOCOLS_BY_KIND,
    Target,
    User,
)

OBJECT_REFRESH_AGE = timedelta(days=30)
DELETE_TASK_DELAY = timedelta(minutes=2)
CREATE_MAX_AGE = timedelta(weeks=2)

# require a follow for users on these domains before we deliver anything from
# them other than their profile
LIMITED_DOMAINS = (os.getenv('LIMITED_DOMAINS', '').split()
                   or util.load_file_lines('limited_domains'))

DONT_STORE_AS1_TYPES = as1.CRUD_VERBS | set((
    'accept',
    'reject',
    'stop-following',
    'undo',
))
STORE_AS1_TYPES = (as1.ACTOR_TYPES | as1.POST_TYPES | as1.VERBS_WITH_OBJECT
                   - DONT_STORE_AS1_TYPES)

logger = logging.getLogger(__name__)


def error(*args, status=299, **kwargs):
    """Default HTTP status code to 299 to prevent retrying task."""
    return common.error(*args, status=status, **kwargs)


class ErrorButDoNotRetryTask(HTTPException):
    code = 299
    description = 'ErrorButDoNotRetryTask'

# https://github.com/pallets/flask/issues/1837#issuecomment-304996942
werkzeug.exceptions.default_exceptions.setdefault(299, ErrorButDoNotRetryTask)
werkzeug.exceptions._aborter.mapping.setdefault(299, ErrorButDoNotRetryTask)


def activity_id_memcache_key(id):
    return memcache.key(f'receive-{id}')


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
      HAS_COPIES (bool): whether this protocol is push and needs us to
        proactively create "copy" users and objects, as opposed to pulling
        converted objects on demand
      REQUIRES_AVATAR (bool): whether accounts on this protocol are required
        to have a profile picture. If they don't, their ``User.status`` will be
        ``blocked``.
      REQUIRES_NAME (bool): whether accounts on this protocol are required to
        have a profile name that's different than their handle or id. If they
        don't, their ``User.status`` will be ``blocked``.
      REQUIRES_OLD_ACCOUNT: (bool): whether accounts on this protocol are
        required to be at least :const:`common.OLD_ACCOUNT_AGE` old. If their
        profile includes creation date and it's not old enough, their
        ``User.status`` will be ``blocked``.
      DEFAULT_ENABLED_PROTOCOLS (sequence of str): labels of other protocols
        that are automatically enabled for this protocol to bridge into
      DEFAULT_SERVE_USER_PAGES (bool): whether to serve user pages for all of
        this protocol's users on the fed.brid.gy. If ``False``, user pages will
        only be served for users who have explictly opted in.
      SUPPORTED_AS1_TYPES (sequence of str): AS1 objectTypes and verbs that this
        protocol supports receiving and sending.
      SUPPORTS_DMS (bool): whether this protocol can receive DMs (chat messages)

    """
    ABBREV = None
    PHRASE = None
    OTHER_LABELS = ()
    LOGO_HTML = ''
    CONTENT_TYPE = None
    HAS_COPIES = False
    REQUIRES_AVATAR = False
    REQUIRES_NAME = False
    REQUIRES_OLD_ACCOUNT = False
    DEFAULT_ENABLED_PROTOCOLS = ()
    DEFAULT_SERVE_USER_PAGES = False
    SUPPORTED_AS1_TYPES = ()
    SUPPORTS_DMS = False

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
    def owns_handle(cls, handle, allow_internal=False):
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
          allow_internal (bool): whether to return False for internal domains
            like ``fed.brid.gy``, ``bsky.brid.gy``, etc

        Returns:
          bool or None
        """
        return False

    @classmethod
    def handle_to_id(cls, handle):
        """Converts a handle to an id.

        To be implemented by subclasses.

        May incur network requests, eg DNS queries or HTTP requests. Avoids
        blocked or opted out users.

        Args:
          handle (str)

        Returns:
          str: corresponding id, or None if the handle can't be found
        """
        raise NotImplementedError()

    @classmethod
    def key_for(cls, id, allow_opt_out=False):
        """Returns the :class:`google.cloud.ndb.Key` for a given id's :class:`models.User`.

        To be implemented by subclasses. Canonicalizes the id if necessary.

        If called via `Protocol.key_for`, infers the appropriate protocol with
        :meth:`for_id`. If called with a concrete subclass, uses that subclass
        as is.

        Args:
          id (str):
          allow_opt_out (bool): whether to allow users who are currently opted out

        Returns:
          google.cloud.ndb.Key: matching key, or None if the given id is not a
          valid :class:`User` id for this protocol.
        """
        if cls == Protocol:
            proto = Protocol.for_id(id)
            return proto.key_for(id, allow_opt_out=allow_opt_out) if proto else None

        # load user so that we follow use_instead
        existing = cls.get_by_id(id, allow_opt_out=True)
        if existing:
            if existing.status and not allow_opt_out:
                return None
            return existing.key

        return cls(id=id).key

    @staticmethod
    def _for_id_memcache_key(id, remote=None):
        """If id is a URL, uses its domain, otherwise returns None.

        Args:
          id (str)

        Returns:
          (str domain, bool remote) or None
        """
        if remote and util.is_web(id):
            return util.domain_from_link(id)

    @cached(LRUCache(20000), lock=Lock())
    @memcache.memoize(key=_for_id_memcache_key, write=lambda id, remote: remote,
                      version=3)
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
        logger.debug(f'Determining protocol for id {id}')
        if not id:
            return None

        # remove our synthetic id fragment, if any
        #
        # will this eventually cause false positives for other services that
        # include our full ids inside their own ids, non-URL-encoded? guess
        # we'll figure that out if/when it happens.
        id = id.partition('#bridgy-fed-')[0]

        if util.is_web(id):
            # step 1: check for our per-protocol subdomains
            try:
                is_homepage = urlparse(id).path.strip('/') == ''
            except ValueError as e:
                logger.info(f'urlparse ValueError: {e}')
                return None

            by_subdomain = Protocol.for_bridgy_subdomain(id)
            if by_subdomain and not is_homepage and id not in BOT_ACTOR_AP_IDS:
                logger.debug(f'  {by_subdomain.LABEL} owns id {id}')
                return by_subdomain

        # step 2: check if any Protocols say conclusively that they own it
        # sort to be deterministic
        protocols = sorted(set(p for p in PROTOCOLS.values() if p),
                           key=lambda p: p.LABEL)
        candidates = []
        for protocol in protocols:
            owns = protocol.owns_id(id)
            if owns:
                logger.debug(f'  {protocol.LABEL} owns id {id}')
                return protocol
            elif owns is not False:
                candidates.append(protocol)

        if len(candidates) == 1:
            logger.debug(f'  {candidates[0].LABEL} owns id {id}')
            return candidates[0]

        # step 3: look for existing Objects in the datastore
        obj = Protocol.load(id, remote=False)
        if obj and obj.source_protocol:
            logger.debug(f'  {obj.key.id()} owned by source_protocol {obj.source_protocol}')
            return PROTOCOLS[obj.source_protocol]

        # step 4: fetch over the network, if necessary
        if not remote:
            return None

        for protocol in candidates:
            logger.debug(f'Trying {protocol.LABEL}')
            try:
                obj = protocol.load(id, local=False, remote=True)

                if protocol.ABBREV == 'web':
                    # for web, if we fetch and get HTML without microformats,
                    # load returns False but the object will be stored in the
                    # datastore with source_protocol web, and in cache. load it
                    # again manually to check for that.
                    obj = Object.get_by_id(id)
                    if obj and obj.source_protocol != 'web':
                        obj = None

                if obj:
                    logger.debug(f'  {protocol.LABEL} owns id {id}')
                    return protocol
            except BadGateway:
                # we tried and failed fetching the id over the network.
                # this depends on ActivityPub.fetch raising this!
                return None
            except HTTPException as e:
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

    @cached(LRUCache(20000), lock=Lock())
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
        logger.debug(f'Determining protocol for handle {handle}')
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
                logger.debug(f'  {proto.LABEL} owns handle {handle}')
                return (proto, None)
            elif owns is not False:
                candidates.append(proto)

        if len(candidates) == 1:
            logger.debug(f'  {candidates[0].LABEL} owns handle {handle}')
            return (candidates[0], None)

        # step 2: look for matching User in the datastore
        for proto in candidates:
            user = proto.query(proto.handle == handle).get()
            if user:
                if user.status:
                    return (None, None)
                logger.debug(f'  user {user.key} handle {handle}')
                return (proto, user.key.id())

        # step 3: resolve handle to id
        for proto in candidates:
            id = proto.handle_to_id(handle)
            if id:
                logger.debug(f'  {proto.LABEL} resolved handle {handle} to id {id}')
                return (proto, id)

        logger.info(f'No matching protocol found for handle {handle} !')
        return (None, None)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        """Returns the web URL for a user's bridged profile in this protocol.

        For example, for Web user ``alice.com``, :meth:`ATProto.bridged_web_url_for`
        returns ``https://bsky.app/profile/alice.com.web.brid.gy``

        Args:
          user (models.User)
          fallback (bool): if True, and bridged users have no canonical user
            profile URL in this protocol, return the native protocol's profile URL

        Returns:
          str, or None if there isn't a canonical URL
        """
        if fallback:
            return user.web_url()

    @classmethod
    def actor_key(cls, obj, allow_opt_out=False):
        """Returns the :class:`User`: key for a given object's author or actor.

        Args:
          obj (models.Object)
          allow_opt_out (bool): whether to return a user key if they're opted out

        Returns:
          google.cloud.ndb.key.Key or None:
        """
        owner = as1.get_owner(obj.as1)
        if owner:
            return cls.key_for(owner, allow_opt_out=allow_opt_out)

    @classmethod
    def bot_user_id(cls):
        """Returns the Web user id for the bot user for this protocol.

        For example, ``'bsky.brid.gy'`` for ATProto.

        Returns:
          str:
        """
        return f'{cls.ABBREV}{common.SUPERDOMAIN}'

    @classmethod
    def create_for(cls, user):
        """Creates or re-activate a copy user in this protocol.

        Should add the copy user to :attr:`copies`.

        If the copy user already exists and active, should do nothing.

        Args:
          user (models.User): original source user. Shouldn't already have a
            copy user for this protocol in :attr:`copies`.

        Raises:
          ValueError: if we can't create a copy of the given user in this protocol
        """
        raise NotImplementedError()

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj_id=None):
        """Sends an outgoing activity.

        To be implemented by subclasses.

        NOTE: if this protocol's ``HAS_COPIES`` is True, and this method creates
        a copy and sends it, it *must* add that copy to the *object*'s (not
        activity's) :attr:`copies`!

        Args:
          obj (models.Object): with activity to send
          url (str): destination URL to send to
          from_user (models.User): user (actor) this activity is from
          orig_obj_id (str): :class:`models.Object` key id of the "original object"
            that this object refers to, eg replies to or reposts or likes

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
          requests.RequestException or werkzeug.HTTPException: if the fetch fails
        """
        raise NotImplementedError()

    @classmethod
    def convert(cls, obj, from_user=None, **kwargs):
        """Converts an :class:`Object` to this protocol's data format.

        For example, an HTML string for :class:`Web`, or a dict with AS2 JSON
        and ``application/activity+json`` for :class:`ActivityPub`.

        Just passes through to :meth:`_convert`, then does minor
        protocol-independent postprocessing.

        Args:
          obj (models.Object):
          from_user (models.User): user (actor) this activity/object is from
          kwargs: protocol-specific, passed through to :meth:`_convert`

        Returns:
          converted object in the protocol's native format, often a dict
        """
        if not obj or not obj.as1:
            return {}

        id = obj.key.id() if obj.key else obj.as1.get('id')
        is_activity = obj.as1.get('verb') in ('post', 'update')
        base_obj = as1.get_object(obj.as1) if is_activity else obj.as1
        orig_our_as1 = obj.our_as1

        # mark bridged actors as bots and add "bridged by Bridgy Fed" to their bios
        if (from_user and base_obj
            and base_obj.get('objectType') in as1.ACTOR_TYPES
            and PROTOCOLS.get(obj.source_protocol) != cls
            and Protocol.for_bridgy_subdomain(id) not in DOMAINS
            # Web users are special cased, they don't get the label if they've
            # explicitly enabled Bridgy Fed with redirects or webmentions
            and not (from_user.LABEL == 'web'
                     and (from_user.last_webmention_in or from_user.has_redirects))):

            obj.our_as1 = copy.deepcopy(obj.as1)
            actor = as1.get_object(obj.as1) if is_activity else obj.as1
            actor['objectType'] = 'person'
            cls.add_source_links(actor=actor, obj=obj, from_user=from_user)

        converted = cls._convert(obj, from_user=from_user, **kwargs)
        obj.our_as1 = orig_our_as1
        return converted

    @classmethod
    def _convert(cls, obj, from_user=None, **kwargs):
        """Converts an :class:`Object` to this protocol's data format.

        To be implemented by subclasses. Implementations should generally call
        :meth:`Protocol.translate_ids` (as their own class) before converting to
        their format.

        Args:
          obj (models.Object):
          from_user (models.User): user (actor) this activity/object is from
          kwargs: protocol-specific

        Returns:
          converted object in the protocol's native format, often a dict. May
            return the ``{}`` empty dict if the object can't be converted.
        """
        raise NotImplementedError()

    @classmethod
    def add_source_links(cls, actor, obj, from_user):
        """Adds "bridged from ... by Bridgy Fed" HTML to ``actor['summary']``.

        Default implementation; subclasses may override.

        Args:
          actor (dict): AS1 actor
          obj (models.Object):
          from_user (models.User): user (actor) this activity/object is from
        """
        assert from_user
        summary = actor.setdefault('summary', '')
        if 'Bridgy Fed]' in html_to_text(summary, ignore_links=True):
            return

        id = actor.get('id')
        proto_phrase = (PROTOCOLS[obj.source_protocol].PHRASE
                        if obj.source_protocol else '')
        if proto_phrase:
            proto_phrase = f' on {proto_phrase}'

        if from_user.key and id in (from_user.key.id(), from_user.profile_id()):
            source_links = f'[<a href="https://{PRIMARY_DOMAIN}{from_user.user_page_path()}">bridged</a> from <a href="{from_user.web_url()}">{from_user.handle}</a>{proto_phrase} by <a href="https://{PRIMARY_DOMAIN}/">Bridgy Fed</a>]'

        else:
            url = as1.get_url(actor) or id
            source = util.pretty_link(url) if url else '?'
            source_links = f'[bridged from {source}{proto_phrase} by <a href="https://{PRIMARY_DOMAIN}/">Bridgy Fed</a>]'

        if summary:
            summary += '<br><br>'
        actor['summary'] = summary + source_links

    @classmethod
    def set_username(to_cls, user, username):
        """Sets a custom username for a user's bridged account in this protocol.

        Args:
          user (models.User)
          username (str)

        Raises:
          ValueError: if the username is invalid
          RuntimeError: if the username could not be set
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
        * ``bcc``
        * ``bto``
        * ``cc``
        * ``object``
        * ``object.actor``
        * ``object.author``
        * ``object.id``
        * ``object.inReplyTo``
        * ``object.object``
        * ``attachments[].id``
        * ``tags[objectType=mention].url``
        * ``to``

        This is the inverse of :meth:`models.Object.resolve_ids`. Much of the
        same logic is duplicated there!

        TODO: unify with :meth:`Object.resolve_ids`,
        :meth:`models.Object.normalize_ids`.

        Args:
          to_proto (Protocol subclass)
          obj (dict): AS1 object or activity (not :class:`models.Object`!)

        Returns:
          dict: wrapped AS1 version of ``obj``
        """
        assert to_cls != Protocol
        if not obj:
            return obj

        outer_obj = copy.deepcopy(obj)
        inner_objs = outer_obj['object'] = as1.get_objects(outer_obj)

        def translate(elem, field, fn, uri=False):
            elem[field] = as1.get_objects(elem, field)
            for obj in elem[field]:
                if id := obj.get('id'):
                    if field in ('to', 'cc', 'bcc', 'bto') and as1.is_audience(id):
                        continue
                    from_cls = Protocol.for_id(id)
                    # TODO: what if from_cls is None? relax translate_object_id,
                    # make it a noop if we don't know enough about from/to?
                    if from_cls and from_cls != to_cls:
                        obj['id'] = fn(id=id, from_=from_cls, to=to_cls)
                    if obj['id'] and uri:
                        obj['id'] = to_cls(id=obj['id']).id_uri()

            elem[field] = [o['id'] if o.keys() == {'id'} else o
                           for o in elem[field]]

            if len(elem[field]) == 1:
                elem[field] = elem[field][0]

        type = as1.object_type(outer_obj)
        translate(outer_obj, 'id',
                  translate_user_id if type in as1.ACTOR_TYPES
                  else translate_object_id)

        for o in inner_objs:
            is_actor = (as1.object_type(o) in as1.ACTOR_TYPES
                        or as1.get_owner(outer_obj) == o.get('id')
                        or type in ('follow', 'stop-following'))
            translate(o, 'id', translate_user_id if is_actor else translate_object_id)
            obj_is_actor = o.get('verb') in as1.VERBS_WITH_ACTOR_OBJECT
            translate(o, 'object', translate_user_id if obj_is_actor
                      else translate_object_id)

        for o in [outer_obj] + inner_objs:
            translate(o, 'inReplyTo', translate_object_id)
            for field in 'actor', 'author', 'to', 'cc', 'bto', 'bcc':
                translate(o, field, translate_user_id)
            for tag in as1.get_objects(o, 'tags'):
                if tag.get('objectType') == 'mention':
                    translate(tag, 'url', translate_user_id, uri=True)
            for att in as1.get_objects(o, 'attachments'):
                translate(att, 'id', translate_object_id)
                url = att.get('url')
                if url and not att.get('id'):
                    if from_cls := Protocol.for_id(url):
                        att['id'] = translate_object_id(from_=from_cls, to=to_cls,
                                                        id=url)

        outer_obj = util.trim_nulls(outer_obj)

        if objs := util.get_list(outer_obj ,'object'):
            outer_obj['object'] = [o['id'] if o.keys() == {'id'} else o for o in objs]
            if len(outer_obj['object']) == 1:
                outer_obj['object'] = outer_obj['object'][0]

        return outer_obj

    @classmethod
    def receive(from_cls, obj, authed_as=None, internal=False, received_at=None):
        """Handles an incoming activity.

        If ``obj``'s key is unset, ``obj.as1``'s id field is used. If both are
        unset, returns HTTP 299.

        Args:
          obj (models.Object)
          authed_as (str): authenticated actor id who sent this activity
          internal (bool): whether to allow activity ids on internal domains,
            from opted out/blocked users, etc.
          received_at (datetime): when we first saw (received) this activity.
            Right now only used for monitoring.

        Returns:
          (str, int) tuple: (response body, HTTP status code) Flask response

        Raises:
          werkzeug.HTTPException: if the request is invalid
        """
        # check some invariants
        assert from_cls != Protocol
        assert isinstance(obj, Object), obj

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
        elif from_cls.owns_id(id) is False:
            error(f'Protocol {from_cls.LABEL} does not own id {id}')
        elif from_cls.is_blocklisted(id, allow_internal=internal):
            error(f'Activity {id} is blocklisted')
        # check that this activity is public. only do this for some activities,
        # not eg likes or follows, since Mastodon doesn't currently mark those
        # as explicitly public.
        elif (obj.type in set(('post', 'update')) | as1.POST_TYPES | as1.ACTOR_TYPES
                  and not as1.is_public(obj.as1, unlisted=False)
                  and not as1.is_dm(obj.as1)):
              logger.info('Dropping non-public activity')
              return ('OK', 200)

        # lease this object, atomically
        memcache_key = activity_id_memcache_key(id)
        leased = memcache.memcache.add(memcache_key, 'leased', noreply=False,
                                     expire=5 * 60)  # 5 min
        # short circuit if we've already seen this activity id.
        # (don't do this for bare objects since we need to check further down
        # whether they've been updated since we saw them last.)
        if (obj.as1.get('objectType') == 'activity'
            and 'force' not in request.values
            and (not leased
                 or (obj.new is False and obj.changed is False))):
            error(f'Already seen this activity {id}', status=204)

        pruned = {k: v for k, v in obj.as1.items()
                  if k not in ('contentMap', 'replies', 'signature')}
        delay = ''
        if (received_at and request.headers.get('X-AppEngine-TaskRetryCount') == '0'
                and obj.type != 'delete'):  # we delay deletes for 2m
            delay_s = int((util.now().replace(tzinfo=None)
                           - received_at.replace(tzinfo=None)
                           ).total_seconds())
            delay = f'({delay_s} s behind)'
        logger.info(f'Receiving {from_cls.LABEL} {obj.type} {id} {delay} AS1: {json_dumps(pruned, indent=2)}')

        # does this protocol support this activity/object type?
        from_cls.check_supported(obj)

        # check authorization
        # https://www.w3.org/wiki/ActivityPub/Primer/Authentication_Authorization
        actor = as1.get_owner(obj.as1)
        if not actor:
            error('Activity missing actor or author')
        elif from_cls.owns_id(actor) is False:
            error(f"{from_cls.LABEL} doesn't own actor {actor}, this is probably a bridged activity. Skipping.", status=204)

        assert authed_as
        assert isinstance(authed_as, str)
        authed_as = normalize_user_id(id=authed_as, proto=from_cls)
        actor = normalize_user_id(id=actor, proto=from_cls)
        if actor != authed_as:
            report_error("Auth: receive: authed_as doesn't match owner",
                         user=f'{id} authed_as {authed_as} owner {actor}')
            error(f"actor {actor} isn't authed user {authed_as}")

        # update copy ids to originals
        obj.normalize_ids()
        obj.resolve_ids()

        if (obj.type == 'follow'
                and Protocol.for_bridgy_subdomain(as1.get_object(obj.as1).get('id'))):
            # follows of bot user; refresh user profile first
            logger.info(f'Follow of bot user, reloading {actor}')
            from_user = from_cls.get_or_create(id=actor, allow_opt_out=True)
            from_user.reload_profile()
        else:
            # load actor user
            from_user = from_cls.get_or_create(id=actor, allow_opt_out=internal)

        if not internal and (not from_user
                             or from_user.manual_opt_out
                             # we want to override opt-out but not manual or blocked
                             or (from_user.status and from_user.status != 'opt-out')):
            error(f'Actor {actor} is opted out or blocked', status=204)

        # if this is an object, ie not an activity, wrap it in a create or update
        obj = from_cls.handle_bare_object(obj, authed_as=authed_as)
        obj.add('users', from_user.key)

        inner_obj_as1 = as1.get_object(obj.as1)
        inner_obj_id = inner_obj_as1.get('id')
        if obj.type in as1.CRUD_VERBS | as1.VERBS_WITH_OBJECT:
            if not inner_obj_id:
                error(f'{obj.type} object has no id!')

        # check age. we support backdated posts, but if they're over 2w old, we
        # don't deliver them
        if obj.type == 'post':
            if published := inner_obj_as1.get('published'):
                try:
                    published_dt = util.parse_iso8601(published)
                    if not published_dt.tzinfo:
                        published_dt = published_dt.replace(tzinfo=timezone.utc)
                    age = util.now() - published_dt
                    if age > CREATE_MAX_AGE:
                        error(f'Ignoring, too old, {age} is over {CREATE_MAX_AGE}',
                              status=204)
                except ValueError:  # from parse_iso8601
                    logger.debug(f"Couldn't parse published {published}")

        # write Object to datastore
        obj.source_protocol = from_cls.LABEL
        if obj.type in STORE_AS1_TYPES:
            obj.put()

        # store inner object
        # TODO: unify with big obj.type conditional below. would have to merge
        # this with the DM handling block lower down.
        crud_obj = None
        if obj.type in ('post', 'update') and inner_obj_as1.keys() > set(['id']):
            crud_obj = Object.get_or_create(inner_obj_id, our_as1=inner_obj_as1,
                                            source_protocol=from_cls.LABEL,
                                            authed_as=actor, users=[from_user.key])

        actor = as1.get_object(obj.as1, 'actor')
        actor_id = actor.get('id')

        # handle activity!
        if obj.type == 'stop-following':
            # TODO: unify with handle_follow?
            # TODO: handle multiple followees
            if not actor_id or not inner_obj_id:
                error(f'stop-following requires actor id and object id. Got: {actor_id} {inner_obj_id} {obj.as1}')

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

            # fall through to deliver to followers

        elif obj.type in ('delete', 'undo'):
            delete_obj_id = (from_user.profile_id()
                            if inner_obj_id == from_user.key.id()
                            else inner_obj_id)

            delete_obj = Object.get_by_id(delete_obj_id, authed_as=authed_as)
            if not delete_obj:
                logger.info(f"Ignoring, we don't have {delete_obj_id} stored")
                return 'OK', 204

            # TODO: just delete altogether!
            logger.info(f'Marking Object {delete_obj_id} deleted')
            delete_obj.deleted = True
            delete_obj.put()

            # if this is an actor, handle deleting it later so that
            # in case it's from_user, user.enabled_protocols is still populated
            #
            # fall through to deliver to followers and delete copy if necessary.
            # should happen via protocol-specific copy target and send of
            # delete activity.
            # https://github.com/snarfed/bridgy-fed/issues/63

        elif obj.type == 'block':
            if proto := Protocol.for_bridgy_subdomain(inner_obj_id):
                # blocking protocol bot user disables that protocol
                from_user.delete(proto)
                from_user.disable_protocol(proto)
                return 'OK', 200

        elif obj.type == 'post':
            # handle DMs to bot users
            if as1.is_dm(obj.as1):
                return dms.receive(from_user=from_user, obj=obj)

        # fetch actor if necessary
        if (actor and actor.keys() == set(['id'])
                and obj.type not in ('delete', 'undo')):
            logger.debug('Fetching actor so we have name, profile photo, etc')
            actor_obj = from_cls.load(ids.profile_id(id=actor['id'], proto=from_cls),
                                      raise_=False)
            if actor_obj and actor_obj.as1:
                obj.our_as1 = {
                    **obj.as1, 'actor': {
                        **actor_obj.as1,
                        # override profile id with actor id
                        # https://github.com/snarfed/bridgy-fed/issues/1720
                        'id': actor['id'],
                    }
                }

        # fetch object if necessary
        if (obj.type in ('post', 'update', 'share')
                and inner_obj_as1.keys() == set(['id'])
                and from_cls.owns_id(inner_obj_id)):
            logger.debug('Fetching inner object')
            inner_obj = from_cls.load(inner_obj_id, raise_=False,
                                      remote=(obj.type in ('post', 'update')))
            if obj.type in ('post', 'update'):
                crud_obj = inner_obj
            if inner_obj and inner_obj.as1:
                obj.our_as1 = {
                    **obj.as1,
                    'object': {
                        **inner_obj_as1,
                        **inner_obj.as1,
                    }
                }
            elif obj.type in ('post', 'update'):
                error("Need object {inner_obj_id} but couldn't fetch, giving up")

        if obj.type == 'follow':
            if proto := Protocol.for_bridgy_subdomain(inner_obj_id):
                # follow of one of our protocol bot users; enable that protocol.
                # fall through so that we send an accept.
                from_user.enable_protocol(proto)
                proto.bot_follow(from_user)

            from_cls.handle_follow(obj)

        # deliver to targets
        resp = from_cls.deliver(obj, from_user=from_user, crud_obj=crud_obj)

        # if this is a user, deactivate its followers/followings
        # https://github.com/snarfed/bridgy-fed/issues/1304
        if obj.type == 'delete':
            if user_key := from_cls.key_for(id=inner_obj_id):
                if user := user_key.get():
                    for proto in user.enabled_protocols:
                        user.disable_protocol(PROTOCOLS[proto])

                    logger.info(f'Deactivating Followers from or to {user_key.id()}')
                    followers = Follower.query(
                        OR(Follower.to == user_key, Follower.from_ == user_key)
                        ).fetch()
                    for f in followers:
                        f.status = 'inactive'
                    ndb.put_multi(followers)

        memcache.memcache.set(memcache_key, 'done', expire=7 * 24 * 60 * 60)  # 1w
        return resp

    @classmethod
    def handle_follow(from_cls, obj):
        """Handles an incoming follow activity.

        Sends an ``Accept`` back, but doesn't send the ``Follow`` itself. That
        happens in :meth:`deliver`.

        Args:
          obj (models.Object): follow activity
        """
        logger.debug('Got follow. Loading users, storing Follow(s), sending accept(s)')

        # Prepare follower (from) users' data
        # TODO: remove all of this and just use from_user
        from_as1 = as1.get_object(obj.as1, 'actor')
        from_id = from_as1.get('id')
        if not from_id:
            error(f'Follow activity requires actor. Got: {obj.as1}')

        from_obj = from_cls.load(from_id, raise_=False)
        if not from_obj:
            error(f"Couldn't load {from_id}", status=502)

        if not from_obj.as1:
            from_obj.our_as1 = from_as1
            from_obj.put()

        from_key = from_cls.key_for(from_id)
        if not from_key:
            error(f'Invalid {from_cls.LABEL} user key: {from_id}')
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
            elif from_cls == to_cls:
                logger.info(f'Skipping same-protocol Follower {from_id} => {to_id}')
                continue

            to_obj = to_cls.load(to_id)
            if to_obj and not to_obj.as1:
                to_obj.our_as1 = to_as1
                to_obj.put()

            to_key = to_cls.key_for(to_id)
            if not to_key:
                logger.info(f'Skipping invalid {from_cls.LABEL} user key: {from_id}')
                continue

            to_user = to_cls.get_or_create(id=to_key.id(), obj=to_obj,
                                           allow_opt_out=True)
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
        if 'accept' not in follower.SUPPORTED_AS1_TYPES:
            return

        target = follower.target_for(follower.obj)
        if not target:
            error(f"Couldn't find delivery target for follower {follower.key.id()}")

        # send accept. note that this is one accept for the whole
        # follow, even if it has multiple followees!
        id = f'{followee.key.id()}/followers#accept-{follow.key.id()}'
        accept = {
            'id': id,
            'objectType': 'activity',
            'verb': 'accept',
            'actor': followee.key.id(),
            'object': follow.as1,
        }
        common.create_task(queue='send', id=id, our_as1=accept, url=target,
                           protocol=follower.LABEL, user=followee.key.urlsafe())

    @classmethod
    def bot_follow(bot_cls, user):
        """Follow a user from a protocol bot user.

        ...so that the protocol starts sending us their activities, if it needs
        a follow for that (eg ActivityPub).

        Args:
          user (User)
        """
        from web import Web
        bot = Web.get_by_id(bot_cls.bot_user_id())
        now = util.now().isoformat()
        logger.info(f'Following {user.key.id()} back from bot user {bot.key.id()}')

        if not user.obj:
            logger.info("  can't follow, user has no profile obj")
            return

        target = user.target_for(user.obj)
        follow_back_id = f'https://{bot.key.id()}/#follow-back-{user.key.id()}-{now}'
        follow_back_as1 = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': follow_back_id,
            'actor': bot.key.id(),
            'object': user.key.id(),
        }
        common.create_task(queue='send', id=follow_back_id,
                           our_as1=follow_back_as1, url=target,
                           source_protocol='web', protocol=user.LABEL,
                           user=bot.key.urlsafe())

    @classmethod
    def handle_bare_object(cls, obj, authed_as=None):
        """If obj is a bare object, wraps it in a create or update activity.

        Checks if we've seen it before.

        Args:
          obj (models.Object)
          authed_as (str): authenticated actor id who sent this activity

        Returns:
          models.Object: ``obj`` if it's an activity, otherwise a new object
        """
        is_actor = obj.type in as1.ACTOR_TYPES
        if not is_actor and obj.type not in ('note', 'article', 'comment'):
            return obj

        obj_actor = ids.normalize_user_id(id=as1.get_owner(obj.as1), proto=cls)
        now = util.now().isoformat()

        # occasionally we override the object, eg if this is a profile object
        # coming in via a user with use_instead set
        obj_as1 = obj.as1
        if obj_id := obj.key.id():
            if obj_as1_id := obj_as1.get('id'):
                if obj_id != obj_as1_id:
                    logger.info(f'Overriding AS1 object id {obj_as1_id} with Object id {obj_id}')
                    obj_as1['id'] = obj_id

        # this is a raw post; wrap it in a create or update activity
        if obj.changed or is_actor:
            if obj.changed:
                logger.info(f'Content has changed from last time at {obj.updated}! Redelivering to all inboxes')
            else:
                logger.info(f'Got actor profile object, wrapping in update')
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
                    **obj_as1,
                },
            }
            logger.debug(f'  AS1: {json_dumps(update_as1, indent=2)}')
            return Object(id=id, our_as1=update_as1,
                          source_protocol=obj.source_protocol)

        if (obj.new
                # HACK: force query param here is specific to webmention
                or 'force' in request.form):
            create_id = f'{obj.key.id()}#bridgy-fed-create'
            create_as1 = {
                'objectType': 'activity',
                'verb': 'post',
                'id': create_id,
                'actor': obj_actor,
                'object': obj_as1,
                'published': now,
            }
            logger.info(f'Wrapping in post')
            logger.debug(f'  AS1: {json_dumps(create_as1, indent=2)}')
            return Object(id=create_id, our_as1=create_as1,
                          source_protocol=obj.source_protocol)

        error(f'{obj.key.id()} is unchanged, nothing to do', status=204)

    @classmethod
    def deliver(from_cls, obj, from_user, crud_obj=None, to_proto=None):
        """Delivers an activity to its external recipients.

        Args:
          obj (models.Object): activity to deliver
          from_user (models.User): user (actor) this activity is from
          crud_obj (models.Object): if this is a create, update, or delete/undo
            activity, the inner object that's being written, otherwise None.
            (This object's ``notify`` and ``feed`` properties may be updated.)
          to_proto (protocol.Protocol): optional; if provided, only deliver to
            targets on this protocol

        Returns:
          (str, int) tuple: Flask response
        """
        if to_proto:
            logger.info(f'Only delivering to {to_proto.LABEL}')

        # find delivery targets. maps Target to Object or None
        #
        # ...then write the relevant object, since targets() has a side effect of
        # setting the notify and feed properties (and dirty attribute)
        targets = from_cls.targets(obj, from_user=from_user, crud_obj=crud_obj)
        if not targets:
            return r'No targets, nothing to do ¯\_(ツ)_/¯', 204

        # store object that targets() updated
        if crud_obj and crud_obj.dirty:
            crud_obj.put()
        elif obj.type in STORE_AS1_TYPES and obj.dirty:
            obj.put()

        obj_params = ({'obj_id': obj.key.id()} if obj.type in STORE_AS1_TYPES
                      else obj.to_request())

        # sort targets so order is deterministic for tests, debugging, etc
        sorted_targets = sorted(targets.items(), key=lambda t: t[0].uri)

        # enqueue send task for each targets
        logger.info(f'Delivering to: {[t for t, _ in sorted_targets]}')
        user = from_user.key.urlsafe()
        for i, (target, orig_obj) in enumerate(sorted_targets):
            if to_proto and target.protocol != to_proto.LABEL:
                continue
            orig_obj_id = orig_obj.key.id() if orig_obj else None
            common.create_task(queue='send', url=target.uri, protocol=target.protocol,
                               orig_obj_id=orig_obj_id, user=user, **obj_params)

        return 'OK', 202

    @classmethod
    def targets(from_cls, obj, from_user, crud_obj=None, internal=False):
        """Collects the targets to send a :class:`models.Object` to.

        Targets are both objects - original posts, events, etc - and actors.

        Args:
          obj (models.Object)
          from_user (User)
          crud_obj (models.Object): if this is a create, update, or delete/undo
            activity, the inner object that's being written, otherwise None.
            (This object's ``notify`` and ``feed`` properties may be updated.)
          internal (bool): whether this is a recursive internal call

        Returns:
          dict: maps :class:`models.Target` to original (in response to)
          :class:`models.Object`, if any, otherwise None
        """
        logger.debug('Finding recipients and their targets')

        # we should only have crud_obj iff this is a create or update
        assert (crud_obj is not None) == (obj.type in ('post', 'update')), obj.type
        write_obj = crud_obj or obj
        write_obj.dirty = False

        target_uris = sorted(set(as1.targets(obj.as1)))
        logger.info(f'Raw targets: {target_uris}')
        orig_obj = None
        targets = {}  # maps Target to Object or None
        owner = as1.get_owner(obj.as1)
        allow_opt_out = (obj.type == 'delete')
        inner_obj_as1 = as1.get_object(obj.as1)
        inner_obj_id = inner_obj_as1.get('id')
        in_reply_tos = as1.get_ids(inner_obj_as1, 'inReplyTo')
        is_reply = obj.type == 'comment' or in_reply_tos
        is_self_reply = False

        if is_reply:
            original_ids = in_reply_tos
        else:
            if inner_obj_id == from_user.key.id():
                inner_obj_id = from_user.profile_id()
            original_ids = [inner_obj_id]

        # which protocols should we allow delivering to?
        to_protocols = []
        for label in (list(from_user.DEFAULT_ENABLED_PROTOCOLS)
                      + from_user.enabled_protocols):
            proto = PROTOCOLS[label]
            if proto.HAS_COPIES and (obj.type in ('update', 'delete', 'share', 'undo')
                                     or is_reply):
                for id in original_ids:
                    if Protocol.for_id(id) == proto:
                        logger.info(f'Allowing {label} for original post {id}')
                        break
                    elif orig := from_user.load(id, remote=False):
                        if orig.get_copy(proto):
                            logger.info(f'Allowing {label}, original post {id} was bridged there')
                            break
                else:
                    logger.info(f"Skipping {label}, original objects {original_ids} weren't bridged there")
                    continue

            util.add(to_protocols, proto)

        # process direct targets
        for id in sorted(target_uris):
            target_proto = Protocol.for_id(id)
            if not target_proto:
                logger.info(f"Can't determine protocol for {id}")
                continue
            elif target_proto.is_blocklisted(id):
                logger.debug(f'{id} is blocklisted')
                continue

            orig_obj = target_proto.load(id, raise_=False)
            if not orig_obj or not orig_obj.as1:
                logger.info(f"Couldn't load {id}")
                continue

            target_author_key = target_proto.actor_key(orig_obj)
            if not from_user.is_enabled(target_proto):
                # if author isn't bridged and inReplyTo author is, DM a prompt
                if id in in_reply_tos:
                    if target_author := target_author_key.get():
                        if target_author.is_enabled(from_cls):
                            dms.maybe_send(
                                from_proto=target_proto, to_user=from_user,
                                type='replied_to_bridged_user', text=f"""\
Hi! You <a href="{inner_obj_as1.get('url') or inner_obj_id}">recently replied</a> to {orig_obj.actor_link(image=False)}, who's bridged here from {target_proto.PHRASE}. If you want them to see your replies, you can bridge your account into {target_proto.PHRASE} by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.""")

                continue

            # deliver self-replies to followers
            # https://github.com/snarfed/bridgy-fed/issues/639
            if id in in_reply_tos and owner == as1.get_owner(orig_obj.as1):
                is_self_reply = True
                logger.info(f'self reply!')

            # also add copies' targets
            for copy in orig_obj.copies:
                proto = PROTOCOLS[copy.protocol]
                if proto in to_protocols:
                    # copies generally won't have their own Objects
                    if target := proto.target_for(Object(id=copy.uri)):
                        logger.debug(f'Adding target {target} for copy {copy.uri} of original {id}')
                        targets[Target(protocol=copy.protocol, uri=target)] = orig_obj

            if target_proto == from_cls:
                logger.debug(f'Skipping same-protocol target {id}')
                continue

            target = target_proto.target_for(orig_obj)
            if not target:
                # TODO: surface errors like this somehow?
                logger.error(f"Can't find delivery target for {id}")
                continue

            logger.debug(f'Target for {id} is {target}')
            # only use orig_obj for inReplyTos, like/repost objects, etc
            # https://github.com/snarfed/bridgy-fed/issues/1237
            targets[Target(protocol=target_proto.LABEL, uri=target)] = (
                orig_obj if id in in_reply_tos or id in as1.get_ids(obj.as1, 'object')
                else None)

            if target_author_key:
                logger.debug(f'Recipient is {target_author_key}')
                if write_obj.add('notify', target_author_key):
                    write_obj.dirty = True

        if obj.type == 'undo':
            logger.debug('Object is an undo; adding targets for inner object')
            if set(inner_obj_as1.keys()) == {'id'}:
                inner_obj = from_cls.load(inner_obj_id, raise_=False)
            else:
                inner_obj = Object(id=inner_obj_id, our_as1=inner_obj_as1)
            if inner_obj:
                targets.update(from_cls.targets(inner_obj, from_user=from_user,
                                                internal=True))

        logger.info(f'Direct targets: {[t.uri for t in targets.keys()]}')

        # deliver to followers, if appropriate
        user_key = from_cls.actor_key(obj, allow_opt_out=allow_opt_out)
        if not user_key:
            logger.info("Can't tell who this is from! Skipping followers.")
            return targets

        followers = []
        if (obj.type in ('post', 'update', 'delete', 'share', 'undo')
                and (not is_reply or is_self_reply)):
            logger.info(f'Delivering to followers of {user_key}')
            followers = [
                f for f in Follower.query(Follower.to == user_key,
                                          Follower.status == 'active')
                # skip protocol bot users
                if not Protocol.for_bridgy_subdomain(f.from_.id())
                # skip protocols this user hasn't enabled, or where the base
                # object of this activity hasn't been bridged
                and PROTOCOLS_BY_KIND[f.from_.kind()] in to_protocols]
            user_keys = [f.from_ for f in followers]
            users = [u for u in ndb.get_multi(user_keys) if u]
            User.load_multi(users)

            if (not followers and
                (util.domain_or_parent_in(
                    util.domain_from_link(from_user.key.id()), LIMITED_DOMAINS)
                 or util.domain_or_parent_in(
                     util.domain_from_link(obj.key.id()), LIMITED_DOMAINS))):
                logger.info(f'skipping, {from_user.key.id()} is on a limited domain and has no followers')
                return {}

            # add to followers' feeds, if any
            if not internal and obj.type in ('post', 'update', 'share'):
                if write_obj.type not in as1.ACTOR_TYPES:
                    write_obj.feed = [u.key for u in users]
                    if write_obj.feed:
                        write_obj.dirty = True

            # collect targets for followers
            for user in users:
                # TODO: should we pass remote=False through here to Protocol.load?
                target = user.target_for(user.obj, shared=True) if user.obj else None
                if not target:
                    # TODO: surface errors like this somehow?
                    logger.error(f'Follower {user.key} has no delivery target')
                    continue

                # normalize URL (lower case hostname, etc)
                # ...but preserve our PDS URL without trailing slash in path
                # https://atproto.com/specs/did#did-documents
                target = util.dedupe_urls([target], trailing_slash=False)[0]

                targets[Target(protocol=user.LABEL, uri=target)] = \
                    Object.get_by_id(inner_obj_id) if obj.type == 'share' else None

        # deliver to enabled HAS_COPIES protocols proactively
        # TODO: abstract for other protocols
        from atproto import ATProto
        if (ATProto in to_protocols
                and obj.type in ('post', 'update', 'delete', 'share')):
            logger.info(f'user has ATProto enabled, adding {ATProto.PDS_URL}')
            targets.setdefault(
                Target(protocol=ATProto.LABEL, uri=ATProto.PDS_URL), None)

        # de-dupe targets, discard same-domain
        # maps string target URL to (Target, Object) tuple
        candidates = {t.uri: (t, obj) for t, obj in targets.items()}
        # maps Target to Object or None
        targets = {}
        source_domains = [
            util.domain_from_link(url) for url in
            (obj.as1.get('id'), obj.as1.get('url'), as1.get_owner(obj.as1))
            if util.is_web(url)
        ]
        for url in sorted(util.dedupe_urls(
                candidates.keys(),
                # preserve our PDS URL without trailing slash in path
                # https://atproto.com/specs/did#did-documents
                trailing_slash=False)):
            if util.is_web(url) and util.domain_from_link(url) in source_domains:
                logger.info(f'Skipping same-domain target {url}')
                continue
            target, obj = candidates[url]
            targets[target] = obj

        return targets

    @classmethod
    def load(cls, id, remote=None, local=True, raise_=True, **kwargs):
        """Loads and returns an Object from datastore or HTTP fetch.

        Sets the :attr:`new` and :attr:`changed` attributes if we know either
        one for the loaded object, ie local is True and remote is True or None.

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
          raise_ (bool): if False, catches any :class:`request.RequestException`
            or :class:`HTTPException` raised by :meth:`fetch()` and returns
            ``None`` instead
          kwargs: passed through to :meth:`fetch()`

        Returns:
          models.Object: loaded object, or None if it isn't fetchable, eg a
          non-URL string for Web, or ``remote`` is False and it isn't in the
          datastore

        Raises:
          requests.HTTPError: anything that :meth:`fetch` raises, if ``raise_``
            is True
        """
        assert id
        assert local or remote is not False
        # logger.debug(f'Loading Object {id} local={local} remote={remote}')

        obj = orig_as1 = None
        if local:
            obj = Object.get_by_id(id)
            if not obj:
                # logger.debug(f' {id} not in datastore')
                pass
            elif obj.as1 or obj.raw or obj.deleted:
                # logger.debug(f'  {id} got from datastore')
                obj.new = False

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
            obj.our_as1 = None
            obj.new = False
        else:
            obj = Object(id=id)
            if local:
                # logger.debug(f'  {id} not in datastore')
                obj.new = True
                obj.changed = False

        try:
            fetched = cls.fetch(obj, **kwargs)
        except (RequestException, HTTPException) as e:
            if raise_:
                raise
            util.interpret_http_exception(e)
            return None

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
        return obj

    @classmethod
    def check_supported(cls, obj):
        """If this protocol doesn't support this object, return 204.

        Also reports an error.

        (This logic is duplicated in some protocols, eg ActivityPub, so that
        they can short circuit out early. It generally uses their native formats
        instead of AS1, before an :class:`models.Object` is created.)

        Args:
          obj (Object)
        """
        if not obj.type:
            return

        inner_type = as1.object_type(as1.get_object(obj.as1)) or ''
        if (obj.type not in cls.SUPPORTED_AS1_TYPES
            or (obj.type in as1.CRUD_VERBS
                and inner_type
                and inner_type not in cls.SUPPORTED_AS1_TYPES)):
            error(f"Bridgy Fed for {cls.LABEL} doesn't support {obj.type} {inner_type} yet", status=204)

        # DMs are only allowed to/from protocol bot accounts
        if recip := as1.recipient_if_dm(obj.as1):
            protocol_user_ids = PROTOCOL_DOMAINS + common.protocol_user_copy_ids()
            if (not cls.SUPPORTS_DMS
                    or (recip not in protocol_user_ids
                        and as1.get_owner(obj.as1) not in protocol_user_ids)):
                error(f"Bridgy Fed doesn't support DMs", status=204)


@cloud_tasks_only(log=None)
def receive_task():
    """Task handler for a newly received :class:`models.Object`.

    Calls :meth:`Protocol.receive` with the form parameters.

    Parameters:
      authed_as (str): passed to :meth:`Protocol.receive`
      obj_id (str): key id of :class:`models.Object` to handle
      received_at (str, ISO 8601 timestamp): when we first saw (received)
        this activity
      *: If ``obj_id`` is unset, all other parameters are properties for a new
        :class:`models.Object` to handle

    TODO: migrate incoming webmentions to this. See how we did it for AP. The
    difficulty is that parts of :meth:`protocol.Protocol.receive` depend on
    setup in :func:`web.webmention`, eg :class:`models.Object` with ``new`` and
    ``changed``, HTTP request details, etc. See stash for attempt at this for
    :class:`web.Web`.
    """
    common.log_request()
    form = request.form.to_dict()

    authed_as = form.pop('authed_as', None)
    internal = (authed_as == common.PRIMARY_DOMAIN
                or authed_as in common.PROTOCOL_DOMAINS)

    obj = Object.from_request()
    assert obj
    assert obj.source_protocol
    obj.new = True

    if received_at := form.pop('received_at', None):
        received_at = datetime.fromisoformat(received_at)

    try:
        return PROTOCOLS[obj.source_protocol].receive(
            obj=obj, authed_as=authed_as, internal=internal, received_at=received_at)
    except RequestException as e:
        util.interpret_http_exception(e)
        error(e, status=304)
    except ValueError as e:
        logger.warning(e, exc_info=True)
        error(e, status=304)


@cloud_tasks_only(log=None)
def send_task():
    """Task handler for sending an activity to a single specific destination.

    Calls :meth:`Protocol.send` with the form parameters.

    Parameters:
      protocol (str): :class:`Protocol` to send to
      url (str): destination URL to send to
      obj_id (str): key id of :class:`models.Object` to send
      orig_obj_id (str): optional, :class:`models.Object` key id of the
        "original object" that this object refers to, eg replies to or reposts
        or likes
      user (url-safe google.cloud.ndb.key.Key): :class:`models.User` (actor)
        this activity is from
      *: If ``obj_id`` is unset, all other parameters are properties for a new
        :class:`models.Object` to handle
    """
    common.log_request()

    # prepare
    form = request.form.to_dict()
    url = form.get('url')
    protocol = form.get('protocol')
    if not url or not protocol:
        logger.warning(f'Missing protocol or url; got {protocol} {url}')
        return '', 204

    target = Target(uri=url, protocol=protocol)
    obj = Object.from_request()
    assert obj and obj.key and obj.key.id()

    PROTOCOLS[protocol].check_supported(obj)
    allow_opt_out = (obj.type == 'delete')

    user = None
    if user_key := form.get('user'):
        key = ndb.Key(urlsafe=user_key)
        # use get_by_id so that we follow use_instead
        user = PROTOCOLS_BY_KIND[key.kind()].get_by_id(
            key.id(), allow_opt_out=allow_opt_out)

    # send
    delay = ''
    if request.headers.get('X-AppEngine-TaskRetryCount') == '0' and obj.created:
        delay_s = int((util.now().replace(tzinfo=None) - obj.created).total_seconds())
        delay = f'({delay_s} s behind)'
    logger.info(f'Sending {obj.source_protocol} {obj.type} {obj.key.id()} to {protocol} {url} {delay}')
    logger.debug(f'  AS1: {json_dumps(obj.as1, indent=2)}')
    sent = None
    try:
        sent = PROTOCOLS[protocol].send(obj, url, from_user=user,
                                        orig_obj_id=form.get('orig_obj_id'))
    except BaseException as e:
        code, body = util.interpret_http_exception(e)
        if not code and not body:
            raise

    if sent is False:
        logger.info(f'Failed sending!')

    return '', 200 if sent else 204 if sent is False else 304
