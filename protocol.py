"""Base protocol class and common code."""
import logging
import threading
from urllib.parse import urljoin

from cachetools import LRUCache
from flask import g, request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1
import werkzeug.exceptions

import common
from common import add, DOMAIN_BLOCKLIST, DOMAINS, error
from flask_app import app
from models import Follower, Object, PROTOCOLS, Target, User
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

SUPPORTED_TYPES = (
    'accept',
    'article',
    'audio',
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

# activity ids that we've already handled and can now ignore.
# used in Protocol.receive
seen_ids = LRUCache(100000)
seen_ids_lock = threading.Lock()

# objects that have been loaded in Protocol.load
objects_cache = LRUCache(5000)
objects_cache_lock = threading.Lock()

logger = logging.getLogger(__name__)


# TODO: merge Protocol and User classes?
class Protocol:
    """Base protocol class. Not to be instantiated; classmethods only.

    Attributes:
      LABEL: str, human-readable lower case name
      OTHER_LABELS: sequence of str, label aliases
      ABBREV: str, lower case abbreviation, used in URL paths
    """
    ABBREV = None
    OTHER_LABELS = ()

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
          fed: :class:`Protocol` subclass to return if the current request is on
          fed.brid.gy

        Returns:
          :class:`Protocol` subclass, or None if the provided domain or request
            hostname domain is not a subdomain of brid.gy or isn't a known protocol
        """
        return Protocol.for_domain(request.host, fed=fed)

    @staticmethod
    def for_domain(domain_or_url, fed=None):
        """Returns the protocol for a brid.gy subdomain.

        Args:
          domain_or_url: str
          fed: :class:`Protocol` subclass to return if the domain_or_url is on
            fed.brid.gy

        Returns:
          :class:`Protocol` subclass, or None if the request hostname is not a
            subdomain of brid.gy or isn't a known protocol
        """
        domain = (util.domain_from_link(domain_or_url, minimize=False)
                  if util.is_web(domain_or_url)
                  else domain_or_url)

        if domain == common.PRIMARY_DOMAIN or domain in common.LOCAL_DOMAINS:
            return fed
        elif domain and domain.endswith(common.SUPERDOMAIN):
            label = domain.removesuffix(common.SUPERDOMAIN)
            return PROTOCOLS.get(label)

    @classmethod
    def subdomain_url(cls, path=None):
        """Returns the URL for a given path on this protocol's subdomain.

        Eg for the path 'foo/bar' on ActivityPub, returns
        'https://ap.brid.gy/foo/bar'.

        Args:
          path: str

        Returns:
          str, URL
        """
        return urljoin(f'https://{cls.ABBREV or "fed"}{common.SUPERDOMAIN}/', path)

    @classmethod
    def owns_id(cls, id):
        """Returns whether this protocol owns the id, or None if it's unclear.

        To be implemented by subclasses.

        Some protocols' ids are more or less deterministic based on the id
        format, eg AT Protocol owns at:// URIs. Others, like http(s) URLs, could
        be owned by eg Web or ActivityPub.

        This should be a quick guess without expensive side effects, eg no
        external HTTP fetches to fetch the id itself or otherwise perform
        discovery.

        Returns False if the id's domain is in :attr:`common.DOMAIN_BLOCKLIST`.

        Args:
          id: str

        Returns:
          boolean or None
        """
        return False

    @classmethod
    def key_for(cls, id):
        """Returns the :class:`ndb.Key` for a given id's :class:`User`.

        To be implemented by subclasses. Canonicalizes the id if necessary.

        If called via `Protocol.key_for`, infers the appropriate protocol with
        :meth:`for_id`. If called with a concrete subclass, uses that subclass
        as is.

        Returns:
          :class:`ndb.Key`, or None if the given id is not a valid :class:`User`
          id for this protocol.
        """
        if cls == Protocol:
            return Protocol.for_id(id).key_for(id)

        return cls(id=id).key

    @staticmethod
    def for_id(id):
        """Returns the protocol for a given id.

        May incur expensive side effects like fetching the id itself over the
        network or other discovery.

        Args:
          id: str

        Returns:
          :class:`Protocol` subclass, or None if no known protocol owns this id
        """
        logger.info(f'Determining protocol for id {id}')
        if not id:
            return None

        # step 1: check for our per-protocol subdomains
        if util.is_web(id):
            by_domain = Protocol.for_domain(id)
            if by_domain:
                logger.info(f'  {by_domain.__name__} owns {id}')
                return by_domain

        # step 2: check if any Protocols say conclusively that they own it
        # sort to be deterministic
        protocols = sorted(set(p for p in PROTOCOLS.values() if p),
                           key=lambda p: p.__name__)
        candidates = []
        for protocol in protocols:
            owns = protocol.owns_id(id)
            if owns:
                logger.info(f'  {protocol.__name__} owns {id}')
                return protocol
            elif owns is not False:
                candidates.append(protocol)

        if len(candidates) == 1:
            logger.info(f'  {candidates[0].__name__} owns {id}')
            return candidates[0]

        # step 3: look for existing Objects in the datastore
        obj = Protocol.load(id, remote=False)
        if obj and obj.source_protocol:
            logger.info(f'  {obj.key} owned by source_protocol {obj.source_protocol}')
            return PROTOCOLS[obj.source_protocol]

        # step 4: fetch over the network
        for protocol in candidates:
            logger.info(f'Trying {protocol.__name__}')
            try:
                if protocol.load(id, local=False, remote=True):
                    logger.info(f'  {protocol.__name__} owns {id}')
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

    @classmethod
    def actor_key(cls, obj, default_g_user=True):
        """Returns the :class:`User`: key for a given object's author or actor.

        If obj has no author or actor, defaults to g.user if it's set and
        default_g_user is True, otherwise None.

        Args:
          obj: :class:`Object`
          default_g_user: boolean

        Returns:
          :class:`ndb.Key` or None
        """
        owner = as1.get_owner(obj.as1)
        if owner:
            return cls.key_for(owner)
        elif default_g_user and g.user:
            return g.user.key

    @classmethod
    def send(to_cls, obj, url, log_data=True):
        """Sends an outgoing activity.

        To be implemented by subclasses.

        Args:
          obj: :class:`Object` with activity to send
          url: str, destination URL to send to
          log_data: boolean, whether to log full data object

        Returns:
          True if the activity is sent successfully, False if it is ignored or
          otherwise unsent due to protocol logic, eg no webmention endpoint,
          protocol doesn't support the activity type. (Failures are raised as
          exceptions.)

        Raises:
          :class:`werkzeug.HTTPException` if the request fails
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
          obj: :class:`Object` with the id to fetch. Data is filled into one of
            the protocol-specific properties, eg as2, mf2, bsky.
          **kwargs: subclass-specific

        Raises:
          :class:`werkzeug.HTTPException` if the fetch fails

        Returns:
          True if the object was fetched and populated successfully,
          False otherwise
        """
        raise NotImplementedError()

    @classmethod
    def serve(cls, obj):
        """Returns this protocol's Flask response for a given :class:`Object`.

        For example, an HTML string and `'text/html'` for :class:`Web`,
        or a dict with AS2 JSON and `'application/activity+json'` for
        :class:`ActivityPub`.

        To be implemented by subclasses.

        Args:
          obj: :class:`Object`

        Returns:
          (response body, dict with HTTP headers) tuple appropriate to be
          returned from a Flask handler
        """
        raise NotImplementedError()

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns an :class:`Object`'s delivery target (endpoint).

        To be implemented by subclasses.

        Examples:

        * If obj has `source_protocol` `'web'`, returns its URL, as a
          webmention target.
        * If obj is an `'activitypub'` actor, returns its inbox.
        * If obj is an `'activitypub'` object, returns it's author's or actor's
          inbox.

        Args:
          obj: :class:`Object`
          shared: boolean, optional. If `True`, returns a common/shared
            endpoint, eg ActivityPub's `sharedInbox`, that can be reused for
            multiple recipients for efficiency

        Returns:
          str target endpoint, or `None` if not available.
        """
        raise NotImplementedError()

    @classmethod
    def is_blocklisted(cls, url):
        """Returns True if we block the given URL and shouldn't deliver to it.

        Default implementation here, subclasses may override.

        Args:
          url: str

        Returns: boolean
        """
        return util.domain_or_parent_in(util.domain_from_link(url),
                                        DOMAIN_BLOCKLIST + DOMAINS)

    @classmethod
    def receive(from_cls, obj):
        """Handles an incoming activity.

        If obj's key is unset, obj.as1's id field is used. If both are unset,
        raises :class:`werkzeug.exceptions.BadRequest`.

        Args:
          obj: :class:`Object`

        Returns:
          (response body, HTTP status code) tuple for Flask response

        Raises:
          :class:`werkzeug.HTTPException` if the request is invalid
        """
        # check some invariants
        assert from_cls != Protocol
        assert isinstance(obj, Object), obj
        logger.info(f'From {from_cls.__name__}: {obj.key} AS1: {json_dumps(obj.as1, indent=2)}')

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

        # short circuit if we've already seen this activity id.
        # (don't do this for bare objects since we need to check further down
        # whether they've been updated since we saw them last.)
        if obj.as1.get('objectType') == 'activity':
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

        # write Object to datastore
        orig = obj
        obj = Object.get_or_create(id, **orig.to_dict())
        if orig.new is not None:
            obj.new = orig.new
        if orig.changed is not None:
            obj.changed = orig.changed

        # if this is a post, ie not an activity, wrap it in a create or update
        obj = from_cls.handle_bare_object(obj)

        if obj.type not in SUPPORTED_TYPES:
            error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

        # add owner(s)
        actor_key = from_cls.actor_key(obj, default_g_user=False)
        if actor_key:
            add(obj.users, actor_key)

        inner_obj_as1 = as1.get_object(obj.as1)
        if obj.as1.get('verb') in ('post', 'update', 'delete'):
            inner_actor = as1.get_owner(inner_obj_as1)
            if inner_actor:
                user_key = from_cls.key_for(inner_actor)
                if user_key:
                    add(obj.users, user_key)

        obj.source_protocol = from_cls.LABEL
        obj.put()

        # store inner object
        inner_obj_id = inner_obj_as1.get('id')
        inner_obj = None
        if obj.type in ('post', 'update') and inner_obj_as1.keys() > set(['id']):
            Object.get_or_create(inner_obj_id, our_as1=inner_obj_as1,
                                 source_protocol=from_cls.LABEL)

        actor = as1.get_object(obj.as1, 'actor')
        actor_id = actor.get('id')

        # handle activity!
        if obj.type == 'accept':  # eg in response to a Follow
            return 'OK'  # noop

        elif obj.type == 'stop-following':
            # TODO: unify with handle_follow?
            # TODO: handle multiple followees
            if not actor_id or not inner_obj_id:
                error(f'Undo of Follow requires actor id and object id. Got: {actor_id} {inner_obj_id} {obj.as1}')

            # deactivate Follower
            # TODO: avoid import?
            from web import Web
            from_ = from_cls.key_for(actor_id)
            to_cls = Protocol.for_id(inner_obj_id) or Web
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

        elif obj.type == 'update':
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

        # fetch actor if necessary so we have name, profile photo, etc
        if actor and actor.keys() == set(['id']):
            logger.info('Fetching actor so we have name, profile photo, etc')
            actor_obj = from_cls.load(actor['id'])
            if actor_obj and actor_obj.as1:
                obj.our_as1 = {**obj.as1, 'actor': actor_obj.as1}

        # fetch object if necessary so we can render it in feeds
        if obj.type == 'share' and inner_obj_as1.keys() == set(['id']):
            if not inner_obj and from_cls.owns_id(inner_obj_id):
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
            from_cls.handle_follow(obj)

        # deliver to targets
        return from_cls.deliver(obj)

    @classmethod
    def handle_follow(from_cls, obj):
        """Handles an incoming follow activity.

        Args:
          obj: :class:`Object`, follow activity
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

        from_target = from_cls.target_for(from_obj)
        if not from_target:
            error(f"Couldn't find delivery target for follower {from_obj}")

        from_key = from_cls.key_for(from_id)
        if not from_key:
            error(f'Invalid {from_cls} user key: {from_id}')
        obj.users = [from_key]

        # Prepare followee (to) users' data
        to_as1s = as1.get_objects(obj.as1)
        if not to_as1s:
            error(f'Follow activity requires object(s). Got: {obj.as1}')

        # Store Followers
        for to_as1 in to_as1s:
            to_id = to_as1.get('id')
            if not to_id or not from_id:
                error(f'Follow activity requires object(s). Got: {obj.as1}')

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

            # If followee user is already direct, follower may not know they're
            # interacting with a bridge. if followee user is indirect though,
            # follower should know, so they're direct.
            to_key = to_cls.key_for(to_id)
            if not to_key:
                logger.info(f'Skipping invalid {from_cls} user key: {from_id}')
                continue

            to_user = to_cls.get_or_create(id=to_key.id(), obj=to_obj, direct=False)

            # HACK: we rewrite direct here for each followee, so the last one
            # wins. Could we do something better?
            from_user = from_cls.get_or_create(id=from_key.id(), obj=from_obj,
                                               direct=not to_user.direct)
            follower_obj = Follower.get_or_create(to=to_user, from_=from_user,
                                                  follow=obj.key, status='active')
            add(obj.notify, to_key)

            # send accept. note that this is one accept for the whole follow, even
            # if it has multiple followees!
            id = common.host_url(to_user.user_page_path(
                f'followers#accept-{obj.key.id()}'))
            accept = Object.get_or_create(id, our_as1={
                'id': id,
                'objectType': 'activity',
                'verb': 'accept',
                'actor': to_id,
                'object': obj.as1,
            })
            sent = from_cls.send(accept, from_target)
            if sent:
                accept.populate(
                    delivered=[Target(protocol=from_cls.LABEL, uri=from_target)],
                    status='complete',
                )
                accept.put()

    @classmethod
    def handle_bare_object(cls, obj):
        """If obj is a bare object, wraps it in a create or update activity.

        Checks if we've seen it before.

        Args:
          obj: :class:`Object`

        Returns:
          obj: :class:`Object`, the same one if the input obj is an activity,
          otherwise a new one
        """
        if obj.type not in ('note', 'article', 'comment'):
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
    def deliver(from_cls, obj):
        """Delivers an activity to its external recipients.

        Args:
          obj: :class:`Object`, activity to deliver
        """
        # find delivery targets
        # sort targets so order is deterministic for tests, debugging, etc
        targets = from_cls.targets(obj)  # maps Target to Object or None

        if not targets:
            obj.status = 'ignored'
            obj.put()
            error('No targets', status=204)

        sorted_targets = sorted(targets.items(), key=lambda t: t[0].uri)
        obj.populate(
            status='in progress',
            delivered=[],
            failed=[],
            undelivered=[t for t, _ in sorted_targets],
        )
        logger.info(f'Delivering to: {obj.undelivered}')

        log_data = True
        errors = []  # stores (target URL, code, body) tuples

        # deliver!
        for target, orig_obj in sorted_targets:
            assert target.uri
            protocol = PROTOCOLS[target.protocol]

            # this is reused later in ActivityPub.send()
            # TODO: find a better way
            obj.orig_obj = orig_obj
            try:
                sent = protocol.send(obj, target.uri, log_data=log_data)
                if sent:
                    add(obj.delivered, target)
                obj.undelivered.remove(target)
            except BaseException as e:
                code, body = util.interpret_http_exception(e)
                if not code and not body:
                    raise
                add(obj.failed, target)
                obj.undelivered.remove(target)
                errors.append((target.uri, code, body))
            finally:
                log_data = False

            obj.put()

        # Pass the response status code and body through as our response
        if obj.delivered:
            ret = 'OK'
            obj.status = 'complete'
        elif errors:
            ret = f'Delivery failed: {errors}', 502
            obj.status = 'failed'
        else:
            ret = r'Nothing to do ¯\_(ツ)_/¯', 204
            obj.status = 'ignored'

        obj.put()
        logger.info(f'Returning {ret}')
        return ret

    @classmethod
    def targets(cls, obj):
        """Collects the targets to send an :class:`models.Object` to.

        Targets are both objects - original posts, events, etc - and actors.

        Args:
          obj (:class:`models.Object`)

        Returns:
          dict: {
            :class:`Target`: original (in response to) :class:`models.Object`,
            if any, otherwise None
          }
        """
        logger.info('Finding recipients and their targets')

        target_uris = set(as1.targets(obj.as1))
        logger.info(f'Raw targets: {target_uris}')

        if target_uris:
            origs = {u.key.id() for u in User.get_for_copies(target_uris)} | \
                {o.key.id() for o in Object.query(Object.copies.uri.IN(target_uris))}
            if origs:
                target_uris |= origs
                logger.info(f'Added originals: {origs}')


        orig_obj = None
        targets = {}  # maps Target to Object or None

        for id in sorted(target_uris):
            protocol = Protocol.for_id(id)
            if not protocol:
                logger.info(f"Can't determine protocol for {id}")
                continue
            elif protocol == cls and cls.LABEL != 'fake':
                logger.info(f'Skipping same-protocol target {id}')
                continue
            elif protocol.is_blocklisted(id):
                logger.info(f'{id} is blocklisted')
                continue

            orig_obj = protocol.load(id)
            if not orig_obj or not orig_obj.as1:
                logger.info(f"Couldn't load {id}")
                continue

            target = protocol.target_for(orig_obj)
            if not target:
                # TODO: surface errors like this somehow?
                logger.error(f"Can't find delivery target for {id}")
                continue

            logger.info(f'Target for {id} is {target}')
            targets[Target(protocol=protocol.LABEL, uri=target)] = orig_obj
            orig_user = protocol.actor_key(orig_obj, default_g_user=False)
            if orig_user:
                logger.info(f'Recipient is {orig_user}')
                add(obj.notify, orig_user)

        logger.info(f'Direct targets: {targets.keys()}')

        # deliver to followers, if appropriate
        user_key = cls.actor_key(obj, default_g_user=False)
        if not user_key:
            logger.info("Can't tell who this is from! Skipping followers.")
            return targets

        if (obj.type in ('post', 'update', 'delete', 'share')
                and not (obj.type == 'comment'
                         or as1.get_object(obj.as1).get('inReplyTo'))):
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
                    add(feed_obj.feed, user.key)

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
          id: str

          remote: boolean, whether to fetch the object over the network. If True,
            fetches even if we already have the object stored, and updates our
            stored copy. If False and we don't have the object stored, returns
            None. Default (None) means to fetch over the network only if we
            don't already have it stored.
          local: boolean, whether to load from the datastore before
            fetching over the network. If False, still stores back to the
            datastore after a successful remote fetch.
          kwargs: passed through to :meth:`fetch()`

        Returns: :class:`Object`, or None if:
          * it isn't fetchable, eg a non-URL string for Web
          * remote is False and it isn't in the cache or datastore

        Raises:
          :class:`requests.HTTPError`, anything else that :meth:`fetch` raises
        """
        assert local or remote is not False

        logger.info(f'Loading Object {id} local={local} remote={remote}')

        if remote is not True:
            with objects_cache_lock:
                cached = objects_cache.get(id)
                if cached:
                    # make a copy so that if the client modifies this entity in
                    # memory, those modifications aren't applied to the cache
                    # until they explicitly put() the modified entity.
                    # NOTE: keep in sync with Object._post_put_hook!
                    return Object(id=cached.key.id(), **cached.to_dict(
                        # computed properties
                        exclude=['as1', 'expire', 'object_ids', 'type']))

        obj = orig_as1 = None
        if local:
            obj = Object.get_by_id(id)
            if obj and (obj.as1 or obj.raw or obj.deleted):
                logger.info('  got from datastore')
                obj.new = False
                orig_as1 = obj.as1
                if remote is not True:
                    with objects_cache_lock:
                        objects_cache[id] = obj
                    return obj

        if remote is True:
            logger.info('  remote=True, forced refresh requested')
        elif remote is False:
            logger.info(f'  remote=False, {"empty" if obj else "not"} in datastore')
            return obj

        if obj:
            obj.clear()
            obj.new = False
        else:
            obj = Object(id=id)
            if local:
                logger.info('  not in datastore')
                obj.new = True
                obj.changed = False

        fetched = cls.fetch(obj, **kwargs)
        if not fetched:
            return None

        if obj.new is False:
            obj.changed = obj.activity_changed(orig_as1)

        obj.source_protocol = cls.LABEL
        # TODO: drop this?
        obj.put()

        with objects_cache_lock:
            objects_cache[id] = obj
        return obj


@app.post('/_ah/queue/receive')
def receive_task():
    """Task handler for a newly received :class:`Object`.

    Form parameters:

    * obj: urlsafe :class:`ndb.Key` of the :class:`Object` to handle
    * user: urlsafe :class:`ndb.Key` of the :class:`User` this activity is on
      behalf of. This user will be loaded into `g.user`.

    TODO: migrate incoming webmentions and AP inbox deliveries to this.
    difficulty is that parts of Protocol.receive depend on setup in
    Web.webmention and ActivityPub.inbox, eg Object with new/changed, g.user
    (which receive now loads), HTTP request details, etc. see stash for attempt
    at this for Web.
    """
    logger.info(f'Params: {list(request.form.items())}')

    obj = ndb.Key(urlsafe=request.form['obj']).get()
    assert obj
    if user_key := request.form.get('user'):
        g.user = ndb.Key(urlsafe=user_key).get()

    try:
        return PROTOCOLS[obj.source_protocol].receive(obj)
    except ValueError as e:
        logger.warning(e, exc_info=True)
        error(e, status=304)
