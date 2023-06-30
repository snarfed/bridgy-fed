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
from common import add, error
from models import Follower, Object, PROTOCOLS, Target
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

        Args:
          id: str

        Returns:
          boolean or None
        """
        return False

    @classmethod
    def key_for(cls, id):
        """Returns the :class:`ndb.Key` for a given id's :class:`User`.

        Canonicalizes the id if necessary.

        If called via `Protocol.key_for`, infers the appropriate protocol with
        :meth:`for_id`. If called with a concrete subclass, uses that subclass
        as is.
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
                protocol.load(id, local=False, remote=True)
                logger.info(f'  {protocol.__name__} owns {id}')
                return protocol
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
    def send(cls, obj, url, log_data=True):
        """Sends an outgoing activity.

        To be implemented by subclasses.

        Args:
          obj: :class:`Object` with activity to send
          url: str, destination URL to send to
          log_data: boolean, whether to log full data object

        Returns:
          True if the activity is sent successfully, False if it is ignored due
          to protocol logic. (Failures are raised as exceptions.)

        Raises:
          :class:`werkzeug.HTTPException` if the request fails
        """
        raise NotImplementedError()

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Fetches a protocol-specific object and populates it in an :class:`Object`.

        To be implemented by subclasses.

        Args:
          obj: :class:`Object` with the id to fetch. Data is filled into one of
            the protocol-specific properties, eg as2, mf2, bsky.
          **kwargs: subclass-specific

        Raises:
          :class:`werkzeug.HTTPException` if the fetch fails
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
    def receive(from_cls, id, **props):
        """Handles an incoming activity.

        Args:
          id: str, activity id
          props: property values to populate into the :class:`Object`

        Returns:
          (response body, HTTP status code) tuple for Flask response

        Raises:
          :class:`werkzeug.HTTPException` if the request is invalid
        """
        logger.info(f'From {from_cls.__name__}')
        assert from_cls != Protocol

        if not id:
            error('No id provided')
        elif util.domain_from_link(id) in common.DOMAINS:
            error(f'{id} is on a Bridgy Fed domain, which is not supported')

        # short circuit if we've already seen this activity id
        with seen_ids_lock:
            already_seen = id in seen_ids
            seen_ids[id] = True
            if already_seen or Object.get_by_id(id):
                msg = f'Already handled this activity {id}'
                logger.info(msg)
                return msg, 200

        # block intra-BF ids
        obj = Object(**props)
        if obj.as1:
            for field in 'id', 'actor', 'author', 'attributedTo':
                val = as1.get_object(obj.as1, field).get('id')
                if util.domain_from_link(val) in common.DOMAINS:
                    error(f'{field} {val} is on Bridgy Fed, which is not supported')

        # write real Object
        obj = Object.get_or_insert(id)
        obj.clear()
        obj.populate(source_protocol=from_cls.LABEL, **props)
        if g.user:
            add(obj.users, g.user.key)
        obj.put()
        logger.info(f'Got AS1: {json_dumps(obj.as1, indent=2)}')

        if obj.type not in SUPPORTED_TYPES:
            error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

        # store inner object
        inner_obj_as1 = as1.get_object(obj.as1)
        inner_obj_id = inner_obj_as1.get('id')
        inner_obj = None
        if (obj.type in ('post', 'update')
              and inner_obj_as1.keys() > set(['id'])):
            inner_obj = Object.get_or_insert(inner_obj_id)
            inner_obj.populate(our_as1=inner_obj_as1,
                               source_protocol=from_cls.LABEL)
            inner_obj.put()

        actor = as1.get_object(obj.as1, 'actor')
        actor_id = actor.get('id')

        # handle activity!
        if obj.type == 'accept':  # eg in response to a Follow
            return 'OK'  # noop

        elif obj.type == 'stop-following':
            if not actor_id or not inner_obj_id:
                error(f'Undo of Follow requires actor id and object id. Got: {actor_id} {inner_obj_id} {obj.as1}')

            # deactivate Follower
            # TODO: avoid import?
            from web import Web
            from_ = from_cls.key_for(actor_id)
            to = (Protocol.for_id(inner_obj_id) or Web).key_for(inner_obj_id)
            follower = Follower.query(Follower.to == to,
                                      Follower.from_ == from_,
                                      Follower.status == 'active').get()
            if follower:
                logger.info(f'Marking {follower} inactive')
                follower.status = 'inactive'
                follower.put()
            else:
                logger.warning(f'No Follower found for {from_} => {to}')

            # TODO send webmention with 410 of u-follow

            obj.status = 'complete'
            obj.put()
            return 'OK'

        elif obj.type == 'update':
            if not inner_obj_id:
                error("Couldn't find id of object to update")

        elif obj.type == 'delete':
            if not inner_obj_id:
                error("Couldn't find id of object to delete")

            to_delete = Object.get_by_id(inner_obj_id)
            if to_delete:
                logger.info(f'Marking Object {inner_obj_id} deleted')
                to_delete.deleted = True
                to_delete.put()

            # assume this is an actor
            # https://github.com/snarfed/bridgy-fed/issues/63
            logger.info(f'Deactivating Followers from or to = {inner_obj_id}')
            deleted_user = from_cls(id=inner_obj_id).key
            followers = Follower.query(OR(Follower.to == deleted_user,
                                          Follower.from_ == deleted_user)
                                       ).fetch()
            for f in followers:
                f.status = 'inactive'
            obj.status = 'complete'
            ndb.put_multi(followers + [obj])
            return 'OK'

        # fetch actor if necessary so we have name, profile photo, etc
        if actor and actor.keys() == set(['id']):
            actor_obj = from_cls.load(actor['id'])
            if actor_obj.as1:
                obj.our_as1 = {**obj.as1, 'actor': actor_obj.as1}

        # fetch object if necessary so we can render it in feeds
        if obj.type == 'share' and inner_obj_as1.keys() == set(['id']):
            if not inner_obj:
                inner_obj = from_cls.load(inner_obj_id)
            if inner_obj.as1:
                obj.our_as1 = {**obj.as1, 'object': inner_obj.as1}

        if obj.type == 'follow':
            from_cls.accept_follow(obj)

        # deliver to each target
        from_cls.deliver(obj)

        # deliver original posts and reposts to followers
        is_reply = (obj.type == 'comment' or
                    (inner_obj_as1 and inner_obj_as1.get('inReplyTo')))
        if ((obj.type == 'share' or obj.type in ('post', 'update') and not is_reply)
                and actor_id):
            logger.info(f'Delivering to followers of {actor_id}')
            for f in Follower.query(Follower.to == from_cls.key_for(actor_id),
                                    Follower.status == 'active'):
                add(obj.users, f.from_)
            if obj.users:
                add(obj.labels, 'feed')

        obj.put()
        return 'OK'

    @classmethod
    def accept_follow(cls, obj):
        """Replies to a follow with an accept.

        Args:
          obj: :class:`Object`, follow activity
        """
        logger.info('Got follow. Loading users, storing Follow, sending accept')

        # Extract follower/followee objects and ids
        from_as1 = as1.get_object(obj.as1, 'actor')
        from_id = from_as1.get('id')
        to_as1 = as1.get_object(obj.as1)
        to_id = to_as1.get('id')
        if not to_id or not from_id:
            error(f'Follow activity requires object and actor. Got: {obj.as1}')

        # Store follower/followee Objects
        from_cls = cls
        from_obj = from_cls.load(from_id)
        if not from_obj.as1:
            from_obj.our_as1 = from_as1
            from_obj.put()

        to_cls = Protocol.for_id(to_id)
        to_obj = to_cls.load(to_id)
        if not to_obj.as1:
            to_obj.our_as1 = to_as1
            to_obj.put()

        from_target = from_cls.target_for(from_obj)
        if not from_target:
            error(f"Couldn't find delivery target for follower {from_obj}")

        # If followee user is alread direct, follower may not know they're
        # interacting with a bridge. f followee user is indirect though,
        # follower should know, so the're direct.
        to_key = to_cls.key_for(to_id)
        to_user = to_cls.get_or_create(id=to_key.id(), obj=to_obj, direct=False)

        from_key = from_cls.key_for(from_id)
        from_user = from_cls.get_or_create(id=from_key.id(), obj=from_obj,
                                           direct=not to_user.direct)

        follower_obj = Follower.get_or_create(to=to_user, from_=from_user,
                                              follow=obj.key, status='active')
        obj.users = [from_key, to_key]

        # send Accept
        id = common.host_url(to_user.user_page_path(
            f'followers#accept-{obj.key.id()}'))
        accept = Object.get_or_insert(id, our_as1={
            'id': id,
            'objectType': 'activity',
            'verb': 'accept',
            'actor': to_id,
            'object': obj.as1,
        })
        sent = cls.send(accept, from_target)

        accept.populate(
            delivered=[Target(protocol=from_cls.LABEL, uri=from_target)],
            status='complete',
        )
        accept.put()
        return sent

    @classmethod
    def deliver(cls, obj):
        """Delivers an activity to its external recipients.

        Args:
          obj: :class:`Object`, activity to deliver
        """
        import web
        return web._deliver(obj)

        # extract source and targets
        source = obj.as1.get('url') or obj.as1.get('id')
        inner_obj = as1.get_object(obj.as1)
        obj_url = util.get_url(inner_obj) or inner_obj.get('id')

        if not source or obj.type in ('post', 'update'):
            source = obj_url
        if not source:
            error("Couldn't find source post URL")

        targets = util.get_list(obj.as1, 'inReplyTo')
        targets.extend(util.get_list(inner_obj, 'inReplyTo'))

        for tag in (util.get_list(obj.as1, 'tags') +
                    util.get_list(as1.get_object(obj.as1), 'tags')):
            if tag.get('objectType') == 'mention':
                url = tag.get('url')
                if url:
                    targets.append(url)

        if obj.type in ('follow', 'like', 'share'):
            targets.append(obj_url)

        target_urls = util.dedupe_urls(util.get_url(t) for t in targets)
        target_urls = common.remove_blocklisted(t.lower() for t in target_urls)
        if not target_urls:
            logger.info("Couldn't find any target URLs in inReplyTo, object, or mention tags")
            return

        logger.info(f'targets: {target_urls}')

        errors = []  # stores (code, body) tuples

        targets = []
        for url in target_urls:
            protocol = Protocol.for_id(url)
            label = protocol.LABEL if protocol else 'web'
            targets.append(Target(uri=url, protocol=label))

        no_user_domains = set()

        obj.undelivered = []
        obj.status = 'in progress'

        obj.populate(
          undelivered=targets,
          status='in progress',
        )

        # send webmentions and update Object
        while obj.undelivered:
            target = obj.undelivered.pop()
            domain = util.domain_from_link(target.uri, minimize=False)
            if g.user and domain == g.user.key.id():
                add(obj.labels, 'notification')

            if (domain == util.domain_from_link(source, minimize=False)
                and cls.LABEL != 'fake'):
                logger.info(f'Skipping same-domain delivery from {source} to {target.uri}')
                continue

            # only deliver if we have a matching User already.
            # TODO: consider delivering or at least storing Users for all
            # targets? need to filter out native targets in this protocol
            # though, eg mastodon.social targets in AP inbox deliveries.
            if domain in no_user_domains:
                continue

            recip = PROTOCOLS[target.protocol](id=domain)
            logger.info(f'Sending to {recip.key}')
            if recip.key not in obj.users:
                if not recip.key.get():
                    logger.info(f'No {recip.key} user found; skipping {target}')
                    no_user_domains.add(domain)
                    continue
                obj.users.append(recip.key)

            try:
                if recip.send(obj, target.uri):
                    obj.delivered.append(target)
                    add(obj.labels, 'notification')
            except BaseException as e:
                code, body = util.interpret_http_exception(e)
                if not code and not body:
                    raise
                errors.append((code, body))
                obj.failed.append(target)

            obj.put()

        obj.status = ('complete' if obj.delivered or obj.users
                      else 'failed' if obj.failed
                      else 'ignored')

        if errors:
            msg = 'Errors: ' + ', '.join(f'{code} {body}' for code, body in errors)
            error(msg, status=int(errors[0][0] or 502))

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

        Returns: :class:`Object` or None if it isn't in the datastore and remote
          is False

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
            if obj and (obj.as1 or obj.deleted):
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
            logger.info('  remote=False, {"empty" if obj else "not"} in datastore')
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

        cls.fetch(obj, **kwargs)
        if obj.new is False:
            if orig_as1 and obj.as1:
                obj.changed = as1.activity_changed(orig_as1, obj.as1)
            else:
                obj.changed = bool(orig_as1) != bool(obj.as1)

        obj.source_protocol = cls.LABEL
        obj.put()

        with objects_cache_lock:
            objects_cache[id] = obj
        return obj
