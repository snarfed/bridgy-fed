"""Base protocol class and common code."""
import logging
import threading

from cachetools import cached, LRUCache
from flask import g
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1, as2

import common
from common import error
from models import Follower, Object, Target
from oauth_dropins.webutil import util, webmention
from oauth_dropins.webutil.util import json_dumps, json_loads

SUPPORTED_TYPES = (
    'accept',
    'article',
    'audio',
    'comment',
    'create',
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


class Protocol:
    """Base protocol class. Not to be instantiated; classmethods only.

    Attributes:
      LABEL: str, label used in `Object.source_protocol`
    """
    LABEL = None

    def __init__(self):
        assert False

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

        Returns:
          True if the activity was sent successfully, False if it was discarded
          or ignored due to protocol logic, ie not network or other failures

        Raises:
          :class:`werkzeug.HTTPException` if the request fails
        """
        raise NotImplementedError()

    @classmethod
    def fetch(cls, obj):
        """Fetches a protocol-specific object and returns it in an :class:`Object`.

        To be implemented by subclasses. The returned :class:`Object` is loaded
        from the datastore, if it exists there, then updated in memory but not
        yet written back to the datastore.

        Args:
          obj: :class:`Object` with the id to fetch. Data is filled into one of
            the protocol-specific properties, eg as2, mf2, bsky.

        Raises:
          :class:`werkzeug.HTTPException` if the fetch fails
        """
        raise NotImplementedError()

    @classmethod
    def serve(cls, obj):
        """Returns this protocol's Flask response for a given :class:`Object`.

        For example, an HTML string and `'text/html'` for :class:`Web`,
        or a dict with AS2 JSON and `'application/activity+json'` for
        :class:`ActivityPub.

        To be implemented by subclasses.

        Args:
          obj: :class:`Object`

        Returns:
          (response body, dict with HTTP headers) tuple appropriate to be
          returned from a Flask handler
        """
        raise NotImplementedError()

    @classmethod
    def receive(cls, id, **props):
        """Handles an incoming activity.

        Args:
          id: str, activity id
          props: property values to populate into the :class:`Object`

        Returns:
          (response body, HTTP status code) tuple for Flask response

        Raises:
          :class:`werkzeug.HTTPException` if the request is invalid
        """
        if not id:
            error('Activity has no id')

        # short circuit if we've already seen this activity id
        with seen_ids_lock:
            already_seen = id in seen_ids
            seen_ids[id] = True
            if already_seen or Object.get_by_id(id):
                msg = f'Already handled this activity {id}'
                logger.info(msg)
                return msg, 200

        obj = Object.get_or_insert(id)
        obj.clear()
        obj.populate(source_protocol=cls.LABEL, **props)
        obj.put()

        logger.info(f'Got AS1: {json_dumps(obj.as1, indent=2)}')

        if obj.type not in SUPPORTED_TYPES:
            error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

        # store inner object
        inner_obj = as1.get_object(obj.as1)
        inner_obj_id = inner_obj.get('id')
        if obj.type in ('post', 'create', 'update') and inner_obj.keys() > set(['id']):
            to_update = (Object.get_by_id(inner_obj_id)
                         or Object(id=inner_obj_id))
            to_update.populate(as2=obj.as2['object'], source_protocol=cls.LABEL)
            to_update.put()

        actor = as1.get_object(obj.as1, 'actor')
        actor_id = actor.get('id')

        # handle activity!
        if obj.type == 'accept':  # eg in response to a Follow
            return 'OK'  # noop

        elif obj.type == 'stop-following':
            if not actor_id or not inner_obj_id:
                error(f'Undo of Follow requires actor id and object id. Got: {actor_id} {inner_obj_id} {obj.as1}')

            # deactivate Follower
            # TODO(#512): generalize across protocols
            # TODO(#512): merge Protocol and User
            followee_domain = util.domain_from_link(inner_obj_id, minimize=False)
            from web import Web
            follower = Follower.query(
                Follower.to == Web(id=followee_domain).key,
                Follower.from_ == cls(id=actor_id).key,
                Follower.status == 'active').get()
            if follower:
                logger.info(f'Marking {follower} inactive')
                follower.status = 'inactive'
                follower.put()
            else:
                logger.warning(f'No Follower found for {followee_domain} {actor_id}')

            # TODO send webmention with 410 of u-follow

            obj.status = 'complete'
            obj.put()
            return 'OK'

        elif obj.type == 'update':
            if not inner_obj_id:
                error("Couldn't find id of object to update")

            obj.status = 'complete'
            obj.put()
            return 'OK'

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
            # TODO(#512): generalize across protocols
            logger.info(f'Deactivating Followers from or to = {inner_obj_id}')
            from activitypub import ActivityPub
            deleted_user = ActivityPub(id=inner_obj_id).key
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
            actor = obj.as2['actor'] = cls.load(actor['id']).as2

        # fetch object if necessary so we can render it in feeds
        if obj.type == 'share' and inner_obj.keys() == set(['id']):
            inner_obj = obj.as2['object'] = as2.from_as1(
                cls.load(inner_obj_id).as1)

        if obj.type == 'follow':
            cls.accept_follow(obj)

        # deliver to each target
        cls.deliver(obj)

        # deliver original posts and reposts to followers
        is_reply = (obj.type == 'comment' or
                    (inner_obj and inner_obj.get('inReplyTo')))
        if (actor and actor_id and
            (obj.type == 'share' or obj.type in ('create', 'post') and not is_reply)):
            logger.info(f'Delivering to followers of {actor_id}')
            from activitypub import ActivityPub
            for f in Follower.query(Follower.to == ActivityPub(id=actor_id).key,
                                    Follower.status == 'active'):
                if f.from_ not in obj.users:
                    obj.users.append(f.from_)
            if obj.users and 'feed' not in obj.labels:
                obj.labels.append('feed')

        obj.put()
        return 'OK'

    @classmethod
    def accept_follow(cls, obj):
        """Replies to an AP Follow request with an Accept request.

        Args:
          obj: :class:`Object`, follow activity
        """
        logger.info('Replying to Follow with Accept')

        followee = as1.get_object(obj.as1)
        followee_id = followee.get('id')
        follower = as1.get_object(obj.as1, 'actor')
        if not followee or not followee_id or not follower:
            error(f'Follow activity requires object and actor. Got: {obj.as1}')

        inbox = follower.get('inbox')
        follower_id = follower.get('id')
        if not inbox or not follower_id:
            error(f'Follow actor requires id and inbox. Got: {follower}')

        # store Follower and follower ActivityPub user.
        #
        # If followee user is already direct, AP follower may not know they're
        # interacting with a bridge. If followee user is indirect though, AP
        # follower should know, so they're direct.
        #
        # TODO(#512): generalize across protocols
        from activitypub import ActivityPub
        from_ = ActivityPub.get_or_create(id=follower_id,
                                          actor_as2=as2.from_as1(follower),
                                          direct=not g.user.direct)
        follower_obj = Follower.get_or_create(to=g.user, from_=from_, follow=obj.key,
                                              status='active')

        # send Accept
        followee_actor_url = g.user.ap_actor()
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': common.host_url(f'/web/{g.user.key.id()}/followers#accept-{obj.key.id()}'),
            'type': 'Accept',
            'actor': followee_actor_url,
            'object': as2.from_as1(obj.as1),
        }
        return cls.send(Object(as2=accept), inbox)

    @classmethod
    def deliver(cls, obj):
        """Delivers an activity to its external recipients.

        Args:
          obj: :class:`Object`, activity to deliver
        """
        # extract source and targets
        source = obj.as1.get('url') or obj.as1.get('id')
        inner_obj = as1.get_object(obj.as1)
        obj_url = util.get_url(inner_obj) or inner_obj.get('id')

        if not source or obj.type in ('create', 'post', 'update'):
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

        targets = util.dedupe_urls(util.get_url(t) for t in targets)
        targets = common.remove_blocklisted(t.lower() for t in targets)
        if not targets:
            logger.info("Couldn't find any IndieWeb target URLs in inReplyTo, object, or mention tags")
            return

        logger.info(f'targets: {targets}')

        # send webmentions and update Object
        errors = []  # stores (code, body) tuples
        targets = [Target(uri=uri, protocol='web') for uri in targets]
        no_user_domains = set()

        obj.populate(
          undelivered=targets,
          status='in progress',
        )

        while obj.undelivered:
            target = obj.undelivered.pop()
            domain = util.domain_from_link(target.uri, minimize=False)
            if g.user and domain == g.user.key.id():
                if 'notification' not in obj.labels:
                    obj.labels.append('notification')

            if domain == util.domain_from_link(source, minimize=False):
                logger.info(f'Skipping same-domain webmention from {source} to {target.uri}')
                continue

            # only deliver if we have a matching User already.
            # TODO: consider delivering or at least storing Users for all
            # targets? need to filter out native targets in this protocol
            # though, eg mastodon.social targets in AP inbox deliveries.
            if domain in no_user_domains:
                continue

            # TODO(#512): generalize protocol
            from web import Web
            recip = Web(id=domain).key
            if recip not in obj.users:
                if not recip.get():
                    logger.info(f'No Web user for {domain}; skipping {target.uri}')
                    no_user_domains.add(domain)
                    continue
                obj.users.append(recip)

            try:
                # TODO(#512): generalize protocol
                if Web.send(obj, target.uri):
                    obj.delivered.append(target)
                    if 'notification' not in obj.labels:
                        obj.labels.append('notification')
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
    def load(cls, id, refresh=False, **kwargs):
        """Loads and returns an Object from memory cache, datastore, or HTTP fetch.

        Assumes id is a URL. Any fragment at the end is stripped before loading.
        This is currently underspecified and somewhat inconsistent across AP
        implementations:

        https://socialhub.activitypub.rocks/t/problems-posting-to-mastodon-inbox/801/11
        https://socialhub.activitypub.rocks/t/problems-posting-to-mastodon-inbox/801/23
        https://socialhub.activitypub.rocks/t/s2s-create-activity/1647/5
        https://github.com/mastodon/mastodon/issues/13879 (open!)
        https://github.com/w3c/activitypub/issues/224

        Note that :meth:`Object._post_put_hook` updates the cache.

        Args:
          id: str
          refresh: boolean, whether to fetch the object remotely even if we have
            it stored
          kwargs: passed through to fetch()

        Returns: :class:`Object`

        Raises:
          :class:`requests.HTTPError`, anything else that :meth:`fetch` raises
        """
        if not refresh:
            with objects_cache_lock:
                cached = objects_cache.get(id)
                if cached:
                    return cached

        logger.info(f'Loading Object {id}')
        orig_as1 = None
        obj = Object.get_by_id(id)
        if obj and (obj.as1 or obj.deleted):
            logger.info('  got from datastore')
            obj.new = False
            orig_as1 = obj.as1
            if not refresh:
                with objects_cache_lock:
                    objects_cache[id] = obj
                return obj

        if refresh:
            logger.info('  forced refresh requested')

        if obj:
            obj.clear()
            obj.new = False
        else:
            logger.info(f'  not in datastore')
            obj = Object(id=id)
            obj.new = True
            obj.changed = False

        cls.fetch(obj, **kwargs)
        if not obj.new:
            if orig_as1 and obj.as1:
                obj.changed = as1.activity_changed(orig_as1, obj.as1)
            else:
                obj.changed = bool(orig_as1) != bool(obj.as1)

        obj.source_protocol = cls.LABEL
        obj.put()

        with objects_cache_lock:
            objects_cache[id] = obj
        return obj
