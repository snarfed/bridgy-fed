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
# import module instead of individual classes to avoid circular import
import models
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
    def fetch(cls, id):
        """Fetches a protocol-specific object and returns it in an :class:`Object`.

        To be implemented by subclasses. The returned :class:`Object` is loaded
        from the datastore, if it exists there, then updated in memory but not
        yet written back to the datastore.

        Args:
          id: str, object's URL id

        Returns:
          obj: :class:`Object` with the fetched object

        Raises:
          :class:`werkzeug.HTTPException` if the fetch fails
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
            if already_seen or models.Object.get_by_id(id):
                msg = f'Already handled this activity {id}'
                logger.info(msg)
                return msg, 200

        obj = models.Object.get_or_insert(id)
        obj.clear()
        obj.populate(source_protocol=cls.LABEL, **props)
        obj.put()

        logging.info(f'Got AS1: {json_dumps(obj.as1, indent=2)}')

        if obj.type not in SUPPORTED_TYPES:
            error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

        # store inner object
        inner_obj = as1.get_object(obj.as1)
        inner_obj_id = inner_obj.get('id')
        if obj.type in ('post', 'create', 'update') and inner_obj.keys() > set(['id']):
            to_update = (models.Object.get_by_id(inner_obj_id)
                         or models.Object(id=inner_obj_id))
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
            followee_domain = util.domain_from_link(inner_obj_id, minimize=False)
            follower = models.Follower.get_by_id(
                models.Follower._id(dest=followee_domain, src=actor_id))
            if follower:
                logging.info(f'Marking {follower} inactive')
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

            to_delete = models.Object.get_by_id(inner_obj_id)
            if to_delete:
                logger.info(f'Marking Object {inner_obj_id} deleted')
                to_delete.deleted = True
                to_delete.put()

            # assume this is an actor
            # https://github.com/snarfed/bridgy-fed/issues/63
            logger.info(f'Deactivating Followers with src or dest = {inner_obj_id}')
            followers = models.Follower.query(OR(models.Follower.src == inner_obj_id,
                                                 models.Follower.dest == inner_obj_id)
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
            for f in models.Follower.query(models.Follower.dest == actor_id,
                                    models.Follower.status == 'active',
                                    projection=[models.Follower.src]):
                if f.src not in obj.domains:
                    obj.domains.append(f.src)
            if obj.domains and 'feed' not in obj.labels:
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

        # store Follower
        follower_obj = models.Follower.get_or_create(
            dest=g.user.key.id(), src=follower_id, last_follow=obj.as2)
        follower_obj.status = 'active'
        follower_obj.put()

        # send AP Accept
        followee_actor_url = g.user.actor_id()
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': common.host_url(f'/user/{g.user.key.id()}/followers#accept-{obj.key.id()}'),
            'type': 'Accept',
            'actor': followee_actor_url,
            'object': {
                'type': 'Follow',
                'actor': follower_id,
                'object': followee_actor_url,
            }
        }
        return cls.send(models.Object(as2=accept), inbox)

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
        targets = [models.Target(uri=uri, protocol='webmention') for uri in targets]

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

            if domain not in obj.domains:
                obj.domains.append(domain)

            try:
                # TODO: fix
                from webmention import Webmention
                if Webmention.send(obj, target.uri):
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

        obj.status = ('complete' if obj.delivered or obj.domains
                      else 'failed' if obj.failed
                      else 'ignored')

        if errors:
            msg = 'Errors: ' + ', '.join(f'{code} {body}' for code, body in errors)
            error(msg, status=int(errors[0][0] or 502))

    @classmethod
    def load(cls, id):
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

        Returns: :class:`Object`

        Raises:
          :class:`requests.HTTPError`, anything else that :meth:`fetch` raises
        """
        id = util.fragmentless(id)

        with objects_cache_lock:
            cached = objects_cache.get(id)
            if cached:
                return cached

        logger.info(f'Loading Object {id}')
        obj = models.Object.get_by_id(id)
        if obj and (obj.as1 or obj.deleted):
            logger.info('  got from datastore')
            with objects_cache_lock:
                objects_cache[id] = obj
            return obj

        logger.info(f'Object not in datastore or has no data: {id}')
        obj = cls.fetch(id)
        obj.source_protocol = cls.LABEL
        obj.put()

        with objects_cache_lock:
            objects_cache[id] = obj
        return obj
