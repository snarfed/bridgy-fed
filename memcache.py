"""Utilities for caching data in memcache.

TODO: move most or all of this to webutil?
"""
from datetime import datetime, timedelta, timezone
import functools
import logging
import os

import config
from google.cloud.ndb._cache import global_cache_key
from google.cloud.ndb.global_cache import _InProcessGlobalCache, MemcacheCache
from oauth_dropins.webutil import appengine_info, util
from pymemcache.client.base import PooledClient
from pymemcache.serde import PickleSerde
from pymemcache.test.utils import MockMemcacheClient

from domains import PRIMARY_DOMAIN

logger = logging.getLogger(__name__)

# https://github.com/memcached/memcached/wiki/Commands#standard-protocol
KEY_MAX_LEN = 250

MEMOIZE_VERSION = 2

# per-user rates for running tasks. rate limits and spreads out tasks for bursty
# users. values map protocol label to delay. None means all protocols.
# https://github.com/snarfed/bridgy-fed/issues/1788
PER_USER_TASK_RATES = {
    'receive': {
        None: timedelta(seconds=5),  # all protocols
    },
    'send': {
        'atproto': timedelta(seconds=20),
    },
}

# https://pymemcache.readthedocs.io/en/latest/apidoc/pymemcache.client.base.html#pymemcache.client.base.Client.__init__
kwargs = {
    'server': os.environ.get('MEMCACHE_HOST', 'localhost'),
    'allow_unicode_keys': True,
    'default_noreply': False,
    'timeout': 10,   # seconds
    'connect_timeout': 10,   # seconds
}

if appengine_info.DEBUG or appengine_info.LOCAL_SERVER:
    logger.info(f'Using in memory mock memcache: {kwargs}')
    memcache = PooledClient(max_pool_size=1, **kwargs)
    pickle_memcache = PooledClient(max_pool_size=1, serde=PickleSerde(), **kwargs)
    memcache.client_class = pickle_memcache.client_class = MockMemcacheClient
    global_cache = _InProcessGlobalCache()
else:
    logger.info(f'Using production Memorystore memcache: {kwargs}')
    memcache = PooledClient(**kwargs)
    pickle_memcache = PooledClient(serde=PickleSerde(), **kwargs)
    global_cache = MemcacheCache(memcache, strict_read=False, strict_write=False)


def key(key):
    """Preprocesses a memcache key. Right now just truncates it to 250 chars.

    https://pymemcache.readthedocs.io/en/latest/apidoc/pymemcache.client.base.html
    https://github.com/memcached/memcached/wiki/Commands#standard-protocol

    TODO: truncate to 250 *UTF-8* chars, to handle Unicode chars in URLs. Related:
    pymemcache Client's allow_unicode_keys constructor kwarg.

    Args:
      key (str)

    Returns:
      bytes:
    """
    assert isinstance(key, str), repr(key)
    return key.replace(' ', '%20').encode()[:KEY_MAX_LEN]


def memoize_key(fn, *args, _version=MEMOIZE_VERSION, **kwargs):
    return key(f'{fn.__qualname__}-{_version}-{repr(args)}-{repr(kwargs)}')


NONE = ()  # empty tuple

def memoize(expire=None, key=None, write=True, version=MEMOIZE_VERSION):
    """Memoize function decorator that stores the cached value in memcache.

    Args:
      expire (datetime.timedelta): optional, expiration
      key (callable): function that takes the function's ``(*args, **kwargs)``
        and returns the cache key to use. If it returns None, memcache won't be
        used.
      write (bool or callable): whether to write to memcache. If this is a
        callable, it will be called with the function's ``(*args, **kwargs)``
        and should return True or False.
      version (int): overrides our default version number in the memcache key.
        Bumping this version can have the same effect as clearing the cache for
        just the affected function.
    """
    expire = int(expire.total_seconds()) if expire else 0

    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            cache_key = None
            if key:
                key_val = key(*args, **kwargs)
                if key_val:
                    cache_key = memoize_key(fn, key_val, _version=version)
            else:
                cache_key = memoize_key(fn, *args, _version=version, **kwargs)

            if pickle_memcache and cache_key:
                val = pickle_memcache.get(cache_key)
                if val is not None:
                    logger.debug(f'cache hit {cache_key} {repr(val)[:100]}')
                    return None if val == NONE else val
                else:
                    logger.debug(f'cache miss {cache_key}')

            val = fn(*args, **kwargs)

            if pickle_memcache and cache_key:
                write_cache = (write if isinstance(write, bool)
                               else write(*args, **kwargs))
                if write_cache:
                    logger.debug(f'cache set {cache_key} {repr(val)[:100]}')
                    pickle_memcache.set(cache_key, NONE if val is None else val,
                                        expire=expire)

            return val

        return wrapped

    return decorator


def evict(entity_key):
    """Evict a datastore entity from memcache.

    For :class:`models.User` and :class:`models.Object` entities, also clears their
    copies from the :func:`models.get_original_user_key` and
    :func:`models.get_original_object_key` memoize caches.

    Args:
      entity_key (google.cloud.ndb.Key)
    """
    if entity := entity_key.get():
        for val in getattr(entity, 'copies', []):
            entity.clear_get_original_cache(val.uri)

    global_cache.delete([global_cache_key(entity_key._key)])


def evict_raw(key):
    """Evict a key from memcache.

    Args:
      key (str)

    Returns:
      bool: whether the key existed and was deleted
    """
    return memcache.delete(key)


def remote_evict(entity_key):
    """Send a request to production Bridgy Fed to evict an entity from memcache.

    Args:
      entity_key (google.cloud.ndb.Key)

    Returns:
      requests.Response:
    """
    return util.requests_post(f'https://{PRIMARY_DOMAIN}/admin/memcache/evict',
                              headers={'Authorization': config.SECRET_KEY},
                              data={'key': entity_key.urlsafe()})


def task_eta(queue, user_id, protocol=None):
    """Get the ETA to use for a given user's task in a given queue.

    Task rate limit delays are per user, stored in memcache with a key based on
    ``queue`` and ``user_id`` and an integer value of POSIX timestamp (UTC) in
    seconds.

    Only generates ETAs for task queues in :attr:`PER_USER_TASK_RATES`. Calls for
    other queues always return ``None``.

    Background: https://github.com/snarfed/bridgy-fed/issues/1788

    Args:
      queue (str)
      user_id (str)
      protocol (str): optional protocol label to look up protocol-specific delay

    Returns:
      datetime.datetime: the ETA for this task, or ``None`` if the ETA is now
    """
    if not (delays := PER_USER_TASK_RATES.get(queue)):
        return None

    # look up delay for protocol, fall back to None (all protocols)
    if not (delay := delays.get(protocol) or delays.get(None)):
        return None

    cache_key = key(f'task-delay-{queue}-{user_id}')

    now = util.now()
    if eta_s := memcache.incr(cache_key, int(delay.total_seconds())):
        eta = datetime.fromtimestamp(eta_s, timezone.utc)
        if eta > now:
            return eta

    # incr failed (key doesn't exist) or timestamp is in the past, set it to now
    #
    # note that this isn't synchronized; multiple callers may race and both get now
    # as the returned ETA. that's ok, we don't depend on this for correctness in any
    # way, just best-effort rate limiting.
    memcache.set(cache_key, int(now.timestamp()))
    return now


###########################################

# https://github.com/googleapis/python-ndb/issues/743#issuecomment-2067590945
#
# fixes "RuntimeError: Key has already been set in this batch" errors due to
# tasklets in pages.serve_feed
from logging import error as log_error
from sys import modules

from google.cloud.datastore_v1.types.entity import Key
from google.cloud.ndb._cache import (
    _GlobalCacheSetBatch,
    global_compare_and_swap,
    global_set_if_not_exists,
    global_watch,
)
from google.cloud.ndb.tasklets import Future, Return, tasklet

GLOBAL_CACHE_KEY_PREFIX: bytes = modules["google.cloud.ndb._cache"]._PREFIX
LOCKED_FOR_READ: bytes = modules["google.cloud.ndb._cache"]._LOCKED_FOR_READ
LOCK_TIME: bytes = modules["google.cloud.ndb._cache"]._LOCK_TIME


@tasklet
def custom_global_lock_for_read(key: str, value: str):
    if value is not None:
        yield global_watch(key, value)
        lock_acquired = yield global_compare_and_swap(
            key, LOCKED_FOR_READ, expires=LOCK_TIME
        )
    else:
        lock_acquired = yield global_set_if_not_exists(
            key, LOCKED_FOR_READ, expires=LOCK_TIME
        )

    if lock_acquired:
        raise Return(LOCKED_FOR_READ)

modules["google.cloud.ndb._cache"].global_lock_for_read = custom_global_lock_for_read
