"""Utilities for caching data in memcache."""
import functools
import logging

from google.cloud.ndb.global_cache import _InProcessGlobalCache, MemcacheCache
from oauth_dropins.webutil import appengine_info

import pymemcache.client.base
from pymemcache.serde import PickleSerde
from pymemcache.test.utils import MockMemcacheClient

logger = logging.getLogger(__name__)

# https://github.com/memcached/memcached/wiki/Commands#standard-protocol
KEY_MAX_LEN = 250


if appengine_info.DEBUG or appengine_info.LOCAL_SERVER:
    logger.info('Using in memory mock memcache')
    memcache = MockMemcacheClient(allow_unicode_keys=True)
    pickle_memcache = MockMemcacheClient(allow_unicode_keys=True, serde=PickleSerde())
    global_cache = _InProcessGlobalCache()
else:
    logger.info('Using production Memorystore memcache')
    memcache = pymemcache.client.base.PooledClient(
        os.environ['MEMCACHE_HOST'], timeout=10, connect_timeout=10,  # seconds
        allow_unicode_keys=True)
    pickle_memcache = pymemcache.client.base.PooledClient(
        os.environ['MEMCACHE_HOST'], timeout=10, connect_timeout=10,  # seconds
        serde=PickleSerde(), allow_unicode_keys=True)
    global_cache = MemcacheCache(memcache)


def key(key):
    """Preprocesses a memcache key. Right now just truncates it to 250 chars.

    https://pymemcache.readthedocs.io/en/latest/apidoc/pymemcache.client.base.html
    https://github.com/memcached/memcached/wiki/Commands#standard-protocol

    TODO: truncate to 250 *UTF-8* chars, to handle Unicode chars in URLs. Related:
    pymemcache Client's allow_unicode_keys constructor kwarg.
    """
    return key[:KEY_MAX_LEN].replace(' ', '%20').encode()


def memoize_key(fn, *args, **kwargs):
    return key(f'{fn.__name__}-2-{repr(args)}-{repr(kwargs)}')


NONE = ()  # empty tuple

def memoize(expire=None, key=None):
    """Memoize function decorator that stores the cached value in memcache.

    Args:
      expire (timedelta): optional, expiration
      key (callable): function that takes the function's (*args, **kwargs) and
        returns the cache key to use
    """
    if expire:
        expire = int(expire.total_seconds())

    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if key:
                cache_key = memoize_key(fn, key(*args, **kwargs))
            else:
                cache_key = memoize_key(fn, *args, **kwargs)

            val = pickle_memcache.get(cache_key)
            if val is not None:
                # logger.debug(f'cache hit {cache_key}')
                return None if val == NONE else val

            # logger.debug(f'cache miss {cache_key}')
            val = fn(*args, **kwargs)
            pickle_memcache.set(cache_key, NONE if val is None else val, expire=expire)
            return val

        return wrapped

    return decorator
