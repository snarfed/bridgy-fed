"""Utilities for caching data in memcache."""
import functools
import logging
import os

from google.cloud.ndb.global_cache import _InProcessGlobalCache, MemcacheCache
from oauth_dropins.webutil import appengine_info

from pymemcache.client.base import PooledClient
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
    memcache = PooledClient(os.environ['MEMCACHE_HOST'], allow_unicode_keys=True,
                            timeout=10, connect_timeout=10) # seconds
    pickle_memcache = PooledClient(os.environ['MEMCACHE_HOST'],
                                   serde=PickleSerde(), allow_unicode_keys=True,
                                   timeout=10, connect_timeout=10)  # seconds
    global_cache = MemcacheCache(memcache)


def key(key):
    """Preprocesses a memcache key. Right now just truncates it to 250 chars.

    https://pymemcache.readthedocs.io/en/latest/apidoc/pymemcache.client.base.html
    https://github.com/memcached/memcached/wiki/Commands#standard-protocol

    TODO: truncate to 250 *UTF-8* chars, to handle Unicode chars in URLs. Related:
    pymemcache Client's allow_unicode_keys constructor kwarg.
    """
    assert isinstance(key, str), repr(key)
    return key[:KEY_MAX_LEN].replace(' ', '%20').encode()


def memoize_key(fn, *args, **kwargs):
    return key(f'{fn.__name__}-2-{repr(args)}-{repr(kwargs)}')


NONE = ()  # empty tuple

def memoize(expire=None, key=None):
    """Memoize function decorator that stores the cached value in memcache.

    Args:
      expire (timedelta): optional, expiration
      key (callable): function that takes the function's (*args, **kwargs) and
        returns the cache key to use. If it returns None, memcache won't be used.
    """
    if expire:
        expire = int(expire.total_seconds())

    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            cache_key = None
            if key:
                key_val = key(*args, **kwargs)
                if key_val:
                    cache_key = memoize_key(fn, key_val)
            else:
                cache_key = memoize_key(fn, *args, **kwargs)

            if cache_key:
                val = pickle_memcache.get(cache_key)
                if val is not None:
                    logger.debug(f'cache hit {cache_key}')
                    return None if val == NONE else val
                else:
                    logger.debug(f'cache miss {cache_key}')

            val = fn(*args, **kwargs)

            if cache_key:
                pickle_memcache.set(cache_key, NONE if val is None else val,
                                    expire=expire)

            return val

        return wrapped

    return decorator
