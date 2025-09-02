"""Unit tests for memcache.py."""
from unittest.mock import patch

from google.cloud.ndb import Key

from arroba.datastore_storage import AtpRepo

import config
import memcache
from memcache import memoize, pickle_memcache
from models import get_original_user_key, Object, Target
from oauth_dropins.webutil.testutil import requests_response
from .testutil import Fake, TestCase


class MemcacheTest(TestCase):
    def test_memoize_int(self):
        calls = []

        @memoize()
        def foo(x, y, z=None):
            calls.append((x, y, z))
            return len(calls)

        self.assertEqual(1, foo(1, 'a', z=1))
        self.assertEqual([(1, 'a', 1)], calls)
        self.assertEqual(1, foo(1, 'a', z=1))
        self.assertEqual([(1, 'a', 1)], calls)

        self.assertEqual(2, foo(2, 'b', z=2))
        self.assertEqual([(1, 'a', 1), (2, 'b', 2)], calls)
        self.assertEqual(1, foo(1, 'a', z=1))
        self.assertEqual(2, foo(2, 'b', z=2))
        self.assertEqual([(1, 'a', 1), (2, 'b', 2)], calls)

    def test_memoize_str(self):
        calls = []

        @memoize()
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('1', foo(1))
        self.assertEqual([1], calls)
        self.assertEqual('1', foo(1))
        self.assertEqual([1], calls)

    def test_memoize_Key(self):
        calls = []

        @memoize()
        def foo(x):
            calls.append(x)
            return Key(Object, x)

        a = Key(Object, 'a')
        self.assertEqual(a, foo('a'))
        self.assertEqual(['a'], calls)
        self.assertEqual(a, foo('a'))
        self.assertEqual(['a'], calls)

        b = Key(Object, 'b')
        self.assertEqual(b, foo('b'))
        self.assertEqual(['a', 'b'], calls)
        self.assertEqual(a, foo('a'))
        self.assertEqual(['a', 'b'], calls)
        self.assertEqual(b, foo('b'))
        self.assertEqual(['a', 'b'], calls)

    def test_memoize_None(self):
        calls = []

        @memoize()
        def foo(x):
            calls.append(x)
            return None

        self.assertIsNone(foo('a'))
        self.assertEqual(['a'], calls)
        self.assertIsNone(foo('a'))
        self.assertEqual(['a'], calls)

    def test_memoize_key_fn(self):
        calls = []

        @memoize(key=lambda x: x + 1)
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

        self.assertIsNone(pickle_memcache.get(
            b'MemcacheTest.test_memoize_key_fn.<locals>.foo-2-(5,)-{}'))
        self.assertEqual('5', pickle_memcache.get(
            'MemcacheTest.test_memoize_key_fn.<locals>.foo-2-(6,)-{}'))

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

    def test_memoize_key_fn_returns_None(self):
        calls = []

        @memoize(key=lambda x: None)
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)
        self.assertEqual(0, len(pickle_memcache.client_pool.free))

        self.assertEqual('5', foo(5))
        self.assertEqual([5, 5], calls)
        self.assertEqual(0, len(pickle_memcache.client_pool.free))

    def test_memoize_write_false(self):
        calls = []

        @memoize(write=False)
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)
        self.assertIsNone(pickle_memcache.get(
            b'MemcacheTest.test_memoize_key_fn.<locals>.foo-2-(5,)-{}'))

        self.assertEqual('5', foo(5))
        self.assertEqual([5, 5], calls)
        self.assertIsNone(pickle_memcache.get(
            b'MemcacheTest.test_memoize_key_fn.<locals>.foo-2-(5,)-{}'))

    def test_memoize_write_callable(self):
        calls = []

        @memoize(write=lambda x: x == 5)
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

        self.assertEqual('6', foo(6))
        self.assertEqual([5, 6], calls)

        self.assertEqual('6', foo(6))
        self.assertEqual([5, 6, 6], calls)

    @patch('memcache.pickle_memcache', new=None)
    def test_memoize_no_memcache(self):
        calls = []

        @memoize()
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

        self.assertEqual('5', foo(5))
        self.assertEqual([5, 5], calls)

    def test_memoize_version_callable(self):
        calls = []

        @memoize(version='x')
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)
        self.assertEqual('5', pickle_memcache.get(
            b'MemcacheTest.test_memoize_version_callable.<locals>.foo-x-(5,)-{}'))

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

    @patch('memcache.KEY_MAX_LEN', new=10)
    def test_key(self):
        for input, expected in (
                ('foo', b'foo'),
                ('foo-bar-baz', b'foo-bar-ba'),
                ('foo bar123', b'foo%20bar1'),
                ('☃.net', b'\xe2\x98\x83.net'),
        ):
            self.assertEqual(expected, memcache.key(input))

    def test_evict(self):
        key = Fake(id='fake:foo').put()
        key.get()
        self.assertIsNotNone(key.get(use_cache=False, use_datastore=False,
                                     use_global_cache=True))

        memcache.evict(key)
        self.assertIsNone(key.get(use_cache=False, use_datastore=False,
                                  use_global_cache=True))

    def test_evict_model_without_copies(self):
        key = AtpRepo(id='did:plc:foo', head='x', signing_key_pem=b'y').put()
        key.get()
        self.assertIsNotNone(key.get(use_cache=False, use_datastore=False,
                                     use_global_cache=True))

        memcache.evict(key)
        self.assertIsNone(key.get(use_cache=False, use_datastore=False,
                                  use_global_cache=True))

    def test_evict_nonexistent_entity(self):
        memcache.evict(Key(Fake, 'fake:nope'))

    def test_evict_user_clears_copies_from_memoize(self):
        user = Fake(id='fake:foo', copies=[Target(protocol='other', uri='other:a'),
                                           Target(protocol='other', uri='other:b')])
        user.put()

        # populate the get_original_user_key memoize cache
        self.assertEqual(user.key, get_original_user_key('other:a'))
        self.assertEqual(user.key, get_original_user_key('other:b'))

        memcache.evict(user.key)
        get_original_user_key.cache_clear()
        user.key.delete()

        self.assertIsNone(get_original_user_key('other:a'))
        self.assertIsNone(get_original_user_key('other:b'))

    @patch('requests.post', return_value=requests_response())
    def test_remote_evict(self, mock_post):
        key = Fake(id='fake:foo').key
        memcache.remote_evict(key)
        mock_post.assert_has_calls([self.req(
            'https://fed.brid.gy/admin/memcache-evict',
            headers={'Authorization': config.SECRET_KEY},
            data={'key': key.urlsafe()},
        )])
