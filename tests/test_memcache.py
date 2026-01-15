"""Unit tests for memcache.py."""
from datetime import timedelta
import time
from unittest.mock import patch

from google.cloud.ndb import Key

from arroba.datastore_storage import AtpRepo

import config
import memcache
from memcache import Lease, memoize, pickle_memcache
from models import get_original_user_key, Object, Target
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW, requests_response
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
            'https://fed.brid.gy/admin/memcache/evict',
            headers={'Authorization': config.SECRET_KEY},
            data={'key': key.urlsafe()},
        )])

    def test_evict_raw(self):
        memcache.memcache.add('foo', 'bar')
        self.assertEqual('bar', memcache.memcache.get('foo'))
        memcache.evict_raw('foo')
        self.assertIsNone(memcache.memcache.get('foo'))

    def test_task_eta(self):
        self.assertEqual(NOW, memcache.task_eta('receive', 'alice'))
        self.assertEqual(NOW.timestamp(),
                         memcache.memcache.get('task-delay-receive-alice'))

        delay = memcache.PER_USER_TASK_RATES['receive']
        delayed = NOW + delay
        self.assertEqual(delayed, memcache.task_eta('receive', 'alice'))
        self.assertEqual(delayed.timestamp(),
                         memcache.memcache.get('task-delay-receive-alice'))

        delayed_2x = delayed + delay
        self.assertEqual(delayed_2x, memcache.task_eta('receive', 'alice'))
        self.assertEqual(delayed_2x.timestamp(),
                         memcache.memcache.get('task-delay-receive-alice'))

    def test_task_eta_queue_not_rate_limited(self):
        self.assertIsNone(memcache.task_eta('send', 'alice'))
        self.assertIsNone(memcache.task_eta('send', 'alice'))
        self.assertIsNone(memcache.memcache.get('task-delay-send-alice'))

    def test_task_eta_memcache_in_past(self):
        memcache.memcache.set('task-delay-receive-alice', int(NOW.timestamp() - 100))

        self.assertEqual(NOW, memcache.task_eta('receive', 'alice'))
        self.assertEqual(NOW.timestamp(),
                         memcache.memcache.get('task-delay-receive-alice'))

    def test_task_eta_multiple_users(self):
        delay = memcache.PER_USER_TASK_RATES['receive']

        self.assertEqual(NOW, memcache.task_eta('receive', 'alice'))
        self.assertEqual(NOW, memcache.task_eta('receive', 'bob'))
        self.assertEqual(NOW + delay, memcache.task_eta('receive', 'bob'))
        self.assertEqual(NOW + delay + delay, memcache.task_eta('receive', 'bob'))
        self.assertEqual(NOW + delay, memcache.task_eta('receive', 'alice'))


@patch('memcache.time.sleep')
class LeaseTest(TestCase):
    def test_acquire_and_release(self, _):
        lease = Lease('kee')
        lease.acquire()
        self.assertAlmostEqual(NOW + timedelta(minutes=5), lease.expires_at,
                               delta=timedelta(seconds=1))
        self.assertEqual('locked', memcache.memcache.get('kee'))

        lease.release()
        self.assertIsNone(memcache.memcache.get('kee'))

    def test_context_manager(self, _):
        with Lease('kee') as lease:
            self.assertAlmostEqual(NOW + timedelta(minutes=5), lease.expires_at,
                                   delta=timedelta(seconds=1))
            self.assertEqual('locked', memcache.memcache.get('kee'))

        self.assertIsNone(memcache.memcache.get('kee'))

    def test_acquire_retry_succeeds(self, _):
        # another worker holds the lease
        memcache.memcache.add('kee', 'locked')

        # simulate expiration by deleting after first attempt
        original_add = memcache.memcache.add
        attempts = [0]
        def mock_add(key, value, **kwargs):
            attempts[0] += 1
            if attempts[0] > 1:  # second attempt
                memcache.memcache.delete('kee')
            return original_add(key, value, **kwargs)

        with patch.object(memcache.memcache, 'add', side_effect=mock_add):
            lease = Lease('kee', retries=2,
                          initial_retry_delay=timedelta(seconds=0.1))
            lease.acquire()

        self.assertIsNotNone(NOW, lease.expires_at)
        self.assertEqual('locked', memcache.memcache.get('kee'))
        lease.release()

    def test_acquire_retry_fails(self, _):
        # another worker holds the lease with long expiration
        memcache.memcache.add('kee', 'locked', expire=999)

        lease = Lease('kee', retries=2,
                      initial_retry_delay=timedelta(seconds=0.1))

        with self.assertRaises(RuntimeError) as ctx:
            lease.acquire()

        self.assertIn("couldn't acquire memcache lease kee after 3 attempts",
                      str(ctx.exception))
        self.assertIsNone(lease.expires_at)

    def test_release_without_acquire(self, _):
        lease = Lease('kee')
        with self.assertRaises(AssertionError):
            lease.release()

    def test_release_after_expiration(self, _):
        lease = Lease('kee', retries=1,
                      initial_retry_delay=timedelta(seconds=0.1))
        lease.acquire()

        # simulate expiration by setting expires_at far in the past
        lease.expires_at = NOW - timedelta(seconds=9999)

        # another worker could have acquired it
        memcache.memcache.set('kee', 'locked')

        lease.release()  # should not delete vals2's lease
        self.assertEqual('locked', memcache.memcache.get('kee'))
