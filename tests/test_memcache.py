"""Unit tests for memcache.py."""
from unittest.mock import patch

from google.cloud.ndb import Key
from oauth_dropins.webutil.testutil import NOW
from oauth_dropins.webutil import util

import common
import memcache
from memcache import memoize, pickle_memcache
from models import Object, User
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
        self.assertEqual(0, len(pickle_memcache._contents))

        self.assertEqual('5', foo(5))
        self.assertEqual([5, 5], calls)
        self.assertEqual(0, len(pickle_memcache._contents))

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

    def test_get_notifications_empty(self):
        user = self.make_user(id='fake:user', cls=Fake)
        self.assertEqual([], memcache.get_notifications(user))

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_new_key(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.add_notification(user, Object(id='http://reply'))

        self.assertEqual(['http://reply'], memcache.get_notifications(user))
        self.assertEqual(b'http://reply', memcache.memcache.get('notifs-fake:user'))

        delayed_eta = (util.to_utc_timestamp(NOW) +
                       memcache.NOTIFY_TASK_FREQ.total_seconds())
        self.assert_task(mock_create_task, 'notify', delayed_eta, user_id='fake:user',
                         protocol='fake')

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_requires_web_url(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.add_notification(user, Object(id='efake:reply'))

        self.assertEqual([], memcache.get_notifications(user))
        self.assertIsNone(memcache.memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_for_user_with_send_notifs_none_is_noop(
            self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake, send_notifs='none')

        memcache.add_notification(user, Object(id='http://reply'))

        self.assertEqual([], memcache.get_notifications(user))
        self.assertIsNone(memcache.memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_append_to_existing(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.memcache.set('notifs-fake:user', 'http://reply0')
        memcache.add_notification(user, Object(id='r1', our_as1={'url': 'http://r1'}))
        memcache.add_notification(user, Object(id='http://reply2'))

        self.assertEqual(['http://reply0', 'http://r1', 'http://reply2'],
                         memcache.get_notifications(user))
        self.assertEqual(b'http://reply0 http://r1 http://reply2',
                         memcache.memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_deduplicate(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.add_notification(user, Object(id='http://reply'))
        memcache.add_notification(user, Object(id='http://reply'))

        self.assertEqual(['http://reply'], memcache.get_notifications(user))
        self.assertEqual(b'http://reply', memcache.memcache.get('notifs-fake:user'))

        delayed_eta = (util.to_utc_timestamp(NOW) +
                       memcache.NOTIFY_TASK_FREQ.total_seconds())
        self.assert_task(mock_create_task, 'notify', delayed_eta, user_id='fake:user',
                         protocol='fake')

    # mock get to say there's nothing in the cache, and cas to say someone changed it
    # since the get. should then append.
    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    @patch.object(memcache.memcache, 'gets', return_value=(None, b'towkin'))
    @patch.object(memcache.memcache, 'cas', return_value=False)
    def test_add_notification_cas_failure(self, mock_cas, mock_get, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.memcache.set('notifs-fake:user', b'http://existing')

        memcache.add_notification(user, Object(id='http://reply'))

        # should get the new value and append
        self.assertEqual(['http://existing', 'http://reply'],
                         memcache.get_notifications(user))
        self.assertEqual(b'http://existing http://reply',
                         memcache.memcache.get('notifs-fake:user'))

        mock_get.assert_called_with(b'notifs-fake:user')
        mock_cas.assert_called_with(b'notifs-fake:user', b'http://reply', b'towkin')
        mock_create_task.assert_not_called()
