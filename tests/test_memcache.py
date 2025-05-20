"""Unit tests for memcache.py."""
from unittest.mock import patch

from google.cloud.ndb import Key

import memcache
from memcache import memoize, pickle_memcache, add_notification
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

    def test_add_notification_new_key(self):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='efake:reply', source_protocol='efake')

        add_notification(user, obj)

        result = memcache.memcache.get('notifs-fake:user')
        self.assertEqual(['efake:reply'], result)

    def test_add_notification_append_to_existing(self):
        user = self.make_user(id='fake:user', cls=Fake)
        obj1 = self.store_object(id='efake:reply1', source_protocol='efake')
        obj2 = self.store_object(id='efake:reply2', source_protocol='efake')

        add_notification(user, obj1)
        add_notification(user, obj2)

        result = memcache.memcache.get('notifs-fake:user')
        self.assertEqual(['efake:reply1', 'efake:reply2'], result)

    def test_add_notification_no_duplicates(self):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='efake:reply', source_protocol='efake')

        # add the same notification twice
        add_notification(user, obj)
        add_notification(user, obj)

        # should only appear once
        result = memcache.memcache.get('notifs-fake:user')
        self.assertEqual(['efake:reply'], result)

    def test_add_notification_cas_failure(self):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='efake:reply', source_protocol='efake')

        memcache.memcache.set('notifs-fake:user', ['existing:reply'])

        add_notification(user, obj)

        # should get the new value and append
        result = memcache.memcache.get('notifs-fake:user')
        self.assertEqual(['existing:reply', 'efake:reply'], result)
