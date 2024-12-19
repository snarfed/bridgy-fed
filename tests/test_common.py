"""Unit tests for common.py."""
from unittest.mock import Mock, patch

import flask
from google.cloud.ndb import Key
from granary import as2
from oauth_dropins.webutil.appengine_config import error_reporting_client

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
from atproto import ATProto
import common
from arroba.datastore_storage import AtpBlock
from flask_app import app
from models import Follower, Object, Target
from ui import UIProtocol
from web import Web


class CommonTest(TestCase):

    def test_pretty_link(self):
        for expected, url, text in (
                ('href="http://foo">bar</a>', 'http://foo', 'bar'),
                ('href="http://x.y/@z">@z@x.y</a>', 'http://x.y/@z', None),
                ('href="http://x.y/@z">foo</a>', 'http://x.y/@z', 'foo'),
                ('href="http://x.y/users/z">@z@x.y</a>', 'http://x.y/users/z', None),
                ('href="http://x.y/users/z">foo</a>', 'http://x.y/users/z', 'foo'),
                ('href="http://x.y/@z/123">x.y/@z/123</a>', 'http://x.y/@z/123', None),
        ):
            self.assertIn(expected, common.pretty_link(url, text=text))

        self.assertEqual('<a href="http://foo">foo</a>',
                         common.pretty_link('http://foo'))

        # current user's homepage gets converted to BF user page
        self.assert_multiline_equals("""\
<span class="logo" title="Web">🌐</span> <a class="h-card u-author" rel="me" href="https://user.com/" title="user.com">user.com</a>""", common.pretty_link('https://user.com/', user=Web(id='user.com')),
        ignore_blanks=True)

    def test_redirect_wrap_empty(self):
        self.assertIsNone(common.redirect_wrap(None))
        self.assertEqual('', common.redirect_wrap(''))

    def test_redirect_wrap(self):
        self.assertEqual('http://localhost/r/http://foo',
                         common.redirect_wrap('http://foo'))

    def test_redirect_noop(self):
        self.assertEqual('http://ap.brid.gy/r/http://foo',
                         common.redirect_wrap('http://ap.brid.gy/r/http://foo'))

    def test_unwrap_empty(self):
        self.assertIsNone(common.unwrap(None))
        for obj in '', {}, []:
            self.assertEqual(obj, common.unwrap(obj))

    def test_subdomain_wrap(self):
        self.assertEqual('https://fa.brid.gy/',
                         common.subdomain_wrap(Fake))
        self.assertEqual('https://fa.brid.gy/foo?bar',
                         common.subdomain_wrap(Fake, 'foo?bar'))
        self.assertEqual('https://fed.brid.gy/',
                         common.subdomain_wrap(UIProtocol))

    def test_unwrap_protocol_subdomain(self):
        for input, expected in [
                ('https://fa.brid.gy/ap/fake:foo', 'fake:foo'),
                ('https://bsky.brid.gy/convert/ap/did:plc:123', 'did:plc:123'),
                # preserve protocol bot user ids
                ('https://fed.brid.gy/', 'https://fed.brid.gy/'),
                ('https://fa.brid.gy/', 'https://fa.brid.gy/'),
                ('fa.brid.gy', 'fa.brid.gy'),
        ]:
            self.assertEqual(expected, common.unwrap(input))

    def test_unwrap_protocol_subdomain_object(self):
        self.assert_equals(
            {'object': 'http://foo'},
            common.unwrap({'object': 'https://ap.brid.gy/r/http://foo',}))
        self.assert_equals(
            {'object': {'id': 'https://foo.com/'}},
            common.unwrap({'object': {'id': 'https://fa.brid.gy/foo.com'}}))

    def test_unwrap_local_actor_urls(self):
        self.assert_equals(
            {'object': 'https://foo.com/'},
            common.unwrap({'object': 'http://localhost/foo.com'}))

        self.assert_equals(
            {'object': {'id': 'https://foo.com/'}},
            common.unwrap({'object': {'id': 'http://localhost/foo.com'}}))

    def test_unwrap_int_id(self):
        self.assert_equals({'id': 3}, common.unwrap({'id': 3}))

    def test_host_url(self):
        with app.test_request_context():
            self.assertEqual('http://localhost/', common.host_url())
            self.assertEqual('http://localhost/asdf', common.host_url('asdf'))
            self.assertEqual('http://localhost/foo/bar', common.host_url('/foo/bar'))

        with app.test_request_context(base_url='https://a.xyz', path='/foo'):
            self.assertEqual('https://a.xyz/', common.host_url())
            self.assertEqual('https://a.xyz/asdf', common.host_url('asdf'))
            self.assertEqual('https://a.xyz/foo/bar', common.host_url('/foo/bar'))

        with app.test_request_context(base_url='http://bridgy-federated.uc.r.appspot.com'):
            self.assertEqual('https://fed.brid.gy/asdf', common.host_url('asdf'))

        with app.test_request_context(base_url='https://bsky.brid.gy', path='/foo'):
            self.assertEqual('https://bsky.brid.gy/asdf', common.host_url('asdf'))

    def test_cache_policy(self):
        for id in 'did:plc:foo', 'did:web:foo':
            self.assertTrue(common.cache_policy(Object(id=id).key))

        for obj in (
            ATProto(id='alice'),
            ActivityPub(id='alice'),
            Web(id='alice'),
            Object(id='https://mastodon.social/users/alice'),
            Object(id='at://did:plc:user/app.bsky.actor.profile/self'),
            Follower(id='abc'),
        ):
            self.assertFalse(common.cache_policy(obj.key))

    def test_global_cache_timeout_policy(self):
        for good in (
            ATProto(id='alice'),
            ActivityPub(id='alice'),
            Web(id='alice'),
            Object(id='https://mastodon.social/users/alice'),
            Object(id='https://mastodon.social/users/alice#main-key'),
            Object(id='did:plc:foo'),
            Object(id='did:web:foo.com'),
            Object(id='at://did:plc:user/app.bsky.actor.profile/self'),
            Follower(id='abc'),
        ):
            self.assertEqual(7200, common.global_cache_timeout_policy(good.key._key))

        for bad in (
            Object(id='abc'),
            Object(id='https://mastodon.social/users/alice/statuses/123'),
            Object(id='at://did:plc:user/app.bsky.feed.post/abc'),
            Object(id='https://web.site/post'),
            AtpBlock(id='abc123'),
        ):
            self.assertEqual(1800, common.global_cache_timeout_policy(bad.key._key))

    @patch('common.DEBUG', new=False)
    @patch('common.error_reporting_client')
    def test_report_error_no_request_context(self, mock_client):
        mock_client.report = Mock(name='report_error')

        self.request_context.pop()
        assert not flask.has_request_context()

        try:
            common.report_error('foo', bar='baz')
        finally:
            self.request_context.push()

        mock_client.report.assert_called_with('foo', http_context=None, bar='baz')

    @patch('common.MEMCACHE_KEY_MAX_LEN', new=10)
    def test_memcache_key(self):
        for input, expected in (
                ('foo', b'foo'),
                ('foo-bar-baz', b'foo-bar-ba'),
                ('foo bar', b'foo%20bar'),
                ('☃.net', b'\xe2\x98\x83.net'),
        ):
            self.assertEqual(expected, common.memcache_key(input))

    def test_memcache_memoize_int(self):
        calls = []

        @common.memcache_memoize()
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

    def test_memcache_memoize_str(self):
        calls = []

        @common.memcache_memoize()
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('1', foo(1))
        self.assertEqual([1], calls)
        self.assertEqual('1', foo(1))
        self.assertEqual([1], calls)

    def test_memcache_memoize_Key(self):
        calls = []

        @common.memcache_memoize()
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

    def test_memcache_memoize_None(self):
        calls = []

        @common.memcache_memoize()
        def foo(x):
            calls.append(x)
            return None

        self.assertIsNone(foo('a'))
        self.assertEqual(['a'], calls)
        self.assertIsNone(foo('a'))
        self.assertEqual(['a'], calls)

    def test_memcache_memoize_key_fn(self):
        calls = []

        @common.memcache_memoize(key=lambda x: x + 1)
        def foo(x):
            calls.append(x)
            return str(x)

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

        self.assertIsNone(common.pickle_memcache.get(b'foo-2-(5,)-{}'))
        self.assertEqual('5', common.pickle_memcache.get('foo-2-(6,)-{}'))

        self.assertEqual('5', foo(5))
        self.assertEqual([5], calls)

    def test_as2_request_type(self):
        for accept, expected in (
                (as2.CONTENT_TYPE_LD_PROFILE, as2.CONTENT_TYPE_LD_PROFILE),
                (as2.CONTENT_TYPE_LD, as2.CONTENT_TYPE_LD_PROFILE),
                (as2.CONTENT_TYPE, as2.CONTENT_TYPE),
                # TODO: handle eventually; this should return non-None
                (CONNEG_HEADERS_AS2_HTML['Accept'], None),
                ('', None),
                ('*/*', None),
                ('text/html', None),
        ):
            with (self.subTest(accept=accept),
                  app.test_request_context('/', headers={'Accept': accept})):
                self.assertEqual(expected, common.as2_request_type())


    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_create_task_no_request_context(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        self.request_context.pop()
        common.create_task('foo')
        mock_create_task.assert_called()
