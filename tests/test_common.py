"""Unit tests for common.py."""
# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitEnableFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub
from atproto import ATProto
import common
from arroba.datastore_storage import AtpBlock
from flask_app import app
from models import Follower, Object
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
<span class="logo" title="Web">🌐</span>
<a class="h-card u-author" href="/web/user.com" title="user.com">
  user.com
</a>""", common.pretty_link('https://user.com/', user=Web(id='user.com')),
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

    def test_global_cache_policy(self):
        for good in (
            ATProto(id='alice'),
            ActivityPub(id='alice'),
            Web(id='alice'),
            Object(id='https://mastodon.social/users/alice'),
            Object(id='https://mastodon.social/users/alice#main-key'),
            Object(id='did:plc:foo'),
            Object(id='did:web:foo.com'),
            Object(id='at://did:plc:user/app.bsky.actor.profile/self'),
        ):
            self.assertTrue(common.global_cache_policy(good.key._key))

        for bad in (
            Follower(id='abc'),
            Object(id='abc'),
            Object(id='https://mastodon.social/users/alice/statuses/123'),
            Object(id='at://did:plc:user/app.bsky.feed.post/abc'),
            Object(id='https://web.site/post'),
            AtpBlock(id='abc123'),
        ):
            self.assertFalse(common.global_cache_policy(bad.key._key))
