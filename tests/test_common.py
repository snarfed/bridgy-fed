"""Unit tests for common.py."""
from flask import g

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

import common
from flask_app import app
from web import Web


class CommonTest(TestCase):
    def setUp(self):
        super().setUp()
        g.user = Fake(id='user.com')

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
        g.user = Web(id='user.com')
        self.assert_multiline_equals("""\
<a class="h-card u-author" href="https://user.com/">
  <img src="" class="profile">
  <span class="logo" title="Web">🕸️</span>
  user.com
</a>""", common.pretty_link('https://user.com/'))

    def test_redirect_wrap_empty(self):
        self.assertIsNone(common.redirect_wrap(None))
        self.assertEqual('', common.redirect_wrap(''))

    def test_redirect_wrap(self):
        self.assertEqual('http://localhost/r/http://foo',
                         common.redirect_wrap('http://foo'))

    def test_redirect_noop(self):
        self.assertEqual('http://ap.brid.gy/r/http://foo',
                         common.redirect_wrap('http://ap.brid.gy/r/http://foo'))

    def test_redirect_unwrap_empty(self):
        self.assertIsNone(common.redirect_unwrap(None))
        for obj in '', {}, []:
            self.assertEqual(obj, common.redirect_unwrap(obj))

    def test_unwrap_protocol_subdomain(self):
        self.assert_equals({
            'type': 'Like',
            'object': 'http://foo',
        }, common.redirect_unwrap({
            'type': 'Like',
            'object': 'https://ap.brid.gy/r/http://foo',
        }))

    def test_unwrap_not_web(self):
        bad = {
            'type': 'Like',
            'object': 'http://localhost/r/foo bar',
        }
        self.assert_equals(bad, common.redirect_unwrap(bad))

    def test_unwrap_local_actor_urls(self):
        self.assert_equals(
            {'object': 'https://foo.com/'},
            common.redirect_unwrap({'object': 'http://localhost/foo.com'}))

        self.assert_equals(
            {'object': {'id': 'https://foo.com/'}},
            common.redirect_unwrap({'object': {'id': 'http://localhost/foo.com'}}))

    def test_unwrap_protocol_subdomains(self):
        self.assert_equals(
            {'object': 'http://foo.com/bar'},
            common.redirect_unwrap(
                {'object': 'https://atproto.brid.gy/r/http://foo.com/bar'}))

        self.assert_equals(
            {'object': {'id': 'https://foo.com/'}},
            common.redirect_unwrap(
                {'object': {'id': 'https://fa.brid.gy/foo.com'}}))

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

        with app.test_request_context(base_url='https://atproto.brid.gy', path='/foo'):
            self.assertEqual('https://atproto.brid.gy/asdf', common.host_url('asdf'))
