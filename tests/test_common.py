"""Unit tests for common.py."""
from unittest import mock

from granary import as2
from oauth_dropins.webutil import appengine_config, util
from oauth_dropins.webutil.testutil import requests_response
import requests

from app import app
import common
from models import Object, User
import protocol
from . import testutil


class CommonTest(testutil.TestCase):
    @classmethod
    def setUpClass(cls):
        with appengine_config.ndb_client.context():
            # do this in setUpClass since generating RSA keys is slow
            cls.user = User.get_or_create('site')

    def setUp(self):
        super().setUp()
        self.app_context = app.test_request_context('/')
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()
        super().tearDown()

    def test_pretty_link(self):
        for expected, url, text in (
                ('<a href="http://foo">bar</a>', 'http://foo', 'bar'),
                ('<a href="http://x.y/@z">@z@x.y</a>', 'http://x.y/@z', None),
                ('<a href="http://x.y/@z">foo</a>', 'http://x.y/@z', 'foo'),
                ('<a href="http://x.y/users/z">@z@x.y</a>', 'http://x.y/users/z', None),
                ('<a href="http://x.y/users/z">foo</a>', 'http://x.y/users/z', 'foo'),
                ('<a href="http://x.y/@z/123">x.y/@z/123</a>', 'http://x.y/@z/123', None),
        ):
            self.assertEqual(expected, common.pretty_link(url, text=text))

        self.assertEqual(
            '<a href="/user/site"><img src="" class="profile"> site</a>',
            common.pretty_link('https://site/', user=self.user))

    def test_redirect_wrap_empty(self):
        self.assertIsNone(common.redirect_wrap(None))
        self.assertEqual('', common.redirect_wrap(''))

    def test_redirect_unwrap_empty(self):
        self.assertIsNone(common.redirect_unwrap(None))
        for obj in '', {}, []:
            self.assertEqual(obj, common.redirect_unwrap(obj))

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
