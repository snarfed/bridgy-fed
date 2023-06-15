"""Unit tests for common.py."""
from unittest import mock

from flask import g
from granary import as2
from oauth_dropins.webutil import appengine_config, util
from oauth_dropins.webutil.testutil import requests_response
import requests

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

import common
from flask_app import app
from models import Object, User
import protocol
from web import Web


class CommonTest(TestCase):
    @classmethod
    def setUpClass(cls):
        with appengine_config.ndb_client.context():
            # do this in setUpClass since generating RSA keys is slow
            cls.user = cls.make_user('user.com')

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
        self.assertEqual(
            '<a class="h-card u-author" href="/web/user.com"><img src="" class="profile"> user.com</a>',
            common.pretty_link('https://user.com/'))

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
