# coding=utf-8
"""Unit tests for models.py."""
from unittest import mock

from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app
from models import User, Activity
from . import testutil


class UserTest(testutil.TestCase):

    def setUp(self):
        super(UserTest, self).setUp()
        self.user = User.get_or_create('y.z')

    def test_get_or_create(self):
        assert self.user.mod
        assert self.user.public_exponent
        assert self.user.private_exponent

        same = User.get_or_create('y.z')
        self.assertEqual(same, self.user)

    def test_href(self):
        href = self.user.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(self.user.mod, href)
        self.assertIn(self.user.public_exponent, href)

    def test_public_pem(self):
        pem = self.user.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)

    def test_private_pem(self):
        pem = self.user.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)

    def test_address(self):
        self.assertEqual('@y.z@y.z', self.user.address())

        self.user.actor_as2 = '{"type": "Person"}'
        self.assertEqual('@y.z@y.z', self.user.address())

        self.user.actor_as2 = '{"url": "http://foo"}'
        self.assertEqual('@y.z@y.z', self.user.address())

        self.user.actor_as2 = '{"urls": ["http://foo", "acct:bar@foo", "acct:baz@y.z"]}'
        self.assertEqual('@baz@y.z', self.user.address())

    @mock.patch('requests.get')
    def test_verify(self, mock_get):
        self.assertFalse(self.user.has_redirects)
        self.assertFalse(self.user.has_hcard)

        def check(redirects, hcard, actor, redirects_error=None):
            with app.test_request_context('/'):
                self.user.verify()
            with self.subTest(redirects=redirects, hcard=hcard, actor=actor,
                              redirects_error=redirects_error):
                self.assert_equals(redirects, bool(self.user.has_redirects))
                self.assert_equals(hcard, bool(self.user.has_hcard))
                if actor is None:
                    self.assertIsNone(self.user.actor_as2)
                else:
                    got = {k: v for k, v in json_loads(self.user.actor_as2).items()
                           if k in actor}
                    self.assert_equals(actor, got)
                self.assert_equals(redirects_error, self.user.redirects_error)

        # both fail
        empty = requests_response('', allow_redirects=False)
        mock_get.side_effect = [empty, empty]
        check(False, False, None)

        # redirect strips query params, no h-card
        half_redir = requests_response(
            status=302, redirected_url='http://localhost/.well-known/webfinger',
            allow_redirects=False)
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [half_redir, no_hcard]
        check(False, False, None, """\
Current vs expected:<pre>- http://localhost/.well-known/webfinger
+ https://fed.brid.gy/.well-known/webfinger?resource=acct:y.z@y.z</pre>""")

        # redirect works, non-representative h-card
        full_redir = requests_response(
            status=302, allow_redirects=False,
            redirected_url='http://localhost/.well-known/webfinger?resource=acct:y.z@y.z')
        bad_hcard = requests_response(
            '<html><body><a class="h-card u-url" href="https://a.b/">acct:me@y.z</a></body></html>',
            url='https://y.z/', allow_redirects=False,
        )
        mock_get.side_effect = [full_redir, bad_hcard]
        check(True, False, None)

        # both work
        hcard = requests_response("""
<html><body class="h-card">
  <a class="u-url p-name" href="/">me</a>
  <a class="u-url" href="acct:myself@y.z">Masto</a>
</body></html>""",
            url='https://y.z/', allow_redirects=False,
        )
        mock_get.side_effect = [full_redir, hcard]
        check(True, True, {
            'type': 'Person',
            'name': 'me',
            'url': 'http://localhost/r/https://y.z/',
            'preferredUsername': 'y.z',
        })

        # reset
        mock_get.side_effect = [empty, empty]
        check(False, False, None)


class ActivityTest(testutil.TestCase):

    def test_constructor(self):
        activity = Activity('abc', 'xyz')
        self.assertEqual('abc xyz', activity.key.id())

        activity = Activity('abc#1', 'xyz#Z')
        self.assertEqual('abc__1 xyz__Z', activity.key.id())

    def test_get_or_create(self):
        activity = Activity.get_or_create('abc', 'xyz')
        self.assertEqual('abc xyz', activity.key.id())

        activity = Activity.get_or_create('abc#1', 'xyz#Z')
        self.assertEqual('abc__1 xyz__Z', activity.key.id())

    def test_proxy_url(self):
        with app.test_request_context('/'):
            activity = Activity.get_or_create('abc', 'xyz')
            self.assertIsNone(activity.proxy_url())

            activity.source_as2 = 'as2'
            self.assertEqual('http://localhost/render?source=abc&target=xyz',
                             activity.proxy_url())
