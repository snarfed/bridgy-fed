# coding=utf-8
"""Unit tests for models.py."""
from unittest import mock

from oauth_dropins.webutil.testutil import requests_response

from app import app
from models import User, Activity
from . import testutil


class UserTest(testutil.TestCase):

    def setUp(self):
        super(UserTest, self).setUp()
        self.user = User.get_or_create('y.z')

    def test_magic_key_get_or_create(self):
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

    @mock.patch('requests.get')
    def test_verify(self, mock_get):
        self.assertFalse(self.user.has_redirects)
        self.assertFalse(self.user.has_hcard)

        def check(redirects, hcard):
            with app.test_request_context('/'):
                self.user.verify()
            with self.subTest(redirects=redirects, hcard=hcard):
                self.assertEqual(redirects, bool(self.user.has_redirects))
                self.assertEqual(hcard, bool(self.user.has_hcard))

        # both fail
        empty = requests_response('')
        mock_get.side_effect = [empty, empty]
        check(False, False)

        # redirect works but strips query params, no h-card
        half_redir = requests_response(
            status=302, redirected_url='http://localhost/.well-known/webfinger')
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [half_redir, no_hcard]
        check(False, False)

        # redirect works, non-representative h-card
        full_redir = requests_response(
            status=302, allow_redirects=False,
            redirected_url='http://localhost/.well-known/webfinger?resource=acct:y.z@y.z')
        bad_hcard = requests_response(
            '<html><body><a class="h-card u-url" href="https://a.b/">me</a></body></html>',
            url='https://y.z/',
        )
        mock_get.side_effect = [full_redir, bad_hcard]
        check(True, False)

        # both work
        hcard = requests_response(
            '<html><body><a class="h-card u-url" href="/">me</a></body></html>',
            url='https://y.z/',
        )
        mock_get.side_effect = [full_redir, hcard]
        check(True, True)


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
