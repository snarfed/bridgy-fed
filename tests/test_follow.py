"""Unit tests for follow.py.
"""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import requests_response

import common
from models import User
from . import testutil

WEBFINGER = requests_response({
    'subject': 'acct:foo@bar',
    'aliases': [
        'https://bar/foo',
    ],
    'links': [{
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'https://bar/follow?uri={uri}'
    }],
})

@patch('requests.get')
class FollowTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        User.get_or_create('me')

    def test_follow_no_domain(self, mock_get):
        got = self.client.post('/follow?address=@foo@bar')
        self.assertEqual(400, got.status_code)

    def test_follow_no_address(self, mock_get):
        got = self.client.post('/follow?domain=baz.com')
        self.assertEqual(400, got.status_code)

    def test_follow_no_user(self, mock_get):
        got = self.client.post('/follow?address=@foo@bar&domain=baz.com')
        self.assertEqual(400, got.status_code)

    def test_follow(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/follow?address=@foo@bar&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://bar/follow?uri=@me@me',
                         got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=acct:foo@bar'),
        ))

    def test_follow_url(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://bar/follow?uri=@me@me', got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=https://bar/foo'),
        ))

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response({
            'subject': 'acct:foo@bar',
            'links': [{'rel': 'other', 'template': 'meh'}],
        })

        got = self.client.post('/follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response(status_code=500)

        got = self.client.post('/follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response('<html>not json</html>')

        got = self.client.post('/follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])
