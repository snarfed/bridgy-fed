"""Unit tests for actor.py."""
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from . import testutil


@patch('requests.get')
class XrpcActorTest(testutil.TestCase):

    def test_getProfile(self, mock_get):
        mock_get.return_value = requests_response("""
<body class="h-card">
<a class="u-url p-name" rel="me" href="/about-me">Mrs. ☕ Foo</a>
<img class="u-photo" src="/me.jpg" />
<img class="u-featured" src="/header.png" />
<span class="u-summary">I'm a person</span>
</body>
""", url='https://foo.com/')

        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'handle': 'foo.com',
            'did': 'TODO',
            'creator': 'TODO (a DID)',
            'displayName': 'Mrs. ☕ Foo',
            'declaration': {
                'cid': 'TODO',
                'actorType': 'app.bsky.system.actorUser',
            },
            'description': "I'm a person",
            'avatar': 'https://foo.com/me.jpg',
            'banner': 'https://foo.com/header.png',
            'followersCount': 0,
            'followsCount': 0,
            'membersCount': 0,
            'postsCount': 0,
            'myState': {
                'follow': 'TODO',
                'member': 'TODO',
            },
        }, resp.json)

    def test_getProfile_not_domain(self, _):
        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getSuggestions(self, _):
        resp = self.client.get('/xrpc/app.bsky.actor.getSuggestions')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'actors': [],
        }, resp.json)

    def test_search(self, _):
        resp = self.client.get('/xrpc/app.bsky.actor.search',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'users': [],
        }, resp.json)

    def test_searchTypeahead(self, _):
        resp = self.client.get('/xrpc/app.bsky.actor.searchTypeahead',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'users': [],
        }, resp.json)
