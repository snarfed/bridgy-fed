"""Unit tests for actor.py."""
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from . import testutil


@patch('requests.get')
class ActorTest(testutil.TestCase):

    def test_getProfile(self, mock_get):
        mock_get.return_value = requests_response("""
<body class="h-card">
<a class="u-url p-name" rel="me" href="/about-me">Mrs. ☕ Foo</a>
<img class="u-photo" src="/me.jpg" />
<img class="u-featured" src="/header.png" />
<span class="u-summary">I'm a person</span>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getProfile',
                              query_string={'actor': 'foo.com'},
                              ).json
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
        }, got)

    def test_getProfile_not_domain(self, _):
        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getSuggestions(self, _):
        got = self.client.get('/xrpc/app.bsky.actor.getSuggestions').json
        self.assertEqual({
            'actors': [],
        }, got)

    def test_search(self, _):
        got = self.client.get('/xrpc/app.bsky.actor.search',
                              query_string={'term': 'foo'}).json
        self.assertEqual({
            'users': [],
        }, got)

    def test_searchTypeahead(self, _):
        got = self.client.get('/xrpc/app.bsky.actor.searchTypeahead',
                              query_string={'term': 'foo'}).json
        self.assertEqual({
            'users': [],
        }, got)
