"""Unit tests for actor.py."""
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from app import xrpc_server
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
        }, xrpc_server.call('app.bsky.actor.getProfile', {}, actor='foo.com'))

    def test_getProfile_not_domain(self, _):
        with self.assertRaises(ValueError):
            xrpc_server.call('app.bsky.actor.getProfile', {}, actor='not a domain')
