"""Unit tests for graph.py."""
import copy
from unittest.mock import patch

from granary import bluesky
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

from .test_activitypub import FOLLOW_WITH_ACTOR
from . import testutil
from models import Follower

ACTOR_DECLARATION = {
    '$type': 'app.bsky.system.declRef',
    'actorType': 'app.bsky.system.actorUser',
    'cid': 'TODO',
}
SUBJECT = {
    '$type': 'app.bsky.actor.ref#withInfo',
    'did': 'did:web:foo.com',
    'handle': 'foo.com',
    'declaration': ACTOR_DECLARATION,
}
FOLLOWERS_BSKY = [{
    '$type': 'app.bsky.graph.getFollowers#follower',
    'did': 'did:web:other',
    'handle': 'other-username',
    'declaration': ACTOR_DECLARATION,
    'indexedAt': '2022-01-02T03:04:05+00:00',
}, {
    '$type': 'app.bsky.graph.getFollowers#follower',
    'did': 'did:web:mastodon.social:users:swentel',
    'handle': 'mastodon.social/users/swentel',
    'declaration': ACTOR_DECLARATION,
    'indexedAt': '2022-01-02T03:04:05+00:00',
}]


@patch('requests.get')
class XrpcGraphTest(testutil.TestCase):

    def test_getFollowers_not_domain(self, mock_get):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getFollowers_empty(self, mock_get):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'followers': [],
        }, resp.json)

    def test_getFollowers(self, mock_get):
        Follower.get_or_create('foo.com', 'https://no/stored/follow')
        Follower.get_or_create('foo.com', 'https://masto/user',
                               last_follow=json_dumps(FOLLOW_WITH_ACTOR))

        other = copy.deepcopy(FOLLOW_WITH_ACTOR)
        other['actor'].update({
            'url': 'http://other',
            'preferredUsername': 'other-username',
        })
        Follower.get_or_create('foo.com', 'http://other', last_follow=json_dumps(other))

        other['actor']['url'] = 'http://nope'
        Follower.get_or_create('nope.com', 'http://nope' , last_follow=json_dumps(other))

        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'followers': FOLLOWERS_BSKY,
        }, resp.json)

    # def test_getFollows(self, mock_get):
    #     resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
    #                           query_string={'user': 'foo.com'})
    #     self.assertEqual({
    #     }, resp.json)
