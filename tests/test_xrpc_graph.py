"""Unit tests for graph.py."""
from granary import bluesky
from oauth_dropins.webutil.testutil import requests_response
import requests

# import first so that Fake is defined before URL routes are registered
from . import testutil

from .test_activitypub import ACTOR, FOLLOW, FOLLOW_WITH_ACTOR, FOLLOW_WITH_OBJECT
from models import Follower, User

SUBJECT = {
    '$type': 'app.bsky.actor.defs#profileView',
    'did': 'did:web:user.com',
    'handle': 'user.com',
    'description': None,
}
FOLLOWERS_BSKY = [{
    '$type': 'app.bsky.graph.getFollowers#follower',
    'did': 'did:web:other',
    'handle': 'yoozer@other',
    'indexedAt': '2022-01-02T03:04:05+00:00',
    'description': None,
}, {
    '$type': 'app.bsky.graph.getFollowers#follower',
    'did': 'did:web:mas.to:users:swentel',
    'handle': 'mas.to/users/swentel',
    'displayName': 'Mrs. ☕ Foo',
    'avatar': 'https://user.com/me.jpg',
    'indexedAt': '2022-01-02T03:04:05+00:00',
    'description': None,
}]


class XrpcGraphTest(testutil.TestCase):

    def test_getProfile_no_user(self):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers')
        self.assertEqual(400, resp.status_code)

    def test_getFollowers_not_domain(self):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getFollowers_no_user(self):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'no.com'})
        self.assertEqual(400, resp.status_code)

    def test_getFollowers_empty(self):
        self.make_user('user.com')

        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'user.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'subject': SUBJECT,
            'cursor': '',
            'followers': [],
        }, resp.json)

    def test_getFollowers(self):
        self.make_user('user.com')

        other_follow = {
            **FOLLOW,
            'actor': {
                'type': 'Person',
                'url': 'http://other',
                'preferredUsername': 'yoozer',
            },
        }

        Follower.get_or_create('user.com', 'https://no/stored/follow')
        Follower.get_or_create('user.com', 'https://masto/user',
                               last_follow=FOLLOW_WITH_ACTOR)
        Follower.get_or_create('user.com', 'http://other',
                               last_follow=other_follow)
        Follower.get_or_create('nope.com', 'http://nope',
                               last_follow=other_follow)

        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'user.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'subject': SUBJECT,
            'cursor': '',
            'followers': FOLLOWERS_BSKY,
        }, resp.json)

    def test_getFollows_not_domain(self):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getFollows_empty(self):
        self.make_user('user.com')

        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'user.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'subject': SUBJECT,
            'cursor': '',
            'follows': [],
        }, resp.json)

    def test_getFollows(self):
        self.make_user('user.com')

        other_follow = {
            **FOLLOW,
            'object': {
                'type': 'Person',
                'url': 'http://other',
                'preferredUsername': 'yoozer',
            },
        }

        Follower.get_or_create('https://no/stored/follow', 'user.com')
        Follower.get_or_create('https://masto/user', 'user.com',
                               last_follow=FOLLOW_WITH_OBJECT)
        Follower.get_or_create( 'http://other', 'user.com',
                               last_follow=other_follow)
        Follower.get_or_create('http://nope', 'nope.com',
                               last_follow=other_follow)

        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'user.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'subject': SUBJECT,
            'cursor': '',
            'follows': FOLLOWERS_BSKY,
        }, resp.json)
