"""Unit tests for graph.py."""
from granary import bluesky
from oauth_dropins.webutil.testutil import requests_response
import requests

from .test_activitypub import ACTOR, FOLLOW, FOLLOW_WITH_ACTOR, FOLLOW_WITH_OBJECT
from . import testutil
from models import Follower, User

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
    'handle': 'yoozer@other',
    'declaration': ACTOR_DECLARATION,
    'indexedAt': '2022-01-02T03:04:05+00:00',
}, {
    '$type': 'app.bsky.graph.getFollowers#follower',
    'did': 'did:web:mastodon.social:users:swentel',
    'handle': 'mastodon.social/users/swentel',
    'displayName': 'Mrs. ☕ Foo',
    'avatar': 'https://foo.com/me.jpg',
    'declaration': ACTOR_DECLARATION,
    'indexedAt': '2022-01-02T03:04:05+00:00',
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
        self.make_user('foo.com')

        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'followers': [],
        }, resp.json)

    def test_getFollowers(self):
        self.make_user('foo.com')

        other_follow = {
            **FOLLOW,
            'actor': {
                'url': 'http://other',
                'preferredUsername': 'yoozer',
            },
        }

        Follower.get_or_create('foo.com', 'https://no/stored/follow')
        Follower.get_or_create('foo.com', 'https://masto/user',
                               last_follow=FOLLOW_WITH_ACTOR)
        Follower.get_or_create('foo.com', 'http://other',
                               last_follow=other_follow)
        Follower.get_or_create('nope.com', 'http://nope',
                               last_follow=other_follow)

        resp = self.client.get('/xrpc/app.bsky.graph.getFollowers',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'followers': FOLLOWERS_BSKY,
        }, resp.json)

    def test_getFollows_not_domain(self):
        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getFollows_empty(self):
        self.make_user('foo.com')

        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'follows': [],
        }, resp.json)

    def test_getFollows(self):
        self.make_user('foo.com')

        other_follow = {
            **FOLLOW,
            'object': {
                'url': 'http://other',
                'preferredUsername': 'yoozer',
            },
        }

        Follower.get_or_create('https://no/stored/follow', 'foo.com')
        Follower.get_or_create('https://masto/user', 'foo.com',
                               last_follow=FOLLOW_WITH_OBJECT)
        Follower.get_or_create( 'http://other', 'foo.com',
                               last_follow=other_follow)
        Follower.get_or_create('http://nope', 'nope.com',
                               last_follow=other_follow)

        resp = self.client.get('/xrpc/app.bsky.graph.getFollows',
                              query_string={'user': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            'subject': SUBJECT,
            'cursor': '',
            'follows': FOLLOWERS_BSKY,
        }, resp.json)
