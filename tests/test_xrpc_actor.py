"""Unit tests for actor.py."""
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from . import testutil
from models import User
from .test_activitypub import ACTOR


class XrpcActorTest(testutil.TestCase):

    def test_getProfile(self):
        actor = {
            **ACTOR,
            'summary': "I'm a person",
            'image': [{'type': 'Image', 'url': 'http://foo.com/header.png'}],
        }
        User.get_or_create('foo.com', has_hcard=True, actor_as2=actor).put()

        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'handle': 'mastodon.social/users/swentel',
            'did': 'did:web:mastodon.social:users:swentel',
            'creator': 'did:web:mastodon.social:users:swentel',
            'displayName': 'Mrs. ☕ Foo',
            'declaration': {
                '$type': 'app.bsky.system.declRef',
                'cid': 'TODO',
                'actorType': 'app.bsky.system.actorUser',
            },
            'description': "I'm a person",
            'avatar': 'https://foo.com/me.jpg',
            'banner': 'http://foo.com/header.png',
            'followersCount': 0,
            'followsCount': 0,
            'membersCount': 0,
            'postsCount': 0,
            'myState': {
                'follow': 'TODO',
                'member': 'TODO',
            },
        }, resp.json)

    def test_getProfile_unset(self):
        resp = self.client.get('/xrpc/app.bsky.actor.getProfile')
        self.assertEqual(400, resp.status_code)

    def test_getProfile_not_domain(self):
        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getProfile_no_user(self):
        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'foo.com'})
        self.assertEqual(400, resp.status_code)

    def test_getSuggestions(self):
        resp = self.client.get('/xrpc/app.bsky.actor.getSuggestions')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'actors': [],
        }, resp.json)

    def test_search(self):
        resp = self.client.get('/xrpc/app.bsky.actor.search',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'users': [],
        }, resp.json)

    def test_searchTypeahead(self):
        resp = self.client.get('/xrpc/app.bsky.actor.searchTypeahead',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'users': [],
        }, resp.json)
