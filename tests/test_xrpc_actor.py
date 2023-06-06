"""Unit tests for actor.py."""
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests
from unittest import skip

# import first so that Fake is defined before URL routes are registered
from . import testutil

from models import User
from .test_activitypub import ACTOR


@skip
class XrpcActorTest(testutil.TestCase):

    def test_getProfile(self):
        actor = {
            **ACTOR,
            'summary': "I'm a person",
            'image': [{'type': 'Image', 'url': 'http://user.com/header.png'}],
        }
        self.make_user('user.com', has_hcard=True, actor_as2=actor)

        resp = self.client.get('/xrpc/app.bsky.actor.getProfile',
                               query_string={'actor': 'user.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '$type': 'app.bsky.actor.defs#profileView',
            'handle': 'mas.to/users/swentel',
            'did': 'did:web:mas.to:users:swentel',
            'displayName': 'Mrs. ☕ Foo',
            'description': None,
            'description': "I'm a person",
            'avatar': 'https://user.com/me.jpg',
            'banner': 'http://user.com/header.png',
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
                               query_string={'actor': 'user.com'})
        self.assertEqual(400, resp.status_code)

    def test_getSuggestions(self):
        resp = self.client.get('/xrpc/app.bsky.actor.getSuggestions')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'actors': [],
        }, resp.json)

    def test_search(self):
        resp = self.client.get('/xrpc/app.bsky.actor.searchActors',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'actors': [],
        }, resp.json)

    def test_searchTypeahead(self):
        resp = self.client.get('/xrpc/app.bsky.actor.searchActorsTypeahead',
                              query_string={'term': 'foo'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            'actors': [],
        }, resp.json)
