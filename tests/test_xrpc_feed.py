"""Unit tests for feed.py."""
import copy
from unittest import skip

from granary import as2, bluesky
from granary.tests.test_as1 import COMMENT, NOTE
from granary.tests.test_bluesky import (
    POST_BSKY,
    POST_AS,
    REPLY_BSKY,
    REPLY_AS,
    REPOST_BSKY,
    REPOST_AS,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests
from werkzeug.exceptions import BadGateway

from app import app
import common
from models import Object, User
from . import testutil
from .test_activitypub import ACTOR

POST_THREAD_AS = {
    **POST_AS,
    'replies': {
        'items': [{
            'objectType': 'comment',
            'url': 'http://bob.org/reply',
            'content': 'Uh huh',
            'author': {
                'objectType': 'person',
                'displayName': 'Bob',
                'url': 'http://bob.org/',
            },
        }],
    },
}
POST_THREAD_BSKY = {
    'thread': {
        '$type': 'app.bsky.feed.getPostThread#threadViewPost',
        'post': POST_BSKY['post'],
        'replies': [{
            '$type': 'app.bsky.feed.getPostThread#threadViewPost',
            'post': {
                '$type': 'app.bsky.feed.post#view',
                'uri': 'http://bob.org/reply',
                'cid': 'TODO',
                'record': {
                    '$type': 'app.bsky.feed.post',
                    'text': 'Uh huh',
                    'createdAt': '',
                },
                'author': {
                    '$type': 'app.bsky.actor.ref#withInfo',
                    'did': 'did:web:bob.org',
                    'displayName': 'Bob',
                    'handle': 'bob.org',
                    'declaration': {
                        '$type': 'app.bsky.system.declRef',
                        'actorType': 'app.bsky.system.actorUser',
                        'cid': 'TODO',
                    },
                },
                'replyCount': 0,
                'repostCount': 0,
                'upvoteCount': 0,
                'downvoteCount': 0,
                'indexedAt': '2022-01-02T03:04:05+00:00',
                'viewer': {},
            },
        }],
    },
}


class XrpcFeedTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.make_user('foo.com', has_hcard=True, actor_as2=ACTOR)

    def test_getAuthorFeed(self):
        post_as2 = as2.from_as1(POST_AS)
        with app.test_request_context('/'):
            Object(id='a', domains=['foo.com'], labels=['user'], as2=post_as2).put()
            Object(id='b', domains=['foo.com'], labels=['user'],
                   as2=as2.from_as1(REPLY_AS)).put()
            Object(id='c', domains=['foo.com'], labels=['user'],
                   as2=as2.from_as1(REPOST_AS)).put()
            # not outbound from user
            Object(id='d', domains=['foo.com'], labels=['feed'], as2=post_as2).put()
            # deleted
            Object(id='e', domains=['foo.com'], labels=['user'], as2=post_as2,
                     deleted=True).put()
            # other user's
            Object(id='f', domains=['bar.org'], labels=['user'], as2=post_as2).put()

        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'foo.com'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'feed': [REPOST_BSKY, REPLY_BSKY, POST_BSKY],
        }, resp.json)

    def test_getAuthorFeed_no_author_param(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed')
        self.assertEqual(400, resp.status_code)

    def test_getAuthorFeed_not_domain(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getAuthorFeed_no_user(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'no.com'})
        self.assertEqual(400, resp.status_code)

    def test_getAuthorFeed_no_objects(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'foo.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({'feed': []}, resp.json)

    def test_getPostThread(self):
        with app.test_request_context('/'):
            Object(id='http://a/post', domains=['foo.com'], labels=['user'],
                   as2=as2.from_as1(POST_THREAD_AS)).put()

        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(POST_THREAD_BSKY, resp.json)

    def test_getPostThread_no_uri_param(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread')
        self.assertEqual(400, resp.status_code)

    def test_getPostThread_no_post(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread',
                               query_string={'uri': 'http://no/post'})
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    def test_getRepostedBy(self):
        with app.test_request_context('/'):
            Object(id='repost/1', domains=['foo.com'], as2=as2.from_as1({
                **REPOST_AS,
                'object': 'http://a/post',
            })).put()
            Object(id='repost/2', domains=['foo.com'], as2=as2.from_as1({
                **REPOST_AS,
                'object': 'http://a/post',
                'actor': as2.to_as1(ACTOR),
            })).put()

        got = self.client.get('/xrpc/app.bsky.feed.getRepostedBy',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual({
            'uri': 'http://orig/post',
            'repostBy': [{
                '$type': 'app.bsky.feed.getRepostedBy#repostedBy',
                'did': 'did:web:mastodon.social:users:swentel',
                'declaration': {
                    '$type': 'app.bsky.system.declRef',
                    'cid': 'TODO',
                    'actorType': 'app.bsky.system.actorUser',
                },
                'handle': 'mastodon.social/users/swentel',
                'displayName': 'Mrs. ☕ Foo',
                'avatar': 'https://foo.com/me.jpg',
            }, {
                '$type': 'app.bsky.feed.getRepostedBy#repostedBy',
                'did': 'did:web:alice.com',
                'declaration': {
                    '$type': 'app.bsky.system.declRef',
                    'cid': 'TODO',
                    'actorType': 'app.bsky.system.actorUser',
                },
                'handle': 'alice.com',
                'displayName': 'Alice',
                'avatar': 'https://alice.com/alice.jpg',
            }],
        }, got.json)

    def test_getTimeline(self):
        self.add_objects()

        got = self.client.get('/xrpc/app.bsky.feed.getTimeline')
        self.assertEqual({
            'feed': [bluesky.from_as1(COMMENT), bluesky.from_as1(NOTE)],
        }, got.json)

    def test_getVotes(self):
        resp = self.client.get('/xrpc/app.bsky.feed.getVotes',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual({
            'uri': 'http://a/post',
            'votes': [],
        }, resp.json)
