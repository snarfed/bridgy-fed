"""Unit tests for feed.py."""
import copy
from unittest import skip
from unittest.mock import patch

from granary import bluesky
from granary.tests.test_bluesky import (
    POST_BSKY,
    POST_HTML,
    REPLY_BSKY,
    REPLY_HTML,
    REPOST_BSKY,
    REPOST_HTML,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests
from werkzeug.exceptions import BadGateway

from .test_pages import PagesTest
from . import testutil

AUTHOR_HTML = """
<a href="/" class="u-author h-card">
  <img src="/alice.jpg"> Alice
</a>
"""

POST_THREAD_HTML = copy.deepcopy(POST_HTML).replace('</article>', """
  <div class="u-comment h-cite">
    <a class="u-author h-card" href="http://bob.org/">Bob</a>
    <a class="u-url" href="http://bob.org/reply"></a>
    <p class="p-content">Uh huh</p>
  </div>

  <div class="u-repost h-cite">
    <a class="u-author h-card" href="http://eve.net/">Eve</a>
    <p class="p-content">This</p>
    <a class="u-repost-of" href="http://orig/post"></a>
  </div>
</article>
""")
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


@patch('requests.get')
class XrpcFeedTest(testutil.TestCase):

    def test_getAuthorFeed(self, mock_get):
        mock_get.return_value = requests_response(f"""\
<body class="h-feed">
{AUTHOR_HTML}
{POST_HTML}
{REPLY_HTML}
{REPOST_HTML}
</body>
""", url='https://alice.com/')

        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'alice.com'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'feed': [POST_BSKY, REPLY_BSKY, REPOST_BSKY],
        }, resp.json)

    def test_getAuthorFeed_unset(self, _):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed')
        self.assertEqual(400, resp.status_code)

    def test_getAuthorFeed_not_domain(self, _):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getAuthorFeed_fetch_fails(self, mock_get):
        mock_get.return_value = requests_response(status=500)
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'alice.com'})
        self.assertEqual(502, resp.status_code)

    def test_getAuthorFeed_no_feed(self, mock_get):
        mock_get.return_value = requests_response(AUTHOR_HTML)
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'alice.com'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual({'feed': []}, resp.json)

    def test_getPostThread(self, mock_get):
        mock_get.return_value = requests_response(
            POST_THREAD_HTML, url='https://alice.com/')

        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(POST_THREAD_BSKY, resp.json)

    def test_getPostThread_unset(self, mock_get):
        mock_get.return_value = requests_response(status=500)
        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread')
        self.assertEqual(400, resp.status_code)

    def test_getPostThread_fetch_fails(self, mock_get):
        mock_get.return_value = requests_response(status=500)
        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual(502, resp.status_code)

    def test_getAuthorFeed_no_post(self, mock_get):
        mock_get.return_value = requests_response(AUTHOR_HTML)
        resp = self.client.get('/xrpc/app.bsky.feed.getPostThread',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    @skip
    def test_getRepostedBy(self, mock_get):
        mock_get.return_value = requests_response(POST_THREAD_HTML,
                                                  url='http://orig/post')
        got = self.client.get('/xrpc/app.bsky.feed.getRepostedBy',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual({
            'uri': 'http://orig/post',
            'repostBy': [{
                '$type': 'app.bsky.feed.getRepostedBy#repostedBy',
                'did': 'did:web:eve.net',
                'declaration': {
                    '$type': 'app.bsky.system.declRef',
                    'cid': 'TODO',
                    'actorType': 'app.bsky.system.actorUser',
                },
                'handle': 'eve.net',
                'displayName': 'Eve',
                'indexedAt': '2022-01-02T03:04:05+00:00',
            }],
        }, got.json)

    def test_getTimeline(self, mock_get):
        PagesTest.add_objects()

        got = self.client.get('/xrpc/app.bsky.feed.getTimeline')
        self.assertEqual({
            'feed': [bluesky.from_as1(a) for a in PagesTest.EXPECTED_AS1]
        }, got.json)

    def test_getVotes(self, mock_get):
        resp = self.client.get('/xrpc/app.bsky.feed.getVotes',
                               query_string={'uri': 'http://a/post'})
        self.assertEqual({
            'uri': 'http://a/post',
            'votes': [],
        }, resp.json)
