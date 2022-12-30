"""Unit tests for feed.py."""
import copy
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW, requests_response
import requests

from . import testutil


POST_HTML = """
<article class="h-entry">
  <main class="e-content">My post</main>
  <a class="u-url" href="http://orig/post"></a>
  <time class="dt-published" datetime="2007-07-07T03:04:05"></time>
</article>
"""
POST = {
    '$type': 'app.bsky.feed.post#view',
    'uri': 'http://orig/post',
    'cid': 'TODO',
    'record': {
        'text': 'My post',
        'createdAt': '2007-07-07T03:04:05',
    },
    'replyCount': 0,
    'repostCount': 0,
    'upvoteCount': 0,
    'downvoteCount': 0,
    'indexedAt': '2022-01-02T03:04:05+00:00',
    'viewer': {}
}

REPLY_HTML = """
<article class="h-entry">
  <main class="e-content">I hereby reply to this</a></main>
  <a class="u-in-reply-to" href="http://orig/post"></a>
  <a class="u-url" href="http://a/reply"></a>
  <time class="dt-published" datetime="2008-08-08T03:04:05"></time>
</article>
"""
REPLY = copy.deepcopy(POST)
REPLY.update({
    'uri': 'http://a/reply',
    'record': {
        'text': 'I hereby reply to this',
        'createdAt': '2008-08-08T03:04:05',
        'reply': {
            'root': {
                'uri': 'http://orig/post',
                'cid': 'TODO',
            },
            'parent': {
                'uri': 'http://orig/post',
                'cid': 'TODO',
            },
        },
    },
})

REPOST_HTML = """
<article class="h-entry">
  <main class="e-content">A compelling post</main>
  <a class="u-repost-of" href="http://orig/post"></a>
  <time class="dt-published" datetime="2007-07-07T03:04:05"></time>
</article>
"""
REPOST = copy.deepcopy(POST)
REPOST['record'].update({
    'text': '',
    'createdAt': '',
})
REPOST_REASON = {
    '$type': 'app.bsky.feed.feedViewPost#reasonRepost',
    'by': {
        'did': 'TODO',
        'declaration': {
            'cid': 'TODO',
            'actorType': 'app.bsky.system.actorUser',
        },
        'handle': 'alice.com',
        'displayName': 'Alice',
        'avatar': 'https://alice.com/alice.jpg',
    },
    'indexedAt': NOW.isoformat(),
}


@patch('requests.get')
class XrpcFeedTest(testutil.TestCase):

    def test_getAuthorFeed(self, mock_get):
        mock_get.return_value = requests_response(f"""\
<body class="h-feed">
<a href="/" class="u-author h-card">
  <img src="/alice.jpg"> Alice
</a>
{POST_HTML}
{REPLY_HTML}
{REPOST_HTML}
</body>
""", url='https://alice.com/')

        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'alice.com'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'feed': [{
                '$type': 'app.bsky.feed.feedViewPost',
                'post': POST,
            }, {
                '$type': 'app.bsky.feed.feedViewPost',
                'post': REPLY,
            }, {
                '$type': 'app.bsky.feed.feedViewPost',
                'post': REPOST,
                'reason': REPOST_REASON,
            }],
        }, resp.json)

    def test_getAuthorFeed_not_domain(self, _):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'author': 'not a domain'})
        self.assertEqual(400, resp.status_code)

#     def test_getPostThread(self, mock_get):
#         mock_get.return_value = requests_response("""
# <body>
# </body>
# """, url='https://foo.com/')

#         got = self.client.get('/xrpc/app.bsky.actor.getProfile',
#                               query_string={'actor': 'foo.com'},
#                               ).json
#         self.assertEqual({
#         }, got)

#     def test_getRepostedBy(self, mock_get):
#         mock_get.return_value = requests_response("""
# <body>
# </body>
# """, url='https://foo.com/')

#         got = self.client.get('/xrpc/app.bsky.actor.getProfile',
#                               query_string={'actor': 'foo.com'},
#                               ).json
#         self.assertEqual({
#         }, got)

#     def test_getTimeline(self, mock_get):
#         mock_get.return_value = requests_response("""
# <body>
# </body>
# """, url='https://foo.com/')

#         got = self.client.get('/xrpc/app.bsky.actor.getProfile',
#                               query_string={'actor': 'foo.com'},
#                               ).json
#         self.assertEqual({
#         }, got)

#     def test_getVotes(self, mock_get):
#         mock_get.return_value = requests_response("""
# <body>
# </body>
# """, url='https://foo.com/')

#         got = self.client.get('/xrpc/app.bsky.actor.getVotes',
#                               query_string={'actor': 'foo.com'},
#                               ).json
#         self.assertEqual({
#         }, got)
