"""Unit tests for feed.py."""
from unittest.mock import patch

from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_REF_BSKY,
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

from . import testutil


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
            'feed': [POST_BSKY, REPLY_BSKY, REPOST_BSKY],
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
