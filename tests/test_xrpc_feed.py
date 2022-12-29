"""Unit tests for feed.py."""
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from . import testutil


@patch('requests.get')
class XrpcFeedTest(testutil.TestCase):

    def test_getAuthorFeed(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getProfile',
                              query_string={'actor': 'foo.com'},
                              ).json
        self.assertEqual({
            'feed': [{
                'post': {
                },
            }, {
                'post': {
                },
                'reply': {
                },
            }, {
                'post': {
                },
                'reason': {
                    'by': '',
                    'indexedAt': testutil.NOW.isoformat(),
                }
            }],
        }, got)


    def test_getAuthorFeed_not_domain(self, _):
        resp = self.client.get('/xrpc/app.bsky.feed.getAuthorFeed',
                               query_string={'actor': 'not a domain'})
        self.assertEqual(400, resp.status_code)

    def test_getPostThread(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getProfile',
                              query_string={'actor': 'foo.com'},
                              ).json
        self.assertEqual({
        }, got)

    def test_getRepostedBy(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getProfile',
                              query_string={'actor': 'foo.com'},
                              ).json
        self.assertEqual({
        }, got)

    def test_getTimeline(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getProfile',
                              query_string={'actor': 'foo.com'},
                              ).json
        self.assertEqual({
        }, got)

    def test_getVotes(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
</body>
""", url='https://foo.com/')

        got = self.client.get('/xrpc/app.bsky.actor.getVotes',
                              query_string={'actor': 'foo.com'},
                              ).json
        self.assertEqual({
        }, got)
