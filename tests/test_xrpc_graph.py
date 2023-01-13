"""Unit tests for graph.py."""
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

from . import testutil


# @patch('requests.get')
# class XrpcGraphTest(testutil.TestCase):

#     def test_getAuthorFeed(self, mock_get):
#         mock_get.return_value = requests_response("""
# <body>
# </body>
# """, url='https://foo.com/')

#         got = self.client.get('/xrpc/app.bsky.actor.getProfile',
#                               query_string={'actor': 'foo.com'},
#                               ).json
#         self.assertEqual({
#         }, got)

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
