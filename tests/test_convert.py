"""Unit tests for convert.py.
"""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import requests_response
import requests

from common import CONTENT_TYPE_HTML

from .test_redirect import (
    REPOST_AS2,
    REPOST_HTML,
)
from . import testutil


@patch('requests.get')
class ConvertTest(testutil.TestCase):

    def test_unknown_source(self, _):
        got = self.client.get('/convert/nope/webmention/http://foo')
        self.assertEqual(404, got.status_code)

    def test_unknown_dest(self, _):
        got = self.client.get('/convert/activitypub/nope/http://foo')
        self.assertEqual(404, got.status_code)

    def test_missing_url(self, _):
        got = self.client.get('/convert/activitypub/webmention/')
        self.assertEqual(404, got.status_code)

    def test_url_not_web(self, _):
        got = self.client.get('/convert/activitypub/webmention/git+ssh://foo/bar')
        self.assertEqual(400, got.status_code)

    def test_activitypub_to_web(self, mock_get):
        mock_get.return_value = self.as2_resp(REPOST_AS2)

        got = self.client.get('/convert/activitypub/webmention/https://user.com/bar?baz=baj&biff')
        self.assertEqual(200, got.status_code)
        self.assertEqual(CONTENT_TYPE_HTML, got.content_type)

        mock_get.assert_has_calls((self.as2_req('https://user.com/bar?baz=baj&biff='),))

    def test_activitypub_to_web_fetch_fails(self, mock_get):
        mock_get.side_effect = [requests_response('', status=405)]

        got = self.client.get('/convert/activitypub/webmention/http://foo')
        self.assertEqual(502, got.status_code)
        mock_get.assert_has_calls((self.as2_req('http://foo'),))
