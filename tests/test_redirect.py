"""Unit tests for redirect.py.
"""
import copy

from mock import patch
from oauth_dropins.webutil.testutil import requests_response

import common
from redirect import app
from test_webmention import REPOST_HTML, REPOST_AS2
import testutil


class RedirectTest(testutil.TestCase):

    def test_redirect(self):
        got = app.get_response('/r/https://foo.com/bar?baz=baj&biff')
        self.assertEqual(302, got.status_int)
        self.assertEqual('https://foo.com/bar?baz=baj&biff', got.headers['Location'])

    def test_redirect_scheme_missing(self):
        got = app.get_response('/r/asdf.com')
        self.assertEqual(400, got.status_int)

    def test_redirect_url_missing(self):
        got = app.get_response('/r/')
        self.assertEqual(404, got.status_int)

    def test_as2(self):
        self._test_as2(common.CONTENT_TYPE_AS2)

    def test_as2_ld(self):
        self._test_as2(common.CONTENT_TYPE_AS2_LD)

    @patch('requests.get')
    def _test_as2(self, content_type, mock_get):
        """Currently mainly for Pixelfed.

        https://github.com/snarfed/bridgy-fed/issues/39
        """
        as2 = copy.deepcopy(REPOST_AS2)
        as2.update({
            'cc': [common.AS2_PUBLIC_AUDIENCE],
            'object': 'http://orig/post',
        })

        mock_get.return_value = requests_response(
            REPOST_HTML, content_type=content_type)

        got = app.get_response('/r/https://foo.com/bar', headers={
            'Accept': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
        })

        args, kwargs = mock_get.call_args
        self.assertEqual(('https://foo.com/bar',), args)

        self.assertEqual(200, got.status_int)
        self.assertEqual(as2, got.json)
