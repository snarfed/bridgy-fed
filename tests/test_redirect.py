"""Unit tests for redirect.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from oauth_dropins.webutil.testutil import requests_response

import common
from models import User
from .test_webmention import REPOST_HTML, REPOST_AS2
from . import testutil


class RedirectTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        User.get_or_create('foo.com')

    def test_redirect(self):
        got = self.client.get('/r/https://foo.com/bar?baz=baj&biff')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://foo.com/bar?baz=baj&biff=', got.headers['Location'])

    def test_redirect_scheme_missing(self):
        got = self.client.get('/r/foo.com')
        self.assertEqual(400, got.status_code)

    def test_redirect_url_missing(self):
        got = self.client.get('/r/')
        self.assertEqual(404, got.status_code)

    def test_redirect_no_magic_key_for_domain(self):
        got = self.client.get('/r/http://bar.com/baz')
        self.assertEqual(404, got.status_code)

    def test_redirect_single_slash(self):
        got = self.client.get('/r/https:/foo.com/bar')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://foo.com/bar', got.headers['Location'])

    def test_redirect_trailing_garbage_chars(self):
        got = self.client.get(r'/r/https://v2.jacky.wtf\"')
        self.assertEqual(404, got.status_code)

    def test_as2(self):
        self._test_as2(common.CONTENT_TYPE_AS2)

    def test_as2_ld(self):
        self._test_as2(common.CONTENT_TYPE_AS2_LD)

    @patch('requests.get')
    def _test_as2(self, accept, mock_get):
        """Currently mainly for Pixelfed.

        https://github.com/snarfed/bridgy-fed/issues/39
        """
        repost = copy.deepcopy(REPOST_AS2)
        del repost['cc']
        repost.update({
            'to': [as2.PUBLIC_AUDIENCE],
            'object': 'http://orig/post',
        })

        mock_get.return_value = requests_response(
            REPOST_HTML, content_type=common.CONTENT_TYPE_HTML)

        got = self.client.get('/r/https://foo.com/bar', headers={'Accept': accept})

        args, kwargs = mock_get.call_args
        self.assertEqual(('https://foo.com/bar',), args)

        self.assertEqual(200, got.status_code)
        self.assertEqual(repost, got.json)
