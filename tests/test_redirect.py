"""Unit tests for redirect.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from oauth_dropins.webutil.testutil import requests_response
import requests

# import first so that Fake is defined before URL routes are registered
from . import testutil

from common import redirect_unwrap
from flask_app import app, cache
from models import Object, User
from .test_web import (
    ACTOR_AS2,
    ACTOR_AS2_FULL,
    ACTOR_HTML,
    REPOST_AS2,
    REPOST_HTML,
)

REPOST_AS2 = {
    **REPOST_AS2,
    'actor': ACTOR_AS2,
}
del REPOST_AS2['cc']

EXTERNAL_REPOST_AS2 = copy.deepcopy(REPOST_AS2)
EXTERNAL_REPOST_AS2['actor']['id'] = 'http://localhost/r/https://user.com/'


class RedirectTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com')

    def test_redirect(self):
        got = self.client.get('/r/https://user.com/bar?baz=baj&biff')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://user.com/bar?baz=baj&biff=', got.headers['Location'])

    def test_redirect_scheme_missing(self):
        got = self.client.get('/r/user.com')
        self.assertEqual(400, got.status_code)

    def test_redirect_url_missing(self):
        got = self.client.get('/r/')
        self.assertEqual(404, got.status_code)

    def test_redirect_html_no_user(self):
        got = self.client.get('/r/http://bar.com/baz')
        self.assertEqual(404, got.status_code)

    def test_redirect_single_slash(self):
        got = self.client.get('/r/https:/user.com/bar')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://user.com/bar', got.headers['Location'])

    def test_redirect_trailing_garbage_chars(self):
        got = self.client.get(r'/r/https://v2.jacky.wtf\"')
        self.assertEqual(404, got.status_code)

    def test_as2(self):
        self._test_as2(as2.CONTENT_TYPE)

    def test_as2_ld(self):
        self._test_as2(as2.CONTENT_TYPE_LD)

    def test_as2_creates_user(self):
        with self.request_context:
            Object(id='https://user.com/repost', as2=EXTERNAL_REPOST_AS2).put()

        self.user.key.delete()

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(EXTERNAL_REPOST_AS2, resp.json)

    @patch('requests.get')
    def test_as2_fetch_post(self, mock_get):
        mock_get.return_value = requests_response(REPOST_HTML)

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(REPOST_AS2, resp.json)

    @patch('requests.get')
    def test_as2_fetch_post_no_backlink(self, mock_get):
        mock_get.return_value = requests_response(
            REPOST_HTML.replace('<a href="http://localhost/"></a>', ''))

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(REPOST_AS2, resp.json)

    @patch('requests.get')
    def test_as2_no_user_fetch_homepage(self, mock_get):
        mock_get.return_value = requests_response(ACTOR_HTML)
        self.user.key.delete()

        resp = self.client.get('/r/https://user.com/',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            **ACTOR_AS2,
            'id': 'http://localhost/r/https://user.com/',
            'summary': '',
            'attachment': [{
                'name': 'Ms. ☕ Baz',
                'type': 'PropertyValue',
                'value': '<a rel="me" href="https://user.com/">user.com</a>',
            }],
        }, resp.json)

    def test_accept_header_cache_key(self):
        app.config['CACHE_TYPE'] = 'SimpleCache'
        cache.init_app(app)
        self.client = app.test_client()

        self._test_as2(as2.CONTENT_TYPE)

        resp = self.client.get('/r/https://user.com/bar')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://user.com/bar', resp.headers['Location'])

        # delete stored Object to make sure we're serving from cache
        self.obj.delete()

        self._test_as2(as2.CONTENT_TYPE)

        resp = self.client.get('/r/https://user.com/bar',
                              headers={'Accept': 'text/html'})
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://user.com/bar', resp.headers['Location'])

    def _test_as2(self, content_type):
        with self.request_context:
            self.obj = Object(id='https://user.com/', as2=REPOST_AS2).put()

        resp = self.client.get('/r/https://user.com/', headers={'Accept': content_type})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(content_type, resp.content_type)
        self.assert_equals(REPOST_AS2, resp.json)

    def test_as2_deleted(self):
        with self.request_context:
            Object(id='https://user.com/bar', as2={}, deleted=True).put()

        resp = self.client.get('/r/https://user.com/bar',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, resp.status_code, resp.get_data(as_text=True))
