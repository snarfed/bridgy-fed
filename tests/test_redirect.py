"""Unit tests for redirect.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from . import testutil

from flask_app import app, cache
from models import Object
from web import Web

from .test_activitypub import ACTOR_BASE_FULL
from .test_web import (
    ACTOR_AS2,
    ACTOR_HTML,
    REPOST_AS2,
    REPOST_HTML,
)

REPOST_AS2 = {
    **REPOST_AS2,
    'actor': ACTOR_AS2,
}
del REPOST_AS2['cc']


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

    def test_redirect_html_domain_allowlist(self):
        got = self.client.get('/r/http://bsky.app/baz')
        self.assertEqual(301, got.status_code)
        self.assertEqual('http://bsky.app/baz', got.headers['Location'])

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
        Object(id='https://user.com/repost', as2=REPOST_AS2).put()

        self.user.key.delete()

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(REPOST_AS2, resp.json)

        self.assert_user(Web, 'user.com', direct=False)

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

        expected = copy.deepcopy(ACTOR_BASE_FULL)
        del expected['endpoints']
        del expected['followers']
        del expected['following']
        self.assert_equals(expected, resp.json, ignore=['publicKeyPem'])

        self.assert_user(Web, 'user.com', direct=False, obj_as2={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'id': 'https://user.com/',
            'url': 'https://user.com/',
            'name': 'Ms. ☕ Baz',
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'Ms. ☕ Baz',
                'value': '<a rel="me" href="https://user.com/"><span class="invisible">https://</span>user.com<span class="invisible">/</span></a>',
            }],
        })

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
        self.obj = Object(id='https://user.com/', as2=REPOST_AS2).put()

        resp = self.client.get('/r/https://user.com/', headers={'Accept': content_type})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(content_type, resp.content_type)
        self.assert_equals(REPOST_AS2, resp.json)

    def test_as2_deleted(self):
        Object(id='https://user.com/bar', as2={}, deleted=True).put()

        resp = self.client.get('/r/https://user.com/bar',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, resp.status_code, resp.get_data(as_text=True))
