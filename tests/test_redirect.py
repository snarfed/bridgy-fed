"""Unit tests for redirect.py.
"""
import copy

from granary import as2
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
from common import redirect_unwrap
from models import Object, User
from .test_webmention import REPOST_AS2
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
        self._test_as2(as2.CONTENT_TYPE)

    def test_as2_ld(self):
        self._test_as2(as2.CONTENT_TYPE_LD)

    def test_accept_header_cache_key(self):
        app.config['CACHE_TYPE'] = 'SimpleCache'
        cache.init_app(app)
        self.client = app.test_client()

        self._test_as2(as2.CONTENT_TYPE)

        resp = self.client.get('/r/https://foo.com/bar')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://foo.com/bar', resp.headers['Location'])

        # delete stored Object to make sure we're serving from cache
        self.obj.delete()

        self._test_as2(as2.CONTENT_TYPE)

        resp = self.client.get('/r/https://foo.com/bar',
                              headers={'Accept': 'text/html'})
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://foo.com/bar', resp.headers['Location'])

    def _test_as2(self, content_type):
        with app.test_request_context('/'):
            self.obj = Object(id='https://foo.com/bar',
                              as2=json_dumps(REPOST_AS2)).put()

        resp = self.client.get('/r/https://foo.com/bar',
                              headers={'Accept': content_type})
        self.assertEqual(200, resp.status_code)
        self.assertEqual(content_type, resp.content_type)

        self.assertEqual({
            **REPOST_AS2,
            'cc': [as2.PUBLIC_AUDIENCE],
        }, resp.json)

    def test_as2_deleted(self):
        with app.test_request_context('/'):
            Object(id='https://foo.com/bar', as2='{}', deleted=True).put()

        resp = self.client.get('/r/https://foo.com/bar',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, resp.status_code)
