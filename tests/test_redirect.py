"""Unit tests for redirect.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from . import testutil

from flask_app import app
from google.cloud.ndb.global_cache import _InProcessGlobalCache
from models import Object
import protocol
from web import Web

from .test_activitypub import ACTOR_BASE_FULL
from .test_web import (
    ACTOR_AS2,
    ACTOR_HTML,
    ACTOR_HTML_RESP,
    REPOST_AS2,
    REPOST_HTML,
    TOOT_AS2,
    TOOT_AS2_DATA,
)

REPOST_AS2 = {
    **REPOST_AS2,
    'actor': 'http://localhost/user.com',
}
del REPOST_AS2['cc']


class RedirectTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com', cls=Web)

    def test_redirect(self):
        got = self.client.get('/r/https://user.com/bar?baz=baj&biff')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://user.com/bar?baz=baj&biff=', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_redirect_scheme_missing(self):
        got = self.client.get('/r/user.com')
        self.assertEqual(400, got.status_code)

    def test_redirect_url_missing(self):
        got = self.client.get('/r/')
        self.assertEqual(404, got.status_code)

    def test_redirect_html_no_user(self):
        got = self.client.get('/r/http://bar.com/baz')
        self.assertEqual(404, got.status_code)
        self.assertEqual('Accept', got.headers['Vary'])

    def test_redirect_html_domain_allowlist(self):
        got = self.client.get('/r/http://bsky.app/baz')
        self.assertEqual(301, got.status_code)
        self.assertEqual('http://bsky.app/baz', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_redirect_single_slash(self):
        got = self.client.get('/r/https:/user.com/bar')
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://user.com/bar', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_redirect_trailing_garbage_chars(self):
        got = self.client.get(r'/r/https://v2.jacky.wtf\"')
        self.assertEqual(404, got.status_code)

    def test_redirect_url_parse_value_error(self):
        got = self.client.get(r'/r/https:/[DOMAIN]/')
        self.assertEqual(400, got.status_code)

    def test_as2(self):
        self._test_as2(as2.CONTENT_TYPE)

    def test_as2_ld(self):
        self._test_as2(as2.CONTENT_TYPE_LD_PROFILE)

    @patch('requests.get', side_effect=[
        requests_response(status=404),  # webfinger
        ACTOR_HTML_RESP,  # h-card fetch
    ])
    def test_as2_creates_user(self, _):
        Object(id='https://user.com/repost', source_protocol='web',
               as2=REPOST_AS2).put()

        self.user.key.delete()

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(REPOST_AS2, resp.json)
        self.assertEqual('Accept', resp.headers['Vary'])

        self.assert_user(Web, 'user.com', has_hcard=True, has_redirects=False,
                         direct=False, ignore=['redirects_error'])

    @patch('requests.get')
    def test_as2_fetch_post(self, mock_get):
        mock_get.return_value = TOOT_AS2  # from Protocol.for_id

        resp = self.client.get('/r/https://user.com/repost',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals(TOOT_AS2_DATA, resp.json)
        self.assertEqual('Accept', resp.headers['Vary'])

    @patch('requests.get', side_effect=[
        requests_response(ACTOR_HTML, url='https://user.com/'),  # AS2 fetch
        requests_response(ACTOR_HTML, url='https://user.com/'),  # web fetch
        requests_response(status=404),  # webfinger
        requests_response(ACTOR_HTML, url='https://user.com/'),  # h-card fetch
    ])
    def test_as2_no_user_fetch_homepage(self, mock_get):
        self.user.key.delete()
        self.user.obj_key.delete()

        resp = self.client.get('/r/https://user.com/',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('Accept', resp.headers['Vary'])

        expected = copy.deepcopy(ACTOR_BASE_FULL)
        del expected['endpoints']
        del expected['followers']
        del expected['following']
        self.assert_equals(expected, resp.json, ignore=['publicKey', 'summary'])

        self.assert_user(Web, 'user.com', has_hcard=True, has_redirects=False,
                         direct=False, obj_as2={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'id': 'https://user.com/',
            'url': 'https://user.com/',
            'name': 'Ms. ☕ Baz',
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'Ms. ☕ Baz',
                'value': '<a rel="me" href="https://user.com"><span class="invisible">https://</span>user.com</a>',
            }],
        }, ignore=['redirects_error'])

    # TODO: is this test still useful?
    def test_accept_header_across_requests(self):
        self.client = app.test_client()

        self._test_as2(as2.CONTENT_TYPE_LD_PROFILE)

        resp = self.client.get('/r/https://user.com/bar')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://user.com/bar', resp.headers['Location'])

        self.obj.delete()

        self._test_as2(as2.CONTENT_TYPE_LD_PROFILE)

        resp = self.client.get('/r/https://user.com/bar',
                               headers={'Accept': 'text/html'})
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://user.com/bar', resp.headers['Location'])

    def _test_as2(self, content_type):
        self.obj = Object(id='https://user.com/', source_protocol='web',
                          as2=REPOST_AS2).put()

        resp = self.client.get('/r/https://user.com/', headers={'Accept': content_type})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(content_type, resp.content_type)
        self.assert_equals(REPOST_AS2, resp.json)
        self.assertEqual('Accept', resp.headers['Vary'])

    def test_as2_deleted(self):
        Object(id='https://user.com/bar', as2={}, source_protocol='web',
               deleted=True).put()

        resp = self.client.get('/r/https://user.com/bar',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(404, resp.status_code, resp.get_data(as_text=True))

    def test_as2_opted_out(self):
        self.user.manual_opt_out = True
        self.user.put()

        resp = self.client.get('/r/https://user.com/',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(404, resp.status_code, resp.get_data(as_text=True))

    def test_as2_atproto_normalize_id(self):
        self.obj = Object(id='at://did:plc:foo/app.bsky.feed.post/123',
                          source_protocol='atproto', as2=REPOST_AS2).put()

        resp = self.client.get('/r/https://bsky.app/profile/did:plc:foo/post/123',
                               headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(as2.CONTENT_TYPE_LD_PROFILE, resp.content_type)
        self.assert_equals(REPOST_AS2, resp.json)
