"""Unit tests for patreon.py."""
from unittest.mock import patch

import oauth_dropins.patreon
from oauth_dropins.patreon import PatreonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from webutil import util
from webutil.testutil import requests_response
from webutil.util import json_dumps

from .testutil import TestCase


@patch.multiple(oauth_dropins.patreon, CLIENT_ID='abc', CLIENT_SECRET='xyz')
class PatreonTest(TestCase):

    def test_start(self):
        resp = self.client.post('/oauth/patreon/start')
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(
            'https://www.patreon.com/oauth2/authorize?'), resp.headers['Location'])

    @patch.object(util.session, 'request', return_value=requests_response({
        'access_token': 'towkin',
        'token_type': 'Bearer',
    }))
    @patch.object(util.session, 'get', return_value=requests_response({
        'data': {
            'id': '456',
            'attributes': {'full_name': 'Bob Patron'},
        },
    }))
    def test_finish_drops_existing_patreon_login(self, _, __):
        PatreonAuth(id='123', token_json='{}', user_json=json_dumps({
            'data': {
                'id': '123',
                'attributes': {'full_name': 'Alice Patron'},
            },
        })).put()
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [
                ('MastodonAuth', '@a@b.c'),
                ('PatreonAuth', '123'),
            ]

        resp = self.client.get('/oauth/patreon/finish?code=my_code')
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            self.assertEqual([
                ('MastodonAuth', '@a@b.c'),
                ('PatreonAuth', '456'),
            ], sess[LOGINS_SESSION_KEY])
