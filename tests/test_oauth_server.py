"""Unit tests for oauth_server.py, shared by mastodon_oauth and atproto_oauth.

Drives the shared code through the Mastodon OAuth server, since it has the
simplest client registration.
"""
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from oauth_dropins import indieauth

import common
from .testutil import TestCase
from web import Web

BASE_URL = 'https://web.brid.gy/'


@patch.object(common, 'BETA_USER_IDS', ('alice.com',))
class ProxyTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web,
                                   enabled_protocols=['activitypub'])

    def authorize_query(self):
        resp = self.client.post('/api/v1/apps', base_url=BASE_URL, data={
            'client_name': 'My App',
            'redirect_uris': 'https://app.example/callback',
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        return urlencode({
            'response_type': 'code',
            'client_id': resp.json['client_id'],
            'redirect_uri': 'https://app.example/callback',
            'state': 'xyz',
        })

    def consent(self):
        return self.client.post('/oauth/authorize', base_url=BASE_URL, data={
            'state': self.authorize_query(),
            'user_key': self.user.key.urlsafe().decode(),
        })

    def log_in(self):
        indieauth.IndieAuth(id='https://alice.com', user_json='{}').put()
        with self.client.session_transaction(base_url=BASE_URL) as sess:
            sess['oauth-dropins.logins'] = [('IndieAuth', 'https://alice.com')]

    def test_consent_requires_session_login(self):
        """Otherwise anyone could POST someone else's user_key and get a token."""
        resp = self.consent()
        self.assertEqual(302, resp.status_code)
        params = parse_qs(urlparse(resp.headers['Location']).query)
        self.assertEqual(['access_denied'], params['error'])
        self.assertNotIn('code', params)

    def test_consent_with_session_login(self):
        self.log_in()
        resp = self.consent()
        self.assertEqual(302, resp.status_code)
        self.assertIn('code', parse_qs(urlparse(resp.headers['Location']).query))
