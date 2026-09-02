"""Unit tests for oauth_server.py, shared by mastodon_oauth and atproto_oauth.

Drives the shared code through the Mastodon OAuth server, since it has the
simplest client registration.
"""
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from oauth_dropins import indieauth
from webutil import util
import webutil.models
from webutil.testutil import requests_response

import activitypub
import common
import mastodon_oauth
import oauth_server
from .testutil import TestCase
from web import Web

BASE_URL = 'https://web.brid.gy/'
REDIRECT_URI = 'https://app.example/callback'


@patch.object(common, 'BETA_USER_IDS', ('alice.com',))
class ProxyTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web,
                                   enabled_protocols=['activitypub'])

    def log_in(self, me='https://alice.com'):
        indieauth.IndieAuth(id=me, user_json='{}').put()
        with self.client.session_transaction(base_url=BASE_URL) as sess:
            sess['oauth-dropins.logins'] = [('IndieAuth', me)]

    def consent(self, **data):
        """Registers a client, then POSTs the authorization consent prompt."""
        resp = self.client.post('/api/v1/apps', base_url=BASE_URL, data={
            'client_name': 'My App',
            'redirect_uris': REDIRECT_URI,
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.client_id = resp.json['client_id']
        self.client_secret = resp.json['client_secret']

        return self.client.post('/oauth/authorize', base_url=BASE_URL, data={
            'state': urlencode({
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': REDIRECT_URI,
                'state': 'xyz',
            }),
            **data,
        })

    def assert_denied(self, resp):
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'error': ['access_denied'],
            'error_description': [
                'The resource owner or authorization server denied the request',
            ],
            'state': ['xyz'],
        }, parse_qs(urlparse(resp.headers['Location']).query))

    def test_consent_requires_session_login(self):
        """Otherwise anyone could POST someone else's user_key and get a token."""
        resp = self.consent(user_key=self.user.key.urlsafe().decode())
        self.assert_denied(resp)

    def test_consent_with_session_login(self):
        self.log_in()
        resp = self.consent(user_key=self.user.key.urlsafe().decode())
        self.assertEqual(302, resp.status_code)
        self.assertIn('code', parse_qs(urlparse(resp.headers['Location']).query))

    def test_consent_deny(self):
        self.log_in()
        self.assert_denied(self.consent(deny='1'))

    def test_non_beta_user_denied(self):
        bob = self.make_user('bob.com', cls=Web, enabled_protocols=['activitypub'])
        self.log_in(me='https://bob.com')
        resp = self.consent(user_key=bob.key.urlsafe().decode())
        self.assert_denied(resp)

    def test_user_not_bridged_denied(self):
        self.user.manual_opt_out = True
        self.user.put()
        self.assertFalse(self.user.is_enabled(activitypub.ActivityPub))

        self.log_in()
        resp = self.consent(user_key=self.user.key.urlsafe().decode())
        self.assert_denied(resp)

    #
    # JwtAuthorizationCodeGrant: the code is a self-contained JWT
    #
    def code(self):
        """Returns a valid authorization code."""
        self.log_in()
        resp = self.consent(user_key=self.user.key.urlsafe().decode())
        return parse_qs(urlparse(resp.headers['Location']).query)['code'][0]

    def token(self, code):
        return self.client.post('/oauth/token', base_url=BASE_URL, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        })

    def test_expired_code_rejected(self):
        code = self.code()

        # decode, force exp into the past, re-encode with the real key, since we
        # can't easily wait 60s in a test
        key = webutil.models.ENCRYPTED_PROPERTY_KEYS_BYTES[0]
        payload = jwt.decode(code, algorithms=[oauth_server.JWT_ALG], key=key)
        payload['exp'] = int(time.time()) - 1
        expired = jwt.encode(payload, algorithm=oauth_server.JWT_ALG, key=key)

        self.assertEqual(400, self.token(expired).status_code)

    def test_tampered_code_rejected(self):
        code = self.code()
        self.assertEqual(400, self.token(code[:-1] + '!').status_code)

    def test_cross_type_blob_rejected_as_code(self):
        """A signed access token used as an authorization code must be rejected."""
        self.log_in()
        self.consent(user_key=self.user.key.urlsafe().decode())
        token = oauth_server.encode_jwt({
            'typ': mastodon_oauth.TOKEN_TYP,
            'user_key': self.user.key.urlsafe().decode(),
            'client_id_hash': oauth_server.hash_client_id(self.client_id),
            'scope': 'read',
        })
        self.assertEqual(400, self.token(token).status_code)
