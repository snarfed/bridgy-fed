"""Unit tests for mastodon_oauth.py."""
import re
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from oauth_dropins import indieauth
from webutil import util
import webutil.models
from webutil.testutil import requests_response

from . import testutil
import activitypub
import common
import mastodon_oauth
from web import Web
from .testutil import TestCase

BASE_URL = 'https://web.brid.gy/'


@patch.object(common, 'BETA_USER_IDS', ('alice.com',))
class MastodonApiTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web)

    def register_app(self, **kwargs):
        kwargs.setdefault('client_name', 'My App')
        kwargs.setdefault('redirect_uris', 'https://app.example/callback')
        resp = self.client.post('/api/v1/apps', data=kwargs, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        return resp.json

    def authorize_query(self, client_id, **kwargs):
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': 'https://app.example/callback',
            'state': 'xyz',
        }
        params.update(kwargs)
        return urlencode(params)

    @patch.object(util.session, 'get', return_value=requests_response(''))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def login_raw(self, client_id, mock_post, mock_get, authorize_qs=None):
        """Runs a full IndieAuth login through /oauth/authorize.

        Returns the raw finish response: a redirect with the code, or, for the
        oob redirect_uri, the page that displays the code as text.
        """
        if authorize_qs is None:
            authorize_qs = self.authorize_query(client_id)

        resp = self.client.get(f'/oauth/authorize?{authorize_qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.post('/oauth/authorize/indieauth/start', data={
            'me': 'https://alice.com',
            'state': authorize_qs,
        }, base_url=BASE_URL)
        self.assertEqual(302, resp.status_code)
        location = resp.headers['Location']

        state = parse_qs(urlparse(location).query)['state'][0]
        return self.client.get(
            f'/oauth/authorize/indieauth/finish?code=my_code&state={state}',
            base_url=BASE_URL)

    def login(self, client_id, authorize_qs=None):
        """Runs a full IndieAuth login through /oauth/authorize, returns the code
        redirect's Location header.
        """
        resp = self.login_raw(client_id, authorize_qs=authorize_qs)
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))
        return resp.headers['Location']

    def test_register_app(self):
        app = self.register_app()
        self.assertEqual('My App', app['name'])
        self.assertEqual(['https://app.example/callback'], app['redirect_uris'])
        self.assertTrue(app['client_id'])
        self.assertTrue(app['client_secret'])

    def test_register_app_json(self):
        resp = self.client.post('/api/v1/apps', json={
            'client_name': 'My App',
            'redirect_uris': 'https://app.example/callback',
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('My App', resp.json['name'])
        self.assertEqual('https://app.example/callback', resp.json['redirect_uri'])
        self.assertEqual(['https://app.example/callback'], resp.json['redirect_uris'])
        self.assertTrue(resp.json['client_id'])
        self.assertTrue(resp.json['client_secret'])

    def test_register_app_json_redirect_uris_array(self):
        resp = self.client.post('/api/v1/apps', json={
            'client_name': 'My App',
            'redirect_uris': ['https://app.example/1', 'https://app.example/2'],
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('https://app.example/1\nhttps://app.example/2',
                         resp.json['redirect_uri'])
        self.assertEqual(['https://app.example/1', 'https://app.example/2'],
                         resp.json['redirect_uris'])

    def test_metadata(self):
        resp = self.client.get('/.well-known/oauth-authorization-server',
                               base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(BASE_URL, resp.json['issuer'])
        self.assertIn('/oauth/authorize', resp.json['authorization_endpoint'])
        self.assertIn('/oauth/token', resp.json['token_endpoint'])

    def test_authorize_renders_login_form(self):
        app = self.register_app()
        resp = self.client.get(
            f"/oauth/authorize?{self.authorize_query(app['client_id'])}",
            base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)
        self.assertIn('My App', resp.get_data(as_text=True))
        self.assertIn('IndieAuth', resp.get_data(as_text=True))

    def test_authorize_shows_existing_logins_and_fresh_login_forms(self):
        """If the browser already has a Bridgy Fed session login, /oauth/authorize
        should list it as a chooser option *and* still show the normal login
        forms, so the user can pick an existing account or log into a new one.
        """
        indieauth.IndieAuth(id='https://alice.com', user_json='{}').put()
        app = self.register_app()
        with self.client.session_transaction(base_url=BASE_URL) as sess:
            sess['oauth-dropins.logins'] = [('IndieAuth', 'https://alice.com')]

        resp = self.client.get(
            f"/oauth/authorize?{self.authorize_query(app['client_id'])}",
            base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('My App', body)
        self.assertIn('alice.com', body)
        self.assertIn('IndieAuth-input', body)

    def test_authorize_no_session_login(self):
        """No existing session: just the fresh login forms, no chooser."""
        app = self.register_app()
        resp = self.client.get(
            f"/oauth/authorize?{self.authorize_query(app['client_id'])}",
            base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('IndieAuth-input', body)
        self.assertNotIn('name="user_key"', body)

    def test_session_consent_issues_token(self):
        indieauth.IndieAuth(id='https://alice.com', user_json='{}').put()
        app = self.register_app()
        with self.client.session_transaction(base_url=BASE_URL) as sess:
            sess['oauth-dropins.logins'] = [('IndieAuth', 'https://alice.com')]

        qs = self.authorize_query(app['client_id'])
        resp = self.client.get(f'/oauth/authorize?{qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)

        resp = self.client.post('/oauth/authorize', data={
            'state': qs,
            'user_key': self.user.key.urlsafe().decode(),
        }, base_url=BASE_URL)
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))
        location = resp.headers['Location']
        self.assertTrue(location.startswith('https://app.example/callback'), location)
        code = parse_qs(urlparse(location).query)['code'][0]

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json['access_token'])

    def test_session_consent_deny(self):
        app = self.register_app()
        qs = self.authorize_query(app['client_id'])
        resp = self.client.post('/oauth/authorize', data={
            'state': qs,
            'deny': '1',
        }, base_url=BASE_URL)
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))
        parsed_qs = parse_qs(urlparse(resp.headers['Location']).query)
        self.assertEqual('access_denied', parsed_qs['error'][0])

    @patch.object(util.session, 'get',
                  return_value=requests_response(''))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://bob.com'))
    def test_non_beta_user_denied(self, mock_post, mock_get):
        self.make_user('bob.com', cls=Web)
        app = self.register_app()
        qs = self.authorize_query(app['client_id'])

        resp = self.client.get(f'/oauth/authorize?{qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)

        resp = self.client.post('/oauth/authorize/indieauth/start', data={
            'me': 'https://bob.com',
            'state': qs,
        }, base_url=BASE_URL)
        self.assertEqual(302, resp.status_code)
        location = resp.headers['Location']
        state = parse_qs(urlparse(location).query)['state'][0]

        resp = self.client.get(
            f'/oauth/authorize/indieauth/finish?code=my_code&state={state}',
            base_url=BASE_URL)
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))
        location = resp.headers['Location']
        self.assertTrue(location.startswith('https://app.example/callback'), location)
        parsed_qs = parse_qs(urlparse(location).query)
        self.assertEqual('access_denied', parsed_qs['error'][0])
        self.assertNotIn('code', parsed_qs)

    def test_authorize_bad_client_id(self):
        resp = self.client.get(
            f"/oauth/authorize?{self.authorize_query('bogus')}", base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_authorize_bad_redirect_uri(self):
        app = self.register_app()
        qs = self.authorize_query(app['client_id'],
                                  redirect_uri='https://evil.example/cb')
        resp = self.client.get(f'/oauth/authorize?{qs}', base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_full_flow_and_verify_credentials(self):
        app = self.register_app()
        location = self.login(app['client_id'])

        parsed = urlparse(location)
        self.assertTrue(location.startswith('https://app.example/callback'))
        code = parse_qs(parsed.query)['code'][0]
        self.assertEqual('xyz', parse_qs(parsed.query)['state'][0])

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('Bearer', resp.json['token_type'])
        token = resp.json['access_token']
        self.assertTrue(token)

        resp = self.client.get('/api/v1/accounts/verify_credentials',
                               headers={'Authorization': f'Bearer {token}'},
                               base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('alice.com', resp.json['username'])

    def test_token_json_body(self):
        app = self.register_app()
        location = self.login(app['client_id'])
        code = parse_qs(urlparse(location).query)['code'][0]

        resp = self.client.post('/oauth/token', json={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('Bearer', resp.json['token_type'])
        self.assertTrue(resp.json['access_token'])

    def test_oob_flow(self):
        app = self.register_app(redirect_uris=mastodon_oauth.OOB_REDIRECT_URI)
        qs = self.authorize_query(app['client_id'],
                                  redirect_uri=mastodon_oauth.OOB_REDIRECT_URI)
        resp = self.login_raw(app['client_id'], authorize_qs=qs)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertNotIn('Location', resp.headers)

        body = resp.get_data(as_text=True)
        match = re.search(r'id="code" readonly value="([^"]+)"', body)
        self.assertTrue(match, body)

        payload = jwt.decode(match.group(1), algorithms=[mastodon_oauth.JWT_ALG],
                             key=webutil.models.ENCRYPTED_PROPERTY_KEYS_BYTES[0])
        self.assertIsNotNone(payload)
        self.assertEqual(mastodon_oauth.OOB_REDIRECT_URI, payload['redirect_uri'])

    def test_pkce(self):
        app = self.register_app()
        code_verifier = 'x' * 43
        code_challenge = mastodon_oauth.create_s256_code_challenge(code_verifier)
        qs = self.authorize_query(app['client_id'], code_challenge=code_challenge,
                                  code_challenge_method='S256')
        location = self.login(app['client_id'], authorize_qs=qs)
        code = parse_qs(urlparse(location).query)['code'][0]

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
            'code_verifier': code_verifier,
        }, base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

    def test_pkce_wrong_code_verifier(self):
        app = self.register_app()
        code_verifier = 'x' * 43
        code_challenge = mastodon_oauth.create_s256_code_challenge(code_verifier)
        qs = self.authorize_query(app['client_id'], code_challenge=code_challenge,
                                  code_challenge_method='S256')
        location = self.login(app['client_id'], authorize_qs=qs)
        code = parse_qs(urlparse(location).query)['code'][0]

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
            'code_verifier': 'y' * 43,
        }, base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_expired_code_rejected(self):
        app = self.register_app()
        location = self.login(app['client_id'])
        code = parse_qs(urlparse(location).query)['code'][0]

        # decode, force exp into the past, re-encode with the real key, since we
        # can't easily wait 60s in a test
        payload = jwt.decode(code, algorithms=[mastodon_oauth.JWT_ALG],
                             key=webutil.models.ENCRYPTED_PROPERTY_KEYS_BYTES[0])
        payload['exp'] = int(time.time()) - 1
        expired_code = jwt.encode(payload, algorithm=mastodon_oauth.JWT_ALG,
                                  key=webutil.models.ENCRYPTED_PROPERTY_KEYS_BYTES[0])

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': expired_code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_tampered_code_rejected(self):
        app = self.register_app()
        location = self.login(app['client_id'])
        code = parse_qs(urlparse(location).query)['code'][0]

        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code[:-1] + ('x' if code[-1] != 'x' else 'y'),
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_cross_type_blob_rejected_as_code(self):
        """A signed access token used as an authorization code must be rejected."""
        app = self.register_app()
        token = mastodon_oauth.encode_jwt({
            'typ': mastodon_oauth.TOKEN_TYP,
            'user_key': self.user.key.urlsafe().decode(),
            'client_id_hash': mastodon_oauth.hash_client_id(app['client_id']),
            'scope': 'read',
        })
        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': token,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        self.assertEqual(400, resp.status_code)

    def test_verify_credentials_tampered_token(self):
        app = self.register_app()
        location = self.login(app['client_id'])
        code = parse_qs(urlparse(location).query)['code'][0]
        resp = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://app.example/callback',
            'client_id': app['client_id'],
            'client_secret': app['client_secret'],
        }, base_url=BASE_URL)
        token = resp.json['access_token']
        bad_token = token[:-1] + ('x' if token[-1] != 'x' else 'y')

        resp = self.client.get('/api/v1/accounts/verify_credentials',
                               headers={'Authorization': f'Bearer {bad_token}'},
                               base_url=BASE_URL)
        self.assertEqual(401, resp.status_code)

    def test_verify_credentials_no_token(self):
        resp = self.client.get('/api/v1/accounts/verify_credentials',
                               base_url=BASE_URL)
        self.assertEqual(401, resp.status_code)

    def test_atproto_proxy_client_metadata(self):
        resp = self.client.get('/oauth/atproto/client-metadata.json',
                               base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(
            [f'{BASE_URL.rstrip("/")}/oauth/authorize/atproto/finish'],
            resp.json['redirect_uris'])
        self.assertNotEqual('/oauth/atproto/client-metadata.json',
                            resp.json['client_id'])

    def test_proxy_start_routes_registered(self):
        for path in (
                '/oauth/authorize/atproto/start',
                '/oauth/authorize/indieauth/start',
        ):
            resp = self.client.post(path, base_url=BASE_URL)
            self.assertEqual(400, resp.status_code, path)
