"""Unit tests for atproto_oauth.py."""
import secrets
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from authlib.oauth2.rfc7636 import create_s256_code_challenge
from cryptography.hazmat.primitives.asymmetric import ec
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey
from webutil import util
from webutil.testutil import requests_response
from webutil.util import json_dumps

from .testutil import OAUTH_ES256_KEY, TestCase
import atproto_oauth
import common
from models import Target
from web import Web

BASE_URL = 'https://atproto.brid.gy/'
PAR_PATH = '/oauth/atproto/par'
PAR_URL = 'https://atproto.brid.gy/oauth/atproto/par'
AUTHORIZE_PATH = '/oauth/atproto/authorize'
TOKEN_PATH = '/oauth/atproto/token'
TOKEN_URL = 'https://atproto.brid.gy/oauth/atproto/token'
DID = 'did:plc:alice'
CLIENT_ID = 'https://app.example/client-metadata.json'
REDIRECT_URI = 'https://app.example/callback'
CLIENT_METADATA = {
    'client_id': CLIENT_ID,
    'client_name': 'My App',
    'redirect_uris': [REDIRECT_URI],
    'response_types': ['code'],
    'grant_types': ['authorization_code', 'refresh_token'],
    'scope': 'atproto',
    'token_endpoint_auth_method': 'none',
    'application_type': 'web',
    'dpop_bound_access_tokens': True,
}
# confidential client, which authenticates with a private_key_jwt assertion
CONFIDENTIAL_CLIENT_ID = 'https://conf.example/client-metadata.json'
CONFIDENTIAL_KID = 'key-1'
CONFIDENTIAL_METADATA = {
    **CLIENT_METADATA,
    'client_id': CONFIDENTIAL_CLIENT_ID,
    'client_name': 'Confidential App',
    'token_endpoint_auth_method': 'private_key_jwt',
    'token_endpoint_auth_signing_alg': 'ES256',
    'jwks': {
        'keys': [{
            **ECKey.import_key(OAUTH_ES256_KEY).as_dict(private=False),
            'kid': CONFIDENTIAL_KID,
            'use': 'sig',
            'alg': 'ES256',
        }],
    },
}

# same confidential client, but publishing its keys at a jwks_uri
JWKS_URI = 'https://conf.example/jwks.json'
CONFIDENTIAL_JWKS_URI_METADATA = {**CONFIDENTIAL_METADATA, 'jwks_uri': JWKS_URI}
CONFIDENTIAL_JWKS_URI_METADATA.pop('jwks')

# PKCE, https://datatracker.ietf.org/doc/html/rfc7636
CODE_VERIFIER = 'abcdefghijklmnopqrstuvwxyz012345678901234567890'



def dpop_proof(method, url, nonce=None, key=OAUTH_ES256_KEY, **claims):
    """Mints a DPoP proof JWT, like a real client would.

    https://datatracker.ietf.org/doc/html/rfc9449#section-4.2
    """
    key = ECKey.import_key(key)
    return joserfc_jwt.encode({
        'alg': 'ES256',
        'typ': 'dpop+jwt',
        'jwk': key.as_dict(private=False),
    }, {
        'jti': secrets.token_urlsafe(16),
        'htm': method,
        'htu': url,
        'iat': int(time.time()),
        **({'nonce': nonce} if nonce else {}),
        **claims,
    }, key)


@patch.object(common, 'BETA_USER_IDS', ('alice.com',))
class ATProtoOAuthTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user(
            'alice.com', cls=Web, enabled_protocols=['atproto'],
            copies=[Target(protocol='atproto', uri=DID)])

    def par_raw(self, nonce=None, dpop=True, key=OAUTH_ES256_KEY, **params):
        """Makes a single pushed authorization request, no nonce retry."""
        headers = ({'DPoP': dpop_proof('POST', PAR_URL, nonce=nonce, key=key)}
                   if dpop else {})
        return self.client.post(PAR_PATH, base_url=BASE_URL, headers=headers, data={
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': 'atproto',
            'state': 'xyz',
            'code_challenge': create_s256_code_challenge(CODE_VERIFIER),
            'code_challenge_method': 'S256',
            **params,
        })

    def par(self, **kwargs):
        """Makes a pushed authorization request, retrying with the DPoP nonce.

        Server-provided nonces are mandatory in ATProto, so real clients always
        make this second request.
        """
        resp = self.par_raw(**kwargs)
        if resp.status_code == 400 and resp.json.get('error') == 'use_dpop_nonce':
            resp = self.par_raw(nonce=resp.headers['DPoP-Nonce'], **kwargs)

        return resp

    def test_metadata(self):
        resp = self.client.get('/.well-known/oauth-authorization-server',
                               base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'issuer': 'https://atproto.brid.gy',
            'authorization_endpoint': 'https://atproto.brid.gy/oauth/atproto/authorize',
            'token_endpoint': 'https://atproto.brid.gy/oauth/atproto/token',
            'pushed_authorization_request_endpoint': 'https://atproto.brid.gy/oauth/atproto/par',
            'require_pushed_authorization_requests': True,
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none', 'private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported': ['ES256'],
            'dpop_signing_alg_values_supported': ['ES256'],
            'scopes_supported': ['atproto'],
            'authorization_response_iss_parameter_supported': True,
            'client_id_metadata_document_supported': True,
        }, resp.json)

    def test_metadata_other_host_is_still_mastodon(self):
        """Only our PDS host serves the ATProto authorization server."""
        resp = self.client.get('/.well-known/oauth-authorization-server',
                               base_url='https://web.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('https://web.brid.gy/oauth/authorize',
                         resp.json['authorization_endpoint'])
        self.assertNotIn('pushed_authorization_request_endpoint', resp.json)

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_par(self, _):
        """The client's metadata document is fetched at its client_id URL."""
        resp = self.par()
        self.assertEqual(201, resp.status_code,
                         (resp.get_data(as_text=True), dict(resp.headers)))
        self.assertTrue(resp.json['request_uri'].startswith(
            'urn:ietf:params:oauth:request_uri:'), resp.json)
        self.assertEqual(600, resp.json['expires_in'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_par_requires_dpop_nonce(self, _):
        """Server-provided DPoP nonces are mandatory in ATProto."""
        resp = self.par_raw()
        self.assertEqual(400, resp.status_code)
        self.assertEqual('use_dpop_nonce', resp.json['error'])
        self.assertTrue(resp.headers['DPoP-Nonce'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_par_requires_dpop(self, _):
        resp = self.par(dpop=False)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('invalid_dpop_proof', resp.json['error'])

    @patch.object(util.session, 'get', side_effect=[
        requests_response('', status=503),
        requests_response(json_dumps(CLIENT_METADATA)),
    ])
    def test_client_metadata_fetch_failure_isnt_cached(self, _):
        """A transient failure must not be cached, or it locks the client out."""
        resp = self.par()
        self.assertEqual(400, resp.status_code)
        self.assertEqual('invalid_client_metadata_document', resp.json['error'])

        # the client's server has recovered, so we should fetch it again
        resp = self.par()
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))

    #
    # full authorization code flow, via IndieAuth passthrough
    #
    def login(self, request_uri, me='https://alice.com'):
        """Runs a full IndieAuth login, returns the finish response."""
        qs = urlencode({'client_id': CLIENT_ID, 'request_uri': request_uri})
        resp = self.client.get(f'{AUTHORIZE_PATH}?{qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.post(f'{AUTHORIZE_PATH}/indieauth/start',
                                base_url=BASE_URL, data={'me': me, 'state': qs})
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))

        state = parse_qs(urlparse(resp.headers['Location']).query)['state'][0]
        return self.client.get(
            f'{AUTHORIZE_PATH}/indieauth/finish?code=my_code&state={state}',
            base_url=BASE_URL)

    def token_raw(self, nonce=None, key=OAUTH_ES256_KEY, **params):
        return self.client.post(TOKEN_PATH, base_url=BASE_URL, headers={
            'DPoP': dpop_proof('POST', TOKEN_URL, nonce=nonce, key=key),
        }, data={
            'grant_type': 'authorization_code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'code_verifier': CODE_VERIFIER,
            **params,
        })

    def token(self, **kwargs):
        """Exchanges a code for a token, retrying with the DPoP nonce."""
        resp = self.token_raw(**kwargs)
        if resp.status_code == 400 and resp.json.get('error') == 'use_dpop_nonce':
            resp = self.token_raw(nonce=resp.headers['DPoP-Nonce'], **kwargs)

        return resp

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_authorization_code_flow(self, *_):
        request_uri = self.par().json['request_uri']

        resp = self.login(request_uri)
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))

        location = urlparse(resp.headers['Location'])
        self.assertEqual('app.example', location.netloc)
        params = parse_qs(location.query)
        self.assertEqual(['xyz'], params['state'])
        # ATProto requires the iss parameter, RFC 9207
        self.assertEqual(['https://atproto.brid.gy'], params['iss'])

        resp = self.token(code=params['code'][0])
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(DID, resp.json['sub'])
        self.assertEqual('DPoP', resp.json['token_type'])
        self.assertEqual('atproto', resp.json['scope'])
        self.assertTrue(resp.json['access_token'])
        self.assertTrue(resp.json['refresh_token'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_token_with_different_dpop_key_rejected(self, *_):
        """The code is bound to the key from PAR; another key can't redeem it."""
        request_uri = self.par().json['request_uri']
        resp = self.login(request_uri)
        code = parse_qs(urlparse(resp.headers['Location']).query)['code'][0]

        other_key = ec.generate_private_key(ec.SECP256R1())
        resp = self.token(code=code, key=other_key)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('invalid_grant', resp.json['error'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_dpop_proof_replay_rejected(self, _):
        nonce = self.par_raw().headers['DPoP-Nonce']
        proof = dpop_proof('POST', PAR_URL, nonce=nonce)

        post = lambda: self.client.post(PAR_PATH, base_url=BASE_URL,
                                        headers={'DPoP': proof}, data={
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': 'atproto',
            'code_challenge': create_s256_code_challenge(CODE_VERIFIER),
            'code_challenge_method': 'S256',
        })

        self.assertEqual(201, post().status_code)

        resp = post()
        self.assertEqual(400, resp.status_code)
        self.assertEqual('invalid_dpop_proof', resp.json['error'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_authorize_requires_par(self, _):
        """ATProto clients must always go through PAR."""
        resp = self.client.get(f'{AUTHORIZE_PATH}?' + urlencode({
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': 'atproto',
            'state': 'xyz',
            'code_challenge': create_s256_code_challenge(CODE_VERIFIER),
            'code_challenge_method': 'S256',
        }), base_url=BASE_URL)
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('invalid_request', resp.json['error'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_authorize_renders_login_form(self, _):
        qs = urlencode({
            'client_id': CLIENT_ID,
            'request_uri': self.par().json['request_uri'],
        })
        resp = self.client.get(f'{AUTHORIZE_PATH}?{qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code)

        body = resp.get_data(as_text=True)
        self.assertIn('My App', body)
        self.assertIn('Mastodon-input', body)
        self.assertIn('IndieAuth-input', body)
        # you can't log in with an ATProto account to get an ATProto account
        self.assertNotIn('Bluesky-input', body)

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    def test_dpop_nonce_on_success(self, _):
        """Clients need a nonce from successful responses too, not just errors."""
        resp = self.par()
        self.assertEqual(201, resp.status_code)
        self.assertTrue(resp.headers['DPoP-Nonce'])

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client(self, _):
        """Localhost dev clients carry their metadata in the client_id's query.

        https://atproto.com/specs/oauth#localhost-client-development
        """
        client_id = 'http://localhost?' + urlencode({
            'redirect_uri': 'http://127.0.0.1/callback',
            'scope': 'atproto',
        })
        # ports aren't matched, so the client can listen on any of them
        resp = self.par(client_id=client_id,
                        redirect_uri='http://127.0.0.1:8080/callback')
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client_default_redirect_uris(self, _):
        resp = self.par(client_id='http://localhost',
                        redirect_uri='http://[::1]:1234/')
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client_id_lookalike_host_rejected(self, _):
        """http://localhost.evil.com must not get a localhost dev client."""
        client_id = 'http://localhost.evil.com?' + urlencode({
            'redirect_uri': 'https://evil.example/steal'})
        resp = self.par(client_id=client_id,
                        redirect_uri='https://evil.example/steal')
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client_id_with_port_rejected(self, _):
        client_id = 'http://localhost:8080?' + urlencode({
            'redirect_uri': 'http://127.0.0.1/callback'})
        resp = self.par(client_id=client_id,
                        redirect_uri='http://127.0.0.1/callback')
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client_id_with_path_rejected(self, _):
        client_id = 'http://localhost/app?' + urlencode({
            'redirect_uri': 'http://127.0.0.1/callback'})
        resp = self.par(client_id=client_id,
                        redirect_uri='http://127.0.0.1/callback')
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get',
                  side_effect=AssertionError('should not fetch anything'))
    def test_localhost_client_non_loopback_redirect_uri_rejected(self, _):
        """Otherwise anyone could exfiltrate authorization codes."""
        client_id = 'http://localhost?' + urlencode({
            'redirect_uri': 'https://evil.example/steal'})
        resp = self.par(client_id=client_id,
                        redirect_uri='https://evil.example/steal')
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    #
    # confidential clients, https://atproto.com/specs/oauth#confidential-clients
    #
    def client_assertion(self, key=OAUTH_ES256_KEY):
        """Mints a private_key_jwt client assertion, like a confidential client."""
        key = ECKey.import_key(key)
        now = int(time.time())
        return joserfc_jwt.encode({
            'alg': 'ES256',
            'kid': CONFIDENTIAL_KID,
        }, {
            'iss': CONFIDENTIAL_CLIENT_ID,
            'sub': CONFIDENTIAL_CLIENT_ID,
            'aud': 'https://atproto.brid.gy',
            'jti': secrets.token_urlsafe(16),
            'iat': now,
            'exp': now + 60,
        }, key)

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CONFIDENTIAL_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_confidential_client(self, *_):
        # RFC 9126: confidential clients authenticate at the PAR endpoint too
        resp = self.par(
            client_id=CONFIDENTIAL_CLIENT_ID,
            client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion=self.client_assertion())
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        request_uri = resp.json['request_uri']

        qs = urlencode({'client_id': CONFIDENTIAL_CLIENT_ID,
                        'request_uri': request_uri})
        resp = self.client.get(f'{AUTHORIZE_PATH}?{qs}', base_url=BASE_URL)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.post(f'{AUTHORIZE_PATH}/indieauth/start',
                                base_url=BASE_URL,
                                data={'me': 'https://alice.com', 'state': qs})
        state = parse_qs(urlparse(resp.headers['Location']).query)['state'][0]
        resp = self.client.get(
            f'{AUTHORIZE_PATH}/indieauth/finish?code=my_code&state={state}',
            base_url=BASE_URL)
        code = parse_qs(urlparse(resp.headers['Location']).query)['code'][0]

        resp = self.token(
            code=code, client_id=CONFIDENTIAL_CLIENT_ID,
            client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion=self.client_assertion())
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(DID, resp.json['sub'])

    @patch.object(util.session, 'get', side_effect=[
        requests_response(json_dumps(CONFIDENTIAL_JWKS_URI_METADATA)),
        requests_response(json_dumps(CONFIDENTIAL_METADATA['jwks'])),
    ])
    def test_confidential_client_jwks_uri(self, _):
        resp = self.par(
            client_id=CONFIDENTIAL_CLIENT_ID,
            client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion=self.client_assertion())
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))

    @patch.object(util.session, 'get', side_effect=[
        requests_response(json_dumps(CONFIDENTIAL_JWKS_URI_METADATA)),
        requests_response('', status=503),
    ])
    def test_confidential_client_jwks_uri_fetch_fails(self, _):
        """The error should say we couldn't fetch the JWKS, not that it's missing."""
        resp = self.par(
            client_id=CONFIDENTIAL_CLIENT_ID,
            client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion=self.client_assertion())
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('invalid_client', resp.json['error'])
        self.assertIn(JWKS_URI, resp.json['error_description'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_login_hint_matching_did(self, *_):
        request_uri = self.par(login_hint=DID).json['request_uri']
        resp = self.login(request_uri)
        self.assertEqual(302, resp.status_code)
        self.assertIn('code', parse_qs(urlparse(resp.headers['Location']).query))

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_login_hint_mismatch_denied(self, *_):
        """The AS should only allow the account the client asked for."""
        request_uri = self.par(login_hint='did:plc:someone-else').json['request_uri']
        resp = self.login(request_uri)
        self.assertEqual(302, resp.status_code)
        params = parse_qs(urlparse(resp.headers['Location']).query)
        self.assertEqual(['access_denied'], params['error'])

    @patch.object(util.session, 'get',
                  return_value=requests_response(json_dumps(CLIENT_METADATA)))
    @patch.object(util.session, 'post',
                  return_value=requests_response('me=https://alice.com'))
    def test_refresh_token(self, *_):
        request_uri = self.par().json['request_uri']
        resp = self.login(request_uri)
        code = parse_qs(urlparse(resp.headers['Location']).query)['code'][0]

        refresh_token = self.token(code=code).json['refresh_token']

        resp = self.token(grant_type='refresh_token', code=None,
                          refresh_token=refresh_token, scope='atproto')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(DID, resp.json['sub'])
        self.assertEqual('DPoP', resp.json['token_type'])
        self.assertNotEqual(refresh_token, resp.json['refresh_token'])
