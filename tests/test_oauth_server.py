"""Unit tests for oauth_server.py, shared by mastodon_oauth and atproto_oauth.

Drives the shared code through the Mastodon OAuth server, since it has the
simplest client registration.
"""
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
from granary.micropub import Micropub
from granary.pixelfed import Pixelfed
import jwt
from oauth_dropins import indieauth
import oauth_dropins.bluesky
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.pixelfed import PixelfedApp, PixelfedAuth
from requests_oauth2client import (
    DPoPKey,
    DPoPToken,
    OAuth2AccessTokenAuth,
    OAuth2Client,
    TokenSerializer,
)
from webutil import util
import webutil.models
from webutil.testutil import requests_response
from webutil.util import json_dumps

import activitypub
from activitypub import ActivityPub
from atproto import ATProto
import common
from flask_app import app
import mastodon_oauth
import oauth_server
from . import test_atproto
from .testutil import Fake, TestCase
from web import Web

BASE_URL = 'https://web.brid.gy/'
REDIRECT_URI = 'https://app.example/callback'

DID_DOC = {
    **test_atproto.DID_DOC,
    'alsoKnownAs': ['at://han.dull'],
}


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


class GranarySourceForTest(TestCase):

    def test_bluesky(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto)
        BlueskyAuth(id='did:plc:user', pds_url='https://some.pds/',
                    user_json=json_dumps({'did': 'did:plc:user',
                                          'handle': 'han.dull'}),
                    session={'accessJwt': 'towkin', 'refreshJwt': 'reefresh'}).put()

        source = oauth_server.granary_source_for(user.key)
        self.assertIsInstance(source, Bluesky)
        self.assertEqual('did:plc:user', source.did)
        self.assertEqual('han.dull', source.handle)
        self.assertEqual('https://some.pds/', source._client.address)

    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    def test_bluesky_dpop(self, mock_oauth_client_for_pds):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto)
        BlueskyAuth(id='did:plc:user', pds_url='https://some.pds/',
                    user_json=json_dumps({'did': 'did:plc:user',
                                          'handle': 'han.dull'}),
                    dpop_token=TokenSerializer().dumps(
                        DPoPToken(access_token='towkin',
                                  _dpop_key=DPoPKey.generate()))).put()

        with app.test_request_context('/', base_url='https://web.brid.gy/'):
            source = oauth_server.granary_source_for(user.key)

        self.assertEqual('did:plc:user', source.did)
        self.assertIsInstance(source._client.requests_kwargs['auth'],
                              OAuth2AccessTokenAuth)
        mock_oauth_client_for_pds.assert_called_once_with({
            **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
            'client_id': 'https://web.brid.gy/oauth/bluesky/client-metadata.json',
            'client_name': 'Bridgy Fed',
            'client_uri': 'https://web.brid.gy/',
            'redirect_uris': [
                'https://web.brid.gy/oauth/bluesky/finish',
                'https://web.brid.gy/oauth/authorize/atproto/finish',
            ],
        }, 'https://some.pds/')

    def test_bluesky_no_auth_entity(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertIsNone(oauth_server.granary_source_for(user.key))

    def test_unsupported_protocol(self):
        user = self.make_user('fake:alice', cls=Fake)
        self.assertIsNone(oauth_server.granary_source_for(user.key))

    @patch.object(util, 'requests_get',
                  return_value=requests_response(
                      '', url='https://alice.com/',
                      headers={'Link': '<https://alice.com/mp>; rel="micropub"'}))
    def test_web(self, mock_get):
        user = self.make_user('alice.com', cls=Web)
        indieauth.IndieAuth(id='https://alice.com', user_json='{}',
                            access_token_str='towkin').put()

        source = oauth_server.granary_source_for(user.key)
        self.assertIsInstance(source, Micropub)
        self.assertEqual('https://alice.com/mp', source.endpoint)
        self.assertEqual('towkin', source.access_token)

    def test_mastodon(self):
        user = self.make_user('https://mas.to/users/alice', cls=ActivityPub,
                              webfinger_addr='@alice@mas.to')
        MastodonAuth(id='@alice@mas.to', access_token_str='towkin',
                     app=MastodonApp(instance='https://mas.to/', data='{}').put(),
                     user_json=json_dumps({
                         'id': '123',
                         'uri': 'https://mas.to/users/alice',
                     })).put()

        source = oauth_server.granary_source_for(user.key)
        self.assertIsInstance(source, Mastodon)
        self.assertNotIsInstance(source, Pixelfed)
        self.assertEqual('https://mas.to/', source.instance)
        self.assertEqual('towkin', source.access_token)
        self.assertEqual('123', source.user_id)

    def test_pixelfed(self):
        user = self.make_user('https://pix.fed/users/alice', cls=ActivityPub,
                              webfinger_addr='@alice@pix.fed')
        PixelfedAuth(id='@alice@pix.fed', access_token_str='towkin',
                     app=PixelfedApp(instance='https://pix.fed/', data='{}').put(),
                     user_json=json_dumps({'id': '123', 'acct': 'alice'})).put()

        source = oauth_server.granary_source_for(user.key)
        self.assertIsInstance(source, Pixelfed)
        self.assertEqual('https://pix.fed/', source.instance)
        self.assertEqual('towkin', source.access_token)
        self.assertEqual('123', source.user_id)

    def test_mastodon_auth_for_different_actor(self):
        user = self.make_user('https://mas.to/users/alice', cls=ActivityPub,
                              webfinger_addr='@alice@mas.to')
        MastodonAuth(id='@alice@mas.to', access_token_str='towkin',
                     app=MastodonApp(instance='https://mas.to/', data='{}').put(),
                     user_json=json_dumps({
                         'id': '123',
                         'uri': 'https://mas.to/users/eve',
                     })).put()

        self.assertIsNone(oauth_server.granary_source_for(user.key))

    def test_activitypub_no_auth_entity(self):
        user = self.make_user('https://mas.to/users/alice', cls=ActivityPub,
                              webfinger_addr='@alice@mas.to')
        self.assertIsNone(oauth_server.granary_source_for(user.key))
