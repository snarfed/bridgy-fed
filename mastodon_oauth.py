"""Serves Mastodon OAuth, passes through to other protocols.

https://github.com/snarfed/bridgy-fed/issues/2492
"""
import hashlib
import hmac
import logging
import secrets
import time

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request
from authlib.oauth2.rfc6749 import (
    AccessDeniedError,
    ClientMixin,
    TokenMixin,
)
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7636 import CodeChallenge, create_s256_code_challenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from flask import request
from google.cloud.ndb.key import Key
from granary.bluesky import Bluesky
from granary.micropub import Micropub
from oauth_dropins import indieauth
import oauth_dropins.bluesky
from oauth_dropins.bluesky import BlueskyAuth
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
from webutil import models
from webutil.flask_util import error, FlashErrors, get_required_param

from activitypub import ActivityPub
import atproto
from atproto import ATProto
from common import render_template
import domains
from flask_app import app
from oauth_server import decode_jwt, encode_jwt, hash_client_id, log_request_response
import oauth_server
from web import Web

logger = logging.getLogger(__name__)

CLIENT_TYP = 'mastodon-oauth-client'
TOKEN_TYP = 'mastodon-oauth-token'
CODE_TYP = 'mastodon-oauth-code'
OOB_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def client_secret_for(client_id):
    return hmac.new(models.ENCRYPTED_PROPERTY_KEYS_BYTES[0], client_id.encode(),
                    hashlib.sha256).hexdigest()


class Client(ClientMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.ClientMixin`.

    ``client_id`` is a self-contained JWT and provides all data.
    """
    def __init__(self, client_id, payload):
        self.client_id = client_id
        self.client_metadata = payload
        self.redirect_uris = payload['redirect_uris']

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        return scope or ''

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        return client_secret_for(self.client_id) == client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return True

    def check_response_type(self, response_type):
        return response_type == 'code'

    def check_grant_type(self, grant_type):
        return grant_type == 'authorization_code'


class AuthorizationCodeGrant(oauth_server.JwtAuthorizationCodeGrant):
    CODE_TYP = CODE_TYP

    def create_authorization_response(self, redirect_uri, grant_user):
        # out of band flow for non-web clients that can't show a webview
        if redirect_uri == OOB_REDIRECT_URI:
            logger.info('oob flow, rendering an authorization code')

            if not grant_user:
                raise AccessDeniedError(redirect_uri=redirect_uri)

            self.request.user = grant_user
            code = self.generate_authorization_code()
            return 200, render_template('mastodon_oauth_code.html', code=code), []

        return super().create_authorization_response(redirect_uri, grant_user)


class Token(TokenMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.TokenMixin`.

    The access token itself is a self-contained JWT and provides all data.
    """
    def __init__(self, payload):
        self.jti = payload.get('jti')
        self.user_key = Key(urlsafe=payload['user_key'])
        self.scope = payload.get('scope') or ''
        # .get: tokens issued before we started including it don't have it, and
        # they never expire
        self.client_id_hash = payload.get('client_id_hash')

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return 0

    def is_expired(self):
        return False

    def is_revoked(self):
        # TODO: check a datastore denylist of revoked jtis, once we add
        # POST /oauth/revoke. Storing only revocations keeps this stateless in
        # the common case.
        return False

    def get_user(self):
        return self.user_key.get()

    def granary_source(self):
        """Returns a :class:`granary.source.Source` for this token's user.

        Uses the user's own credentials from their oauth-dropins auth entity.

        TODO: our bearer tokens never expire, but the underlying login can be
        revoked or expire. Distinguish that from "never logged in" and return 401.

        Returns:
          granary.source.Source or None:
        """
        if self.user_key.kind() == ATProto._get_kind():
            if auth := BlueskyAuth.get_by_id(self.user_key.id()):
                return Bluesky.from_auth(
                    auth, client_metadata=atproto.oauth_client_metadata())

        elif self.user_key.kind() == Web._get_kind():
            url = f'https://{self.user_key.id()}'
            if auth := (indieauth.IndieAuth.get_by_id(url)
                        or indieauth.IndieAuth.get_by_id(url + '/')):
                return Micropub.from_auth(auth)

        logger.info(f"No auth for {self.user_key}, or it doesn't support writes yet")

    def check_client(self, client):
        """Only the client this token was issued to may revoke it."""
        return self.client_id_hash == hash_client_id(client.get_client_id())


class BearerValidator(BearerTokenValidator):
    def authenticate_token(self, token):
        if payload := decode_jwt(token, TOKEN_TYP):
            return Token(payload)


def query_client(client_id):
    if payload := decode_jwt(client_id, CLIENT_TYP):
        return Client(client_id, payload)
    logger.info(f'query_client: no client for {client_id}')


def generate_bearer_token(grant_type, client, user=None, scope=None,
                          expires_in=None, include_refresh_token=True):
    token = encode_jwt({
        # https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
        'typ': TOKEN_TYP,
        # unique nonce, https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
        'jti': secrets.token_urlsafe(16),
        'user_key': user.key.urlsafe().decode(),
        'client_id_hash': hash_client_id(client.get_client_id()),
        'scope': scope,
    })
    return {
        'access_token': token,
        'token_type': 'Bearer',
        'scope': scope or '',
        'created_at': int(time.time()),
    }


class JsonAwareOAuth2Request(FlaskOAuth2Request):
    """Like :class:`FlaskOAuth2Request`, but also reads JSON bodies.

    Technically this shouldn't be necessary, at least for the token endpoint. OAuth 2
    (RFC 6749 section 4.1.3) says its request body *has* to be form-encoded. However,
    Mastodon accepts JSON too, and evidently lots of clients do that instead. :/
    """
    def __init__(self, flask_request):
        super().__init__(flask_request)
        if flask_request.is_json and (data := flask_request.get_json(silent=True)):
            self._json_data = data
            self.payload = BasicOAuth2Payload(data)

    @property
    def form(self):
        if hasattr(self, '_json_data'):
            return self._json_data
        return super().form


class JsonAwareAuthorizationServer(AuthorizationServer):
    def create_oauth2_request(self, _):
        return JsonAwareOAuth2Request(request)


server = JsonAwareAuthorizationServer(
    app, query_client=query_client,
    # noop; our tokens are self-contained, not stored
    save_token=lambda token, request: None)
server.register_token_generator('default', generate_bearer_token)
server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerValidator())


class Proxy(oauth_server.Proxy):
    SERVER = server
    AUTHORIZE_PATH = '/oauth/authorize'
    PROTO = ActivityPub
    # you can't log in with a fediverse account to use a fediverse account
    HIDE_LOGINS = ('mastodon', 'pixelfed')


def metadata():
    """Returns our authorization server metadata document.

    The ``/.well-known/oauth-authorization-server`` route that serves this is in
    :mod:`app`, since :mod:`atproto_oauth` serves its own on our PDS host.
    """
    metadata = AuthorizationServerMetadata({
        'issuer': domains.host_url(),
        'authorization_endpoint': domains.host_url('/oauth/authorize'),
        'token_endpoint': domains.host_url('/oauth/token'),
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code'],
        'token_endpoint_auth_methods_supported': [
            'client_secret_basic',
            'client_secret_post',
        ],
        'code_challenge_methods_supported': ['S256', 'plain'],
        'scopes_supported': [],
    })
    metadata.validate()
    return metadata


@app.post('/api/v1/apps')
@log_request_response
def create_app():
    params = request.get_json(silent=True) or request.values

    if not (client_name := params.get('client_name')):
        error('Missing required parameter: client_name', status=400)
    if not (redirect_uris := params.get('redirect_uris')):
        error('Missing required parameter: redirect_uris', status=400)
    if isinstance(redirect_uris, str):
        redirect_uris = redirect_uris.split()

    website = params.get('website') or ''
    client_id = encode_jwt({
        'typ': CLIENT_TYP,
        'client_name': client_name,
        'website': website,
        'redirect_uris': redirect_uris,
    })
    return {
        'id': hash_client_id(client_id)[:16],
        'name': client_name,
        'website': website,
        'redirect_uri': '\n'.join(redirect_uris),
        'redirect_uris': redirect_uris,
        'client_id': client_id,
        'client_secret': client_secret_for(client_id),
        'vapid_key': '',
    }


@app.get('/oauth/authorize')
@app.get('/oauth/authorize/')
@log_request_response
def oauth_authorize():
    return Proxy.authorize_response()


@app.post('/oauth/authorize')
@log_request_response
def oauth_authorize_consent():
    """Shows the authorization consent prompt."""
    return Proxy.consent_response(get_required_param('state'))


@app.post('/oauth/token')
@log_request_response
def oauth_token():
    return server.create_token_response()


#
# IndieAuth backend
#

class ProxyIndieAuthStart(FlashErrors, indieauth.Start):
    ON_ERROR_REDIRECT_TO = '/'


class ProxyIndieAuthCallback(Proxy, FlashErrors, indieauth.Callback):
    pass


app.add_url_rule(
    '/oauth/authorize/indieauth/start',
    view_func=ProxyIndieAuthStart.as_view(
        'proxy_indieauth_start', '/oauth/authorize/indieauth/finish'),
    methods=['POST'])
app.add_url_rule(
    '/oauth/authorize/indieauth/finish',
    view_func=ProxyIndieAuthCallback.as_view(
        'proxy_indieauth_finish', '/oauth/authorize'))


#
# ATProto backend
#

class ProxyAtprotoStart(FlashErrors, oauth_dropins.bluesky.OAuthStart):
    ON_ERROR_REDIRECT_TO = '/'

    @property
    def CLIENT_METADATA(self):
        return atproto.oauth_client_metadata()


class ProxyAtprotoCallback(Proxy, FlashErrors, oauth_dropins.bluesky.OAuthCallback):
    @property
    def CLIENT_METADATA(self):
        return atproto.oauth_client_metadata()


app.add_url_rule(
    '/oauth/authorize/atproto/start',
    view_func=ProxyAtprotoStart.as_view(
        'proxy_atproto_start', '/oauth/authorize/atproto/finish'),
    methods=['POST'])
app.add_url_rule(
    '/oauth/authorize/atproto/finish',
    view_func=ProxyAtprotoCallback.as_view(
        'proxy_atproto_finish', '/oauth/authorize'))
