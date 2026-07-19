"""Serves Mastodon OAuth, passes through to other protocols."""
from datetime import datetime, timedelta
import hashlib
import hmac
import logging
import os
import time
from urllib.parse import parse_qsl

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request
from authlib.integrations.flask_oauth2.resource_protector import current_token
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import (
    AccessDeniedError,
    AuthorizationCodeGrant,
    AuthorizationCodeMixin,
    ClientMixin,
    OAuth2Request,
    TokenMixin,
)
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7636 import CodeChallenge, create_s256_code_challenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from flask import redirect, Response, request
from google.cloud import ndb
from google.cloud.ndb.key import Key
import jwt
from oauth_dropins import indieauth
import oauth_dropins.bluesky
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
from webutil import util
from webutil.models import ENCRYPTED_PROPERTY_KEYS_BYTES
from webutil.flask_util import error, FlashErrors, flash, get_required_param
from werkzeug.exceptions import HTTPException

from activitypub import ActivityPub
import common
from common import render_template
import domains
from flask_app import app
import pages

logger = logging.getLogger(__name__)

JWT_ALG = 'HS256'
CLIENT_TYP = 'mastodon-oauth-client'
CODE_TYP = 'mastodon-oauth-code'
TOKEN_TYP = 'mastodon-oauth-token'
CODE_MAX_AGE = timedelta(seconds=60)
OOB_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def log_request_response(fn):
    """Logs the full request and response for this view."""
    def wrapper(*args, **kwargs):
        logger.info(f'>> {request.method} {request.url}')
        if auth := request.headers.get('Authorization'):
            logger.info(f'>> Authorization: {auth}')
        if body := request.get_data(as_text=True):
            logger.info(f'>> body: {body}')
        elif request.form:
            logger.info(f'>> form: {dict(request.form)}')

        try:
            resp = fn(*args, **kwargs)
        except HTTPException as e:
            # authlib's own HTTPException subclass carries the real error body in
            # .body instead of .description
            body = getattr(e, 'body', None) or e.description
            logger.info(f'<< {e.code}: {body}')
            raise

        if not isinstance(resp, str):
            logger.info(f'<< {resp}')

        return resp

    wrapper.__name__ = fn.__name__
    return wrapper


def hash_client_id(client_id):
    return hashlib.sha256(client_id.encode()).hexdigest()


def encode_jwt(val):
    return jwt.encode(val, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0], algorithm=JWT_ALG)


def decode_jwt(val, typ):
    """Decodes a JWT and checks its ``typ``."""
    try:
        payload = jwt.decode(val, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0],
                             algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        logger.info(f'decode failed for {val}: {e}')
        return None

    if payload.get('typ') != typ:
        logger.info(f"expected type {typ} but got {payload['typ']} in {val}")
        return None

    return payload


def client_secret_for(client_id):
    return hmac.new(ENCRYPTED_PROPERTY_KEYS_BYTES[0], client_id.encode(),
                    hashlib.sha256).hexdigest()


class Client(ClientMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.ClientMixin`.

    ``client_id`` is self-contained; nothing is stored.
    """
    def __init__(self, client_id, payload):
        self.client_id = client_id
        self.client_name = payload['client_name']
        self.website = payload.get('website')
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


class AuthCode(AuthorizationCodeMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.AuthorizationCodeMixin`.

    Unsigned from a self-contained authorization code; nothing is stored.
    """
    def __init__(self, payload):
        self.user_key = Key(urlsafe=payload['user_key'])
        self.redirect_uri = payload['redirect_uri']
        self.scope = payload.get('scope') or ''
        self.code_challenge = payload.get('code_challenge')
        self.code_challenge_method = payload.get('code_challenge_method')

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class BFAuthorizationCodeGrant(AuthorizationCodeGrant):
    def create_authorization_response(self, redirect_uri, grant_user):
        # out of band flow for non-web clients that can't show a webview
        if redirect_uri == OOB_REDIRECT_URI:
            logger.info('oob flow, rendering an authorization code')

            if not grant_user:
                raise AccessDeniedError(redirect_uri=redirect_uri)

            self.request.user = grant_user
            code = self.generate_authorization_code()
            self.save_authorization_code(code, self.request)
            return 200, render_template('mastodon_oauth_code.html', code=code), []

        return super().create_authorization_response(redirect_uri, grant_user)

    def generate_authorization_code(self):
        return encode_jwt({
            'typ': CODE_TYP,
            # real wall-clock time, not util.now(): PyJWT checks 'exp' against real
            # time regardless of any test-time mocking
            'exp': int(time.time() + CODE_MAX_AGE.total_seconds()),
            'user_key': self.request.user.key.urlsafe().decode(),
            'client_id_hash': hash_client_id(self.request.client.get_client_id()),
            # same defaulting as authlib itself, in create_authorization_response();
            # the resolved redirect_uri isn't otherwise available here
            'redirect_uri': (self.request.payload.redirect_uri
                             or self.request.client.get_default_redirect_uri()),
            'scope': self.request.scope,
            'code_challenge': self.request.payload.data.get('code_challenge'),
            'code_challenge_method': self.request.payload.data.get('code_challenge_method'),
        })

    def save_authorization_code(self, code, request):
        pass

    def query_authorization_code(self, code, client):
        if not (payload := decode_jwt(code, CODE_TYP)):
            return None

        client_id_hash = hash_client_id(client.get_client_id())
        if payload['client_id_hash'] != client_id_hash:
            logger.info(f"query_authorization_code: client_id_hash mismatch, code was issued to {payload['client_id_hash']}, token request is from {client.get_client_id()} (hash {client_id_hash})")
            return None

        return AuthCode(payload)

    def delete_authorization_code(self, authorization_code):
        # TODO: mark spent codes in memcache so they're single-use; right now
        # they're only good for CODE_MAX_AGE.
        pass

    def authenticate_user(self, authorization_code):
        return authorization_code.user_key.get()


class Token(TokenMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.TokenMixin`.

    The access token itself is self-contained and provides all data.
    """
    def __init__(self, payload):
        self.user_key = Key(urlsafe=payload['user_key'])
        self.scope = payload.get('scope') or ''

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return 0

    def is_expired(self):
        return False

    def is_revoked(self):
        # TODO: check a datastore denylist of revoked token hashes, once we add
        # POST /oauth/revoke. Storing only revocations keeps this stateless in
        # the common case.
        return False

    def get_user(self):
        return self.user_key.get()

    def get_client(self):
        return None

    def check_client(self, client):
        return True


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
        'typ': TOKEN_TYP,
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
server.register_grant(BFAuthorizationCodeGrant, [CodeChallenge(required=False)])

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerValidator())


@app.get('/.well-known/oauth-authorization-server')
@app.get('/.well-known/oauth-authorization-server/')
@log_request_response
def oauth_metadata():
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


def _grant_or_deny(grant_user, state):
    """Common prompt decision logic.

    Applies the beta gate, then finishes (or denies) the OAuth authorization
    response for the original ``/oauth/authorize`` request captured in ``state``.

    Args:
      grant_user (models.User): the resolved Bridgy Fed user, or None to deny
      state (str): the original ``/oauth/authorize`` query string
    """
    if grant_user and grant_user.key.id() not in common.BETA_USER_IDS:
        flash('Mastodon OAuth login is limited to beta testers for now.')
        grant_user = None

    params = dict(parse_qsl(state or ''))
    req = OAuth2Request('GET', domains.host_url('/oauth/authorize'))
    req.payload = BasicOAuth2Payload(params)

    try:
        grant = server.get_authorization_grant(req)
        resp = server.create_authorization_response(
            request=req, grant_user=grant_user, grant=grant)
    except OAuth2Error as err:
        logger.info(err)
        resp = server.handle_error_response(None, err)

    logger.info(f'<< {resp.get_data(as_text=True)}, Location: {resp.headers.get("Location")}')
    return resp


def _finish_proxy_login(auth_entity, state):
    """Common ``finish()`` logic for every backend's proxy login callback.

    Resolves the oauth-dropins auth entity to a Bridgy Fed user via
    :func:`pages.login_to_user_key`, then hands off to :func:`_grant_or_deny`.
    """
    logger.info(f'auth_entity: {auth_entity}, state: {state}')

    if not auth_entity:
        flash("OK, you're not logged in.")
        return redirect('/')

    if (not (user_key := pages.login_to_user_key(auth_entity))
            or not (grant_user := user_key.get())):
        flash("That account isn't set up on Bridgy Fed yet.")
        return redirect('/')

    return _grant_or_deny(grant_user, state)


@app.get('/oauth/authorize')
@app.get('/oauth/authorize/')
@log_request_response
def oauth_authorize():
    try:
        grant = server.get_consent_grant()
    except OAuth2Error as err:
        logger.info(err)
        return server.handle_error_response(None, err)

    logins = ndb.get_multi(pages.login_to_user_key(l) for l in pages.get_logins())
    client_name = grant.request.client.client_name
    state = request.query_string.decode()

    return render_template('mastodon_oauth_login.html', client_name=client_name,
                           state=state, existing_logins=logins)


@app.post('/oauth/authorize')
@log_request_response
def oauth_authorize_consent():
    """Shows the authorization consent prompt."""
    grant_user = None
    if not request.form.get('deny') and (key := request.form.get('user_key')):
        grant_user = Key(urlsafe=key).get()

    return _grant_or_deny(grant_user, get_required_param('state'))


@app.post('/oauth/token')
@log_request_response
def oauth_token():
    return server.create_token_response()


@app.get('/api/v2/instance')
@app.get('/api/v2/instance/')
@log_request_response
def instance_v2():
    return {
        'domain': request.host,
        'title': 'Bridgy Fed',
        'version': os.getenv('GAE_VERSION'),
        'source_url': 'https://fed.brid.gy/',
        'description': 'Bridges other networks to the fediverse',
        'thumbnail': {},
        'languages': ['en'],
        'configuration': {},
        'registrations': {'enabled': False, 'approval_required': False},
        'contact': {
            'email': 'feedback@brid.gy',
        },
        'rules': [],
    }


@app.get('/api/v1/accounts/verify_credentials')
@app.get('/api/v1/accounts/verify_credentials/')
@log_request_response
@require_oauth()
def verify_credentials():
    if not (user := current_token.get_user()):
        error('Account not found', status=401)

    # TODO: move to granary.mastodon
    obj_as1 = user.obj.as1 if user.obj and user.obj.as1 else {}
    image = util.get_url(obj_as1, 'image')
    return {
        'id': user.key.id(),
        'uri': user.id_as(ActivityPub),
        'username': user.handle,
        'acct': user.handle,
        'display_name': user.name(),
        'url': user.web_url(),
        'avatar': image,
        'avatar_static': image,
        'header': '',
        'header_static': '',
        'note': obj_as1.get('summary'),
        'locked': False,
        'bot': False,
        'created_at': obj_as1.get('published'),
        'followers_count': 0,
        'following_count': 0,
        'statuses_count': 0,
    }


#
# IndieAuth
#

class ProxyIndieAuthStart(FlashErrors, indieauth.Start):
    ON_ERROR_REDIRECT_TO = '/'


class ProxyIndieAuthCallback(FlashErrors, indieauth.Callback):
    ON_ERROR_REDIRECT_TO = '/'

    def finish(self, auth_entity, state=None):
        return _finish_proxy_login(auth_entity, state)


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
# Bluesky
#

def _bluesky_proxy_client_metadata():
    return {
        **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
        'client_id': domains.host_url('/oauth/authorize/bluesky/client-metadata.json'),
        'client_name': 'Bridgy Fed (Mastodon API)',
        'client_uri': domains.host_url(),
        'redirect_uris': [domains.host_url('/oauth/authorize/bluesky/finish')],
    }


@app.get('/oauth/authorize/bluesky/client-metadata.json')
def bluesky_proxy_client_metadata():
    return _bluesky_proxy_client_metadata()


class ProxyBlueskyStart(FlashErrors, oauth_dropins.bluesky.OAuthStart):
    ON_ERROR_REDIRECT_TO = '/'

    @property
    def CLIENT_METADATA(self):
        return _bluesky_proxy_client_metadata()


class ProxyBlueskyCallback(FlashErrors, oauth_dropins.bluesky.OAuthCallback):
    ON_ERROR_REDIRECT_TO = '/'

    @property
    def CLIENT_METADATA(self):
        return _bluesky_proxy_client_metadata()

    def finish(self, auth_entity, state=None):
        return _finish_proxy_login(auth_entity, state)


app.add_url_rule(
    '/oauth/authorize/bluesky/start',
    view_func=ProxyBlueskyStart.as_view(
        'proxy_bluesky_start', '/oauth/authorize/bluesky/finish'),
    methods=['POST'])
app.add_url_rule(
    '/oauth/authorize/bluesky/finish',
    view_func=ProxyBlueskyCallback.as_view(
        'proxy_bluesky_finish', '/oauth/authorize'))
