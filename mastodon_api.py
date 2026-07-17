"""Serves Mastodon API and OAuth, passes through to other protocols."""
from datetime import timedelta
import hashlib
import hmac
import logging
import time
from urllib.parse import parse_qsl

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request
from authlib.integrations.flask_oauth2.resource_protector import current_token
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import AccessDeniedError, AuthorizationCodeGrant, OAuth2Request
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7636 import CodeChallenge, create_s256_code_challenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from flask import redirect, request
from google.cloud.ndb.key import Key
import jwt
from oauth_dropins import indieauth
from webutil import util
from webutil.models import ENCRYPTED_PROPERTY_KEYS_BYTES
from webutil.flask_util import error, FlashErrors, flash
from werkzeug.exceptions import HTTPException

import common
from common import render_template
from flask_app import app
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)

JWT_ALG = 'HS256'
CLIENT_TYP = 'mastodon-oauth-client'
CODE_TYP = 'mastodon-oauth-code'
TOKEN_TYP = 'mastodon-oauth-token'
CODE_MAX_AGE = timedelta(seconds=60)
OOB_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def _web_only(fn):
    """Decorator that 404s unless the request is on a ``Web``-backed subdomain."""
    def wrapper(*args, **kwargs):
        if Protocol.for_request(fed=Web) is not Web:
            error('Not found', status=404)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def _response_body(resp):
    if isinstance(resp, tuple):
        resp = resp[0]
    if hasattr(resp, 'get_data'):
        return resp.get_data(as_text=True)
    return repr(resp)


def _logged(fn):
    """Logs the full request and response for this view, at INFO level.

    TEMPORARY, for debugging the OAuth flow against real clients. This logs
    sensitive material -- tokens, client secrets, auth codes -- so it should come
    back out once we're done chasing interop bugs.
    """
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

        logger.info(f'<< {_response_body(resp)}')
        return resp

    wrapper.__name__ = fn.__name__
    return wrapper


def hash_client_id(client_id):
    return hashlib.sha256(client_id.encode()).hexdigest()


def encode_client(client_name, website, redirect_uris):
    return jwt.encode({
        'typ': CLIENT_TYP,
        'client_name': client_name,
        'website': website,
        'redirect_uris': redirect_uris,
    }, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0], algorithm=JWT_ALG)


def decode_client(client_id):
    try:
        payload = jwt.decode(client_id, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0],
                             algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        logger.info(f'decode_client failed for {client_id!r}: {e}')
        return None

    if payload.get('typ') != CLIENT_TYP:
        logger.info(f"decode_client: wrong typ {payload.get('typ')!r} for {client_id!r}")
        return None

    return payload


def client_secret_for(client_id):
    return hmac.new(ENCRYPTED_PROPERTY_KEYS_BYTES[0], client_id.encode(),
                    hashlib.sha256).hexdigest()


def encode_code(*, user_key, client_id, redirect_uri, scope, code_challenge,
                code_challenge_method):
    return jwt.encode({
        'typ': CODE_TYP,
        # real wall-clock time, not util.now(): PyJWT checks 'exp' against real time
        # regardless of any test-time mocking
        'exp': int(time.time() + CODE_MAX_AGE.total_seconds()),
        'user_key': user_key.urlsafe().decode(),
        'client_id_hash': hash_client_id(client_id),
        'redirect_uri': redirect_uri,
        'scope': scope,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
    }, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0], algorithm=JWT_ALG)


def decode_code(code):
    try:
        payload = jwt.decode(code, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0],
                             algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        logger.info(f'decode_code failed for {code!r}: {e}')
        return None

    if payload.get('typ') != CODE_TYP:
        logger.info(f"decode_code: wrong typ {payload.get('typ')!r} for {code!r}")
        return None

    return payload


def encode_token(*, user_key, client_id, scope):
    return jwt.encode({
        'typ': TOKEN_TYP,
        'user_key': user_key.urlsafe().decode(),
        'client_id_hash': hash_client_id(client_id),
        'scope': scope,
    }, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0], algorithm=JWT_ALG)


def decode_token(token):
    try:
        payload = jwt.decode(token, key=ENCRYPTED_PROPERTY_KEYS_BYTES[0],
                             algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        logger.info(f'decode_token failed for {token!r}: {e}')
        return None

    if payload.get('typ') != TOKEN_TYP:
        logger.info(f"decode_token: wrong typ {payload.get('typ')!r} for {token!r}")
        return None

    return payload


class Client:
    """In-memory :class:`authlib.oauth2.rfc6749.ClientMixin`.

    Unsigned from a self-encoding ``client_id``; nothing is stored.
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
        return hmac.compare_digest(client_secret_for(self.client_id), client_secret)

    def check_endpoint_auth_method(self, method, endpoint):
        return True

    def check_response_type(self, response_type):
        return response_type == 'code'

    def check_grant_type(self, grant_type):
        return grant_type == 'authorization_code'


def query_client(client_id):
    if payload := decode_client(client_id):
        return Client(client_id, payload)
    logger.info(f'query_client: no client for {client_id!r}')


def save_token(token, request):
    """No-op; our tokens are self-encoding and never stored."""
    pass


def generate_bearer_token(grant_type, client, user=None, scope=None,
                          expires_in=None, include_refresh_token=True):
    token = encode_token(user_key=user.key, client_id=client.get_client_id(),
                         scope=scope)
    return {
        'access_token': token,
        'token_type': 'Bearer',
        'scope': scope or '',
        'created_at': int(time.time()),
    }


class AuthCode:
    """In-memory :class:`authlib.oauth2.rfc6749.AuthorizationCodeMixin`.

    Unsigned from a self-encoding authorization code; nothing is stored.
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
        if redirect_uri != OOB_REDIRECT_URI:
            return super().create_authorization_response(redirect_uri, grant_user)

        # can't redirect to the oob URN, so show the code as text instead, like
        # real Mastodon does
        if not grant_user:
            raise AccessDeniedError(redirect_uri=redirect_uri)

        self.request.user = grant_user
        code = self.generate_authorization_code()
        self.save_authorization_code(code, self.request)
        return 200, render_template('oauth_code.html', code=code), []

    def generate_authorization_code(self):
        req = self.request
        # same defaulting authlib itself applies in create_authorization_response();
        # the resolved redirect_uri isn't otherwise available here
        redirect_uri = req.payload.redirect_uri or req.client.get_default_redirect_uri()
        return encode_code(
            user_key=req.user.key,
            client_id=req.client.get_client_id(),
            redirect_uri=redirect_uri,
            scope=req.scope,
            code_challenge=req.payload.data.get('code_challenge'),
            code_challenge_method=req.payload.data.get('code_challenge_method'),
        )

    def save_authorization_code(self, code, request):
        pass

    def query_authorization_code(self, code, client):
        payload = decode_code(code)
        if not payload:
            return None
        if payload['client_id_hash'] != hash_client_id(client.get_client_id()):
            logger.info(f"query_authorization_code: client_id_hash mismatch, "
                       f"code was issued to {payload['client_id_hash']!r}, "
                       f"token request is from {client.get_client_id()!r} "
                       f"(hash {hash_client_id(client.get_client_id())!r})")
            return None
        return AuthCode(payload)

    def delete_authorization_code(self, authorization_code):
        # TODO: mark spent codes in memcache so they're single-use; right now
        # they're only good for CODE_MAX_AGE.
        pass

    def authenticate_user(self, authorization_code):
        return authorization_code.user_key.get()


class Token:
    """In-memory :class:`authlib.oauth2.rfc6749.TokenMixin`.

    Unsigned from a self-encoding access token; nothing is stored.
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
    def authenticate_token(self, token_string):
        if payload := decode_token(token_string):
            return Token(payload)


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


class BFAuthorizationServer(AuthorizationServer):
    def create_oauth2_request(self, _request):
        return JsonAwareOAuth2Request(request)


server = BFAuthorizationServer(app, query_client, save_token)
server.register_token_generator('default', generate_bearer_token)
server.register_grant(BFAuthorizationCodeGrant, [CodeChallenge(required=False)])

require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerValidator())


def _oauth_error_response(error):
    logger.info(f'OAuth2Error: {error.error} {getattr(error, "description", None)}')
    return server.handle_response(*error(server.get_error_uri(None, error)))


@app.get('/.well-known/oauth-authorization-server')
@app.get('/.well-known/oauth-authorization-server/')
@_logged
@_web_only
def oauth_metadata():
    # mirrors the request's actual scheme; in production this is always https
    # (ProxyFix reads X-Forwarded-Proto). For plain-http local testing, set
    # AUTHLIB_INSECURE_TRANSPORT=1 so both this and authlib's own per-request
    # checks accept it.
    base = request.host_url.rstrip('/')
    metadata = AuthorizationServerMetadata({
        'issuer': base,
        'authorization_endpoint': f'{base}/oauth/authorize',
        'token_endpoint': f'{base}/oauth/token',
        'registration_endpoint': f'{base}/oauth/register',
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code'],
        'token_endpoint_auth_methods_supported': [
            'client_secret_basic', 'client_secret_post'],
        'code_challenge_methods_supported': ['S256', 'plain'],
        'scopes_supported': [],
    })
    metadata.validate()
    return metadata


@app.post('/api/v1/apps')
@_logged
@_web_only
def create_app():
    params = request.get_json(silent=True) or request.values

    if not (client_name := params.get('client_name')):
        error('Missing required parameter: client_name', status=400)
    if not (redirect_uris := params.get('redirect_uris')):
        error('Missing required parameter: redirect_uris', status=400)
    if isinstance(redirect_uris, str):
        redirect_uris = redirect_uris.split()

    website = params.get('website') or ''
    client_id = encode_client(client_name, website, redirect_uris)
    return {
        'id': hash_client_id(client_id)[:16],
        'name': client_name,
        'website': website,
        'redirect_uri': redirect_uris[0],
        'client_id': client_id,
        'client_secret': client_secret_for(client_id),
        'vapid_key': '',
    }


@app.post('/oauth/register')
@_logged
@_web_only
def oauth_register():
    data = request.get_json(force=True, silent=True) or {}
    redirect_uris = data.get('redirect_uris') or []
    if not redirect_uris:
        error("'redirect_uris' is required", status=400)

    client_name = data.get('client_name') or ''
    website = data.get('client_uri') or ''
    client_id = encode_client(client_name, website, redirect_uris)
    return {
        'client_id': client_id,
        'client_secret': client_secret_for(client_id),
        'client_id_issued_at': int(time.time()),
        'client_secret_expires_at': 0,
        'client_name': client_name,
        'redirect_uris': redirect_uris,
    }, 201


@app.get('/oauth/authorize')
@app.get('/oauth/authorize/')
@_logged
@_web_only
def oauth_authorize():
    try:
        grant = server.get_consent_grant()
    except OAuth2Error as oauth_error:
        return _oauth_error_response(oauth_error)

    return render_template('oauth_authorize.html',
                           client_name=grant.request.client.client_name,
                           state=request.query_string.decode())


class MastodonIndieAuthStart(FlashErrors, indieauth.Start):
    ON_ERROR_REDIRECT_TO = '/'

    def redirect_url(self, state=None, me=None):
        logger.info(f'>> POST {request.url}')
        logger.info(f'>> form: {dict(request.form)}')

        me = me or request.values['me'].strip()
        domain = util.domain_from_link(me)
        if domain not in common.BETA_USER_IDS:
            logger.info(f'<< 403: {domain} is not a beta user')
            error('Mastodon OAuth login is limited to beta testers for now.',
                 status=403)

        url = super().redirect_url(state=state, me=me)
        logger.info(f'<< redirecting to {url}')
        return url


class MastodonIndieAuthCallback(FlashErrors, indieauth.Callback):
    ON_ERROR_REDIRECT_TO = '/'

    def finish(self, auth_entity, state=None):
        logger.info(f'>> GET {request.url}')
        logger.info(f'>> auth_entity: {auth_entity.key.id() if auth_entity else None}, '
                   f'state: {state!r}')

        if not auth_entity:
            flash('Login canceled.')
            logger.info(f'<< redirecting to {self.ON_ERROR_REDIRECT_TO}')
            return redirect(self.ON_ERROR_REDIRECT_TO)

        domain = util.domain_from_link(auth_entity.key.id())
        grant_user = Web.get_by_id(domain)
        logger.info(f'grant_user for {domain}: {grant_user}')
        if not grant_user:
            flash(f"{domain} isn't set up on Bridgy Fed yet.")

        params = dict(parse_qsl(state or ''))
        logger.info(f'authorize params from state: {params}')
        req = OAuth2Request('GET', f'{request.host_url.rstrip("/")}/oauth/authorize')
        req.payload = BasicOAuth2Payload(params)

        try:
            grant = server.get_authorization_grant(req)
            resp = server.create_authorization_response(
                request=req, grant_user=grant_user, grant=grant)
        except OAuth2Error as oauth_error:
            return _oauth_error_response(oauth_error)

        logger.info(f'<< {_response_body(resp)}, '
                   f'Location: {resp.headers.get("Location")}')
        return resp


app.add_url_rule(
    '/oauth/authorize/indieauth/start',
    view_func=MastodonIndieAuthStart.as_view(
        'mastodon_indieauth_start', '/oauth/authorize/indieauth/finish'),
    methods=['POST'])
app.add_url_rule(
    '/oauth/authorize/indieauth/finish',
    view_func=MastodonIndieAuthCallback.as_view(
        'mastodon_indieauth_finish', '/oauth/authorize'))


@app.post('/oauth/token')
@_logged
@_web_only
def oauth_token():
    return server.create_token_response()


@app.get('/api/v2/instance')
@app.get('/api/v2/instance/')
@_logged
@_web_only
def instance_v2():
    return {
        'domain': request.host,
        'title': 'Bridgy Fed',
        'version': '4.0.0',
        'source_url': 'https://github.com/snarfed/bridgy-fed',
        'description': 'Bridgy Fed',
        'usage': {'users': {'active_month': 0}},
        'thumbnail': {},
        'languages': ['en'],
        'configuration': {},
        'registrations': {'enabled': False, 'approval_required': False},
        'contact': {},
        'rules': [],
    }


def account_dict(user):
    as1 = user.obj.as1 if user.obj and user.obj.as1 else {}
    # AS1 image may be a string, dict, or list of either
    image = util.get_url(as1, 'image') or ''
    return {
        'id': user.key.id(),
        'username': user.handle,
        'acct': user.handle,
        'display_name': user.name(),
        'url': user.web_url(),
        'avatar': image,
        'avatar_static': image,
        'header': '',
        'header_static': '',
        'note': as1.get('summary') or '',
        'locked': False,
        'bot': False,
        'created_at': as1.get('published') or '',
        'followers_count': 0,
        'following_count': 0,
        'statuses_count': 0,
    }


@app.get('/api/v1/accounts/verify_credentials')
@app.get('/api/v1/accounts/verify_credentials/')
@_logged
@_web_only
@require_oauth()
def verify_credentials():
    if not (user := current_token.get_user()):
        error('Account not found', status=401)

    return account_dict(user)
