"""Serves ATProto OAuth, passes through to other protocols.

Users with accounts bridged into ATProto can use this to log into ATProto clients
with OAuth. We authenticate them by passing through to their native network's auth,
eg IndieAuth for web users.

Returns the account's DID in ``sub``.

ATProto uses a bleeding edge (as of 2026) OAuth profile: CIMD, PAR, DPoP, etc:
https://atproto.com/specs/oauth

TODO: read/write scopes, eg ``transition:generic``

https://github.com/snarfed/bridgy-fed/issues/1785
"""
from datetime import timedelta
import logging
import secrets
import time
import urllib.parse

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2 import cimd, OAuth2Error, rfc7523, rfc9126, rfc9207, rfc9449
from authlib.oauth2.rfc6749 import (
    InvalidClientError,
    InvalidRequestError,
    TokenMixin,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as BaseRefreshTokenGrant
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from flask import request
from google.cloud import ndb
from google.cloud.ndb.key import Key
from joserfc.jwk import KeySet
from oauth_dropins import indieauth
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
import requests
from webutil import models, util
from webutil.appengine_info import DEBUG
from webutil.flask_util import FlashErrors, flash, get_required_param

from atproto import ATProto
from common import render_template
import domains
from flask_app import app
import memcache
import oauth_server
from oauth_server import decode_jwt, encode_jwt, hash_client_id, log_request_response
import pages

logger = logging.getLogger(__name__)

AUTHORIZE_PATH = '/oauth/atproto/authorize'
TOKEN_PATH = '/oauth/atproto/token'
PAR_PATH = '/oauth/atproto/par'

# https://atproto.com/specs/oauth#authorization-scopes
SCOPE = 'atproto'

PAR_TYP = 'atproto-oauth-par'
TOKEN_TYP = 'atproto-oauth-token'
REFRESH_TYP = 'atproto-oauth-refresh'
CODE_TYP = 'atproto-oauth-code'

# RFC 9126 suggests 60s, but our request_uri is a self-contained JWT that we
# decode again at the end of the user's login, after they've authenticated with
# their native network, so it has to outlive that whole round trip.
PAR_MAX_AGE = timedelta(minutes=10)
# ATProto wants under 30m, and 5m if we can't revoke individual access tokens
TOKEN_MAX_AGE = timedelta(minutes=15)
REFRESH_MAX_AGE = timedelta(days=14)

# ATProto clients authenticate with a private_key_jwt assertion, or not at all
TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'private_key_jwt']

# RFC 9126 requires client authentication at the PAR endpoint, but these aren't
# part of the authorization request, and the request_uri we build from it ends
# up in the browser's URL bar, so keep them out of it
CLIENT_AUTH_PARAMS = ('client_assertion', 'client_assertion_type', 'client_secret')

# ATProto requires server-provided DPoP nonces, rotated at least every 5 min
DPOP_NONCE_MAX_AGE = timedelta(minutes=3)

# how long a client's metadata document and JWKS are cached for
CLIENT_METADATA_CACHE_EXPIRE = timedelta(hours=1)


class MemcacheDPoPReplayCache(rfc9449.validator.DPoPReplayCache):
    """Rejects replayed DPoP proofs, shared across all our workers.

    authlib's default is in memory, so a proof replayed against a different
    worker wouldn't be detected.
    """
    def check_and_add(self, jti, expires_at):
        expire = max(int(expires_at - time.time()), 1)
        return bool(memcache.memcache.add(memcache.key(f'dpop-jti-{jti}'), 1,
                                          expire=expire))


@memcache.memoize(expire=CLIENT_METADATA_CACHE_EXPIRE)
def fetch_client_json(url, **kwargs):
    """Fetches a JSON document that a client publishes, eg its metadata or JWKS.

    Raises on failure instead of returning None so that :func:`memcache.memoize`
    doesn't cache failures, which would turn a blip at the client's server into
    an hour of failed logins.

    Module level, not a method on :class:`ClientIdMetadataDocument`, so that
    :func:`memcache.memoize`'s key doesn't include the instance's ``repr``.

    Args:
      url (str)
      kwargs: passed through to :func:`webutil.util.requests_get`

    Returns:
      dict: JSON document

    Raises:
      requests.RequestException: if the fetch fails
      ValueError: if the response isn't JSON
    """
    resp = util.requests_get(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


class ClientIdMetadataDocument(cimd.ClientIdMetadataDocument):
    """Resolves clients by fetching the document at their ``client_id`` URL.

    https://atproto.com/specs/oauth#clients
    """
    def fetch_client_id_metadata_document(self, client_id):
        # the authorization server MUST NOT follow redirects when fetching a
        # client ID metadata document, and only 200 is success
        # https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document#section-5
        try:
            return fetch_client_json(client_id, allow_redirects=False)
        except (requests.RequestException, ValueError) as e:
            logger.info(e)
            util.interpret_http_exception(e)
            return None

    def resolve_client_id_metadata_document(self, client_id):
        """Adds ATProto's localhost development clients, for the dev server.

        Their metadata is in the ``client_id``'s query string instead of a
        document to fetch, so authlib's client ID metadata document support
        doesn't cover them.
        https://atproto.com/specs/oauth#localhost-client-development
        """
        if not DEBUG or not client_id.startswith('http://localhost'):
            return super().resolve_client_id_metadata_document(client_id)

        params = urllib.parse.parse_qs(urllib.parse.urlparse(client_id).query)
        redirect_uris = params.get('redirect_uri') or ['http://127.0.0.1/']
        claims = cimd.ClientMetadataClaims({
            'client_id': client_id,
            'client_name': 'Localhost dev client',
            'redirect_uris': redirect_uris,
            'scope': (params.get('scope') or [SCOPE])[0],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method': 'none',
        }, {}, params={'client_id': client_id})
        return cimd.ClientIdMetadataDocumentClient(claims)


class DPoP(rfc9449.DPoP):
    """ATProto requires DPoP."""
    def get_client_metadata(self, client):
        return rfc9449.ClientMetadataClaims({'dpop_bound_access_tokens': True})


class PushedAuthorizationEndpoint(rfc9126.PushedAuthorizationEndpoint):
    """Returns the pushed request in the ``request_uri`` itself, as a JWT.

    The JWT is self-contained and provides all data.
    """
    REQUEST_URI_EXPIRES_IN = int(PAR_MAX_AGE.total_seconds())

    def create_endpoint_response(self, request):
        # ATProto requires a DPoP proof here, not just at the token endpoint,
        # and authlib's DPoP extension only hooks the token endpoint's grants.
        # Binding the code to this key is stronger than the optional dpop_jkt
        # request parameter, so it wins over any the client sent.
        dpop_jkt = proof_validator.validate_proof(request)

        # super() validates the request, then hands the random request_uri it
        # generated to our no-op save_request_payload; replace it with the JWT
        # that actually carries the pushed params.
        status, body, headers = super().create_endpoint_response(request)
        params = {k: v for k, v in request.payload.data.items()
                  if k not in CLIENT_AUTH_PARAMS}
        body['request_uri'] = f'{self.REQUEST_URI_PREFIX}:' + encode_jwt({
            'typ': PAR_TYP,
            # real wall-clock time; PyJWT checks 'exp' against it regardless of
            # any test-time mocking
            'exp': int(time.time() + self.REQUEST_URI_EXPIRES_IN),
            'params': {**params, 'dpop_jkt': dpop_jkt},
        })
        return status, body, headers

    def save_request_payload(self, payload, request_uri, expires_at):
        pass


class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
    """Require PAR, and read the pushed request back out of its JWT."""
    def get_request_payload(self, request_uri):
        prefix = f'{PushedAuthorizationEndpoint.REQUEST_URI_PREFIX}:'
        if not request_uri.startswith(prefix):
            return None

        # TODO: request_uris are single use per RFC 9126. Mark spent ones in
        # memcache, like the authorization codes in mastodon_oauth; right now
        # they're only good for PAR_MAX_AGE.
        if payload := decode_jwt(request_uri.removeprefix(prefix), PAR_TYP):
            return payload['params']

    def handle_request_uri_data(self, request_uri_data, server, request):
        if request.payload.client_id != request_uri_data.get('client_id'):
            raise InvalidRequestError(
                'This request_uri was issued to a different client.')

        super().handle_request_uri_data(request_uri_data, server, request)

    def get_server_metadata(self):
        return rfc9126.AuthorizationServerMetadata(
            {'require_pushed_authorization_requests': True})


class RefreshToken(rfc9449.TokenMixin, TokenMixin):
    """In-memory refresh token; the token itself is a self-contained JWT."""
    def __init__(self, payload):
        self.user_key = Key(urlsafe=payload['user_key'])
        self.scope = payload.get('scope') or ''
        self.dpop_jkt = (payload.get('cnf') or {}).get('jkt')
        self.client_id_hash = payload['client_id_hash']

    def get_scope(self):
        return self.scope

    def is_expired(self):
        # the JWT's own exp is checked when we decode it
        return False

    def is_revoked(self):
        # TODO: check a denylist of revoked jtis, if/when we add that
        # POST /oauth/atproto/revoke
        return False

    def get_dpop_jkt(self):
        return self.dpop_jkt

    def check_client(self, client):
        """Only the client this token was issued to can refresh it."""
        return self.client_id_hash == hash_client_id(client.get_client_id())


def generate_token(oauth_request, user, scope, include_refresh_token=True):
    """Builds the token endpoint's response.

    Not registered with :meth:`AuthorizationServer.register_token_generator`,
    since that doesn't see the request, and we need its DPoP key binding.

    Args:
      oauth_request (authlib.oauth2.rfc6749.OAuth2Request)
      user (models.User)
      scope (str)
      include_refresh_token (bool)

    Returns:
      dict:
    """
    did = user.get_copy(ATProto)
    user_key = user.key.urlsafe().decode()
    client_id_hash = hash_client_id(oauth_request.client.get_client_id())

    # bind these to the client's DPoP key
    # https://datatracker.ietf.org/doc/html/rfc9449#section-6
    cnf = {'jkt': getattr(oauth_request.payload, 'dpop_jkt', None)}

    # real wall-clock time, not util.now(): PyJWT checks 'exp' against real time
    # regardless of any test-time mocking
    now = int(time.time())

    resp = {
        'access_token': encode_jwt({
            'typ': TOKEN_TYP,
            'exp': now + int(TOKEN_MAX_AGE.total_seconds()),
            'jti': secrets.token_urlsafe(16),
            'sub': did,
            'user_key': user_key,
            'scope': scope,
            'cnf': cnf,
            'client_id_hash': client_id_hash,
        }),
        'token_type': 'DPoP',
        'expires_in': int(TOKEN_MAX_AGE.total_seconds()),
        'scope': scope or '',
        # ATProto requires the account's DID here
        'sub': did,
    }

    if include_refresh_token:
        resp['refresh_token'] = encode_jwt({
            'typ': REFRESH_TYP,
            'exp': now + int(REFRESH_MAX_AGE.total_seconds()),
            'jti': secrets.token_urlsafe(16),
            'user_key': user_key,
            'scope': scope,
            'cnf': cnf,
            'client_id_hash': client_id_hash,
        })

    return resp


class AuthorizationCodeGrant(oauth_server.JwtAuthorizationCodeGrant):
    CODE_TYP = CODE_TYP
    TOKEN_ENDPOINT_AUTH_METHODS = TOKEN_ENDPOINT_AUTH_METHODS

    def generate_token(self, user=None, scope=None, grant_type=None,
                       expires_in=None, include_refresh_token=True):
        return generate_token(self.request, user, scope, include_refresh_token)


class RefreshTokenGrant(BaseRefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = TOKEN_ENDPOINT_AUTH_METHODS
    INCLUDE_NEW_REFRESH_TOKEN = True

    def generate_token(self, user=None, scope=None, grant_type=None,
                       expires_in=None, include_refresh_token=True):
        return generate_token(self.request, user, scope, include_refresh_token)

    def authenticate_refresh_token(self, refresh_token):
        if payload := decode_jwt(refresh_token, REFRESH_TYP):
            return RefreshToken(payload)

    def authenticate_user(self, credential):
        return credential.user_key.get()

    def revoke_old_credential(self, credential):
        # TODO: ATProto refresh tokens are single use. Mark spent jtis in
        # memcache; right now the old one stays valid for REFRESH_MAX_AGE.
        pass


class JWTClientAuth(rfc7523.JWTBearerClientAssertion):
    """``private_key_jwt`` auth for confidential clients.

    https://atproto.com/specs/oauth#confidential-clients
    """
    CLIENT_AUTH_METHOD = 'private_key_jwt'

    def get_audiences(self):
        return [domains.host_url().rstrip('/'), domains.host_url(TOKEN_PATH)]

    def validate_jti(self, claims, jti):
        # TODO: track spent jtis in memcache to make assertions single use.
        # They're only good for their (short) exp for now.
        return True

    def resolve_client_public_key(self, client, headers=None):
        """Returns the keys from the client's metadata document."""
        metadata = client.client_metadata
        if jwks := metadata.get('jwks'):
            return KeySet.import_key_set(jwks)

        if jwks_uri := metadata.get('jwks_uri'):
            try:
                return KeySet.import_key_set(fetch_client_json(jwks_uri))
            except (requests.RequestException, ValueError) as e:
                logger.info(e)
                util.interpret_http_exception(e)
                raise InvalidClientError(
                    description=f"Couldn't fetch the client's JWKS at {jwks_uri}") from e

        raise InvalidClientError(
            description='Client has no jwks or jwks_uri to verify its assertion.')


class IssuerParameter(rfc9207.IssuerParameter):
    """Adds ``iss`` to authorization responses, which ATProto requires."""
    def get_issuer(self):
        return domains.host_url().rstrip('/')


def metadata():
    """Serves our authorization server metadata document.

    https://atproto.com/specs/oauth#authorization-server-metadata

    The ``/.well-known/oauth-authorization-server`` route that serves this is in
    :mod:`app`, since :mod:`mastodon_oauth` serves its own on every other host.
    """
    md = AuthorizationServerMetadata({
        # the issuer must be a bare origin, no trailing slash
        'issuer': domains.host_url().rstrip('/'),
        'authorization_endpoint': domains.host_url(AUTHORIZE_PATH),
        'token_endpoint': domains.host_url(TOKEN_PATH),
        'pushed_authorization_request_endpoint': domains.host_url(PAR_PATH),
        'require_pushed_authorization_requests': True,
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
        # no 'plain'; ATProto requires S256
        'code_challenge_methods_supported': ['S256'],
        # must match what the grants actually accept
        'token_endpoint_auth_methods_supported': TOKEN_ENDPOINT_AUTH_METHODS,
        'token_endpoint_auth_signing_alg_values_supported': ['ES256'],
        'dpop_signing_alg_values_supported': ['ES256'],
        'scopes_supported': [SCOPE],
        'authorization_response_iss_parameter_supported': True,
        'client_id_metadata_document_supported': True,
    })
    md.validate(metadata_classes=[
        cimd.AuthorizationServerMetadata,
        rfc9126.AuthorizationServerMetadata,
        rfc9207.AuthorizationServerMetadata,
        rfc9449.AuthorizationServerMetadata,
    ])
    return md


proof_validator = rfc9449.DPoPProofValidator(
    algs=['ES256'],
    nonce_generator=rfc9449.HMACDPoPNonceGenerator(
        models.ENCRYPTED_PROPERTY_KEYS_BYTES[0],
        max_age=int(DPOP_NONCE_MAX_AGE.total_seconds())),
    replay_cache=MemcacheDPoPReplayCache())

server = AuthorizationServer(
    app,
    # every ATProto client is a client ID metadata document client, which the
    # ClientIdMetadataDocument extension resolves by wrapping this
    query_client=lambda client_id: None,
    # noop; our tokens are self-contained, not stored
    save_token=lambda token, request: None)

par_endpoint = PushedAuthorizationEndpoint(server)
server.register_endpoint(par_endpoint)
# ATProto requires PKCE, always, with S256
server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
server.register_grant(RefreshTokenGrant)
server.register_extension(PushedAuthorizationRequest())
server.register_extension(ClientIdMetadataDocument(allow_loopback=DEBUG))
server.register_extension(DPoP(proof_validator))
server.register_extension(IssuerParameter())
server.register_client_auth_method(JWTClientAuth.CLIENT_AUTH_METHOD, JWTClientAuth())


class Proxy(oauth_server.Proxy):
    SERVER = server
    AUTHORIZE_PATH = AUTHORIZE_PATH
    PROTO = ATProto

    @classmethod
    def check_user(cls, user, params):
        if not (user := super().check_user(user, params)):
            return None

        # "If a login_hint was supplied, the Authorization Server should only
        # allow the user to authenticate with that account."
        # https://atproto.com/specs/oauth#authorization-interface
        if hint := params.get('login_hint'):
            if hint.lstrip('@') not in (user.get_copy(ATProto),
                                        user.handle_as(ATProto)):
                flash(f'This app asked you to log in as {hint}.')
                return None

        return user


@app.after_request
def add_dpop_nonce(resp):
    """Hands out a fresh DPoP nonce on success, not just on errors.

    authlib puts ``DPoP-Nonce`` on :class:`UseDPoPNonceError` responses, but
    clients also need one from successful responses, so that their next request
    doesn't have to be rejected first.
    """
    if request.path in (PAR_PATH, TOKEN_PATH):
        resp.headers.setdefault('DPoP-Nonce', proof_validator.nonce_generator.next())

    return resp


@app.post(PAR_PATH)
@log_request_response
def par():
    """https://datatracker.ietf.org/doc/html/rfc9126"""
    return server.create_endpoint_response(par_endpoint.ENDPOINT_NAME)


@app.get(AUTHORIZE_PATH)
@log_request_response
def authorize():
    try:
        grant = server.get_consent_grant()
    except OAuth2Error as err:
        logger.info(err)
        return server.handle_error_response(None, err)

    # only offer accounts that check_user will actually accept
    logins = [l for l in ndb.get_multi(pages.login_to_user_key(l)
                                       for l in pages.get_logins())
              if l and l.is_enabled(ATProto)]

    return render_template(
        'oauth_login.html',
        client_name=grant.client.client_metadata.get('client_name') or grant.client.get_client_id(),
        state=request.query_string.decode(), existing_logins=logins,
        authorize_path=AUTHORIZE_PATH,
        # you can't log in with an ATProto account to use an ATProto account
        hide=['bluesky', 'blacksky'])


@app.post(AUTHORIZE_PATH)
@log_request_response
def authorize_consent():
    """Handles the authorization consent prompt."""
    grant_user = None
    if not request.form.get('deny') and (key := request.form.get('user_key')):
        grant_user = Key(urlsafe=key).get()

    return Proxy.grant_or_deny(grant_user, get_required_param('state'))


@app.post(TOKEN_PATH)
@log_request_response
def token():
    return server.create_token_response()


#
# proxy login backends: everything that can be bridged into ATProto
#

class ProxyIndieAuthStart(FlashErrors, indieauth.Start):
    ON_ERROR_REDIRECT_TO = '/'


class ProxyIndieAuthCallback(Proxy, FlashErrors, indieauth.Callback):
    pass


class ProxyMastodonStart(FlashErrors, oauth_dropins.mastodon.Start):
    ON_ERROR_REDIRECT_TO = '/'

    def app_name(self):
        return 'Bridgy Fed'

    def app_url(self):
        return 'https://fed.brid.gy/'


class ProxyMastodonCallback(Proxy, FlashErrors, oauth_dropins.mastodon.Callback):
    pass


class ProxyPixelfedStart(FlashErrors, oauth_dropins.pixelfed.Start):
    ON_ERROR_REDIRECT_TO = '/'

    def app_name(self):
        return 'Bridgy Fed'

    def app_url(self):
        return 'https://fed.brid.gy/'


class ProxyPixelfedCallback(Proxy, FlashErrors, oauth_dropins.pixelfed.Callback):
    pass


app.add_url_rule(
    f'{AUTHORIZE_PATH}/indieauth/start',
    view_func=ProxyIndieAuthStart.as_view(
        'atproto_proxy_indieauth_start', f'{AUTHORIZE_PATH}/indieauth/finish'),
    methods=['POST'])
app.add_url_rule(
    f'{AUTHORIZE_PATH}/indieauth/finish',
    view_func=ProxyIndieAuthCallback.as_view(
        'atproto_proxy_indieauth_finish', AUTHORIZE_PATH))

app.add_url_rule(
    f'{AUTHORIZE_PATH}/mastodon/start',
    view_func=ProxyMastodonStart.as_view(
        'atproto_proxy_mastodon_start', f'{AUTHORIZE_PATH}/mastodon/finish'),
    methods=['POST'])
app.add_url_rule(
    f'{AUTHORIZE_PATH}/mastodon/finish',
    view_func=ProxyMastodonCallback.as_view(
        'atproto_proxy_mastodon_finish', AUTHORIZE_PATH))

app.add_url_rule(
    f'{AUTHORIZE_PATH}/pixelfed/start',
    view_func=ProxyPixelfedStart.as_view(
        'atproto_proxy_pixelfed_start', f'{AUTHORIZE_PATH}/pixelfed/finish'),
    methods=['POST'])
app.add_url_rule(
    f'{AUTHORIZE_PATH}/pixelfed/finish',
    view_func=ProxyPixelfedCallback.as_view(
        'atproto_proxy_pixelfed_finish', AUTHORIZE_PATH))
