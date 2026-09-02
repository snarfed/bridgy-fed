"""Common code for our OAuth server implementations.

We serve OAuth for more than one protocol - Mastodon in :mod:`mastodon_oauth`,
ATProto in :mod:`atproto_oauth` - and they both work the same way: we're the
authorization server, but we don't have any credentials of our own for the user,
so we authenticate them by passing through to whatever auth their original
account supports, eg IndieAuth for web users.
"""
from datetime import timedelta
import hashlib
import logging
import time
from urllib.parse import parse_qsl

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import (
    AuthorizationCodeGrant,
    AuthorizationCodeMixin,
    OAuth2Request,
)
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from flask import redirect, request
from google.cloud.ndb.key import Key
import jwt
from webutil import models
from webutil.flask_util import flash
from werkzeug.exceptions import HTTPException

import common
import domains
import pages

logger = logging.getLogger(__name__)

JWT_ALG = 'HS256'


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


def encode_jwt(val):
    return jwt.encode(val, key=models.ENCRYPTED_PROPERTY_KEYS_BYTES[0], algorithm=JWT_ALG)


def decode_jwt(val, typ):
    """Decodes a JWT and checks its ``typ``."""
    try:
        payload = jwt.decode(val, key=models.ENCRYPTED_PROPERTY_KEYS_BYTES[0],
                             algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        logger.info(f'decode failed for {val}: {e}')
        return None

    if payload.get('typ') != typ:
        logger.info(f"expected type {typ} but got {payload['typ']} in {val}")
        return None

    return payload


def hash_client_id(client_id):
    return hashlib.sha256(client_id.encode()).hexdigest()


class AuthCode(AuthorizationCodeMixin):
    """In-memory :class:`authlib.oauth2.rfc6749.AuthorizationCodeMixin`.

    The authorization code is a self-contained JWT that provides all data.
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


class JwtAuthorizationCodeGrant(AuthorizationCodeGrant):
    """Authorization code grant whose codes are self-contained JWTs.

    Nothing is stored: the code carries all its own data, signed with our key,
    and expires on its own. Subclasses set :attr:`CODE_TYP`.
    """
    CODE_TYP = None
    """str: ``typ`` for this server's code JWTs, eg ``mastodon-oauth-code``."""
    CODE_MAX_AGE = timedelta(seconds=60)

    def generate_authorization_code(self):
        payload = self.request.payload
        return encode_jwt({
            'typ': self.CODE_TYP,
            # real wall-clock time, not util.now(): PyJWT checks 'exp' against real
            # time regardless of any test-time mocking
            'exp': int(time.time() + self.CODE_MAX_AGE.total_seconds()),
            'user_key': self.request.user.key.urlsafe().decode(),
            'client_id_hash': hash_client_id(self.request.client.get_client_id()),
            # same defaulting as authlib itself, in create_authorization_response();
            # the resolved redirect_uri isn't otherwise available here
            'redirect_uri': (payload.redirect_uri
                             or self.request.client.get_default_redirect_uri()),
            'scope': self.request.scope,
            'code_challenge': payload.data.get('code_challenge'),
            'code_challenge_method': payload.data.get('code_challenge_method'),
        })

    def save_authorization_code(self, code, request):
        pass

    def query_authorization_code(self, code, client):
        if not (payload := decode_jwt(code, self.CODE_TYP)):
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


class Proxy:
    """One OAuth server's proxy login.

    Each OAuth server subclasses this once, filling in the class attrs below.
    That subclass then also serves as a base class for the server's proxy login
    ``Callback`` views, which is how they get :meth:`finish`.
    """
    SERVER = None
    """authlib.oauth2.rfc6749.AuthorizationServer: this server."""
    AUTHORIZE_PATH = None
    """str: this server's authorization endpoint, eg ``/oauth/authorize``."""
    PROTO = None
    """protocol.Protocol: users must be bridged into this to log in here."""

    # for oauth_dropins' FlashErrors
    ON_ERROR_REDIRECT_TO = '/'

    @classmethod
    def check_user(cls, user, params):
        """Returns ``user`` if they're allowed to log into this server.

        Otherwise flashes why and returns None.

        Args:
          user (models.User)
          params (dict): the authorization request's parameters

        Returns:
          models.User or None:
        """
        if user.key.id() not in common.BETA_USER_IDS:
            flash('OAuth login is limited to beta testers for now.')
            return None

        if not user.is_enabled(cls.PROTO):
            flash(f"{user.handle_or_id()} isn't bridged to {cls.PROTO.PHRASE} yet.")
            return None

        return user

    @classmethod
    def grant_or_deny(cls, grant_user, state):
        """Finishes, or denies, the authorization request captured in ``state``.

        Args:
          grant_user (models.User): the resolved Bridgy Fed user, or None to deny
          state (str): the original authorize request's query string
        """
        req = OAuth2Request('GET', domains.host_url(cls.AUTHORIZE_PATH))
        req.payload = BasicOAuth2Payload(dict(parse_qsl(state or '')))

        try:
            # get the grant first: it's what resolves a PAR request_uri back
            # into the parameters the client actually pushed, which is what
            # check_user needs to see
            grant = cls.SERVER.get_authorization_grant(req)
            if grant_user:
                grant_user = cls.check_user(grant_user, req.payload.data)

            resp = cls.SERVER.create_authorization_response(
                request=req, grant_user=grant_user, grant=grant)
        except OAuth2Error as err:
            logger.info(err)
            resp = cls.SERVER.handle_error_response(None, err)

        logger.info(f'<< {resp.get_data(as_text=True)}, Location: {resp.headers.get("Location")}')
        return resp

    def finish(self, auth_entity, state=None):
        """``finish()`` for every backend's proxy login callback view.

        Resolves the oauth-dropins auth entity to a Bridgy Fed user via
        :func:`pages.login_to_user_key`, then hands off to :meth:`grant_or_deny`.
        """
        logger.info(f'auth_entity: {auth_entity}, state: {state}')

        if not auth_entity:
            flash("OK, you're not logged in.")
            return redirect('/')

        if (not (user_key := pages.login_to_user_key(auth_entity))
                or not (grant_user := user_key.get())):
            flash("That account isn't set up on Bridgy Fed yet.")
            return redirect('/')

        return self.grant_or_deny(grant_user, state)
