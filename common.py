"""Misc common utilities."""
import base64
from datetime import timedelta
import functools
import logging
import os
from pathlib import Path
import re
import threading
import urllib.parse
from urllib.parse import urljoin, urlparse

from Crypto.Util import number
import flask
from flask import abort, g, has_request_context, make_response, redirect, request
from flask.views import View
from google.cloud.error_reporting.util import build_flask_context
from google.cloud import ndb
from google.cloud.ndb.key import Key
from google.protobuf.timestamp_pb2 import Timestamp
from granary import as2
import jwt
from oauth_dropins.webutil import flask_util, util, webmention
from oauth_dropins.webutil.appengine_config import error_reporting_client, tasks_client
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER
from oauth_dropins.webutil.models import ENCRYPTED_PROPERTY_KEY_BYTES
from oauth_dropins.webutil.util import interpret_http_exception, json_dumps
from negotiator import ContentNegotiator, AcceptParameters, ContentType
import requests
import werkzeug.exceptions
from werkzeug.exceptions import HTTPException

import config
from domains import (
    DOMAIN_RE,
    DOMAINS,
    LOCAL_DOMAINS,
    OTHER_DOMAINS,
    PROTOCOL_DOMAINS,
    PRIMARY_DOMAIN,
    SUBDOMAIN_BASE_URL_RE,
    SUPERDOMAIN,
)
import memcache

logger = logging.getLogger(__name__)

CONTENT_TYPE_HTML = 'text/html; charset=utf-8'

GCP_PROJECT_ID = 'bridgy-federated'  # used in create_task

CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour
CACHE_CONTROL_VARY_ACCEPT = {**CACHE_CONTROL, 'Vary': 'Accept'}

NDB_MEMCACHE_TIMEOUT = timedelta(hours=2)

USER_AGENT = 'Bridgy Fed (https://fed.brid.gy/)'
util.set_user_agent(USER_AGENT)

# https://cloud.google.com/appengine/docs/locations
TASKS_LOCATION = 'us-central1'
RUN_TASKS_INLINE = False  # overridden by unit tests

# for Protocol.REQUIRES_OLD_ACCOUNT, how old is old enough
OLD_ACCOUNT_AGE = timedelta(days=7)

# populated later in this file
NDB_CONTEXT_KWARGS = None

_negotiator = ContentNegotiator(acceptable=[
    AcceptParameters(ContentType(CONTENT_TYPE_HTML)),
    AcceptParameters(ContentType(as2.CONTENT_TYPE)),
    AcceptParameters(ContentType(as2.CONTENT_TYPE_LD)),
])

# User ids who opt into testing new "beta" features and changes before we roll them
# out to everyone.
with open(Path(os.path.dirname(__file__)) / 'beta_users.txt') as f:
  BETA_USER_IDS = util.load_file_lines(f)

class ErrorButDoNotRetryTask(HTTPException):
    code = 299
    description = 'ErrorButDoNotRetryTask'

# https://github.com/pallets/flask/issues/1837#issuecomment-304996942
werkzeug.exceptions.default_exceptions.setdefault(299, ErrorButDoNotRetryTask)
werkzeug.exceptions._aborter.mapping.setdefault(299, ErrorButDoNotRetryTask)


@functools.cache
def bot_user_ids():
    """Returns all copy ids for protocol bot users."""
    from models import PROTOCOLS
    from web import Web

    bot_ids = set(PROTOCOL_DOMAINS)
    protocols = set(p for p in PROTOCOLS.values() if p and p.LABEL != 'ui')

    for bot_proto in protocols:
        subdomain = f'{bot_proto.ABBREV}{SUPERDOMAIN}'
        if not (bot := Web.get_by_id(subdomain)):
            continue

        bot_ids.update(copy.uri for copy in bot.copies)

        for other_proto in protocols:
            if (bot_proto != other_proto and not other_proto.HAS_COPIES
                    and other_proto.LABEL not in bot_proto.DEFAULT_ENABLED_PROTOCOLS):
                bot_ids.add(bot.id_as(other_proto))

    return bot_ids


def base64_to_long(x):
    """Converts from URL safe base64 encoding to long integer.

    Originally from ``django_salmon.magicsigs``. Used in :meth:`User.public_pem`
    and :meth:`User.private_pem`.
    """
    return number.bytes_to_long(base64.urlsafe_b64decode(x))


def long_to_base64(x):
    """Converts from long integer to base64 URL safe encoding.

    Originally from ``django_salmon.magicsigs``. Used in :meth:`User.get_or_create`.
    """
    return base64.urlsafe_b64encode(number.long_to_bytes(x))


def error(err, status=400, exc_info=None, **kwargs):
    """Like :func:`oauth_dropins.webutil.flask_util.error`, but wraps body in JSON."""
    msg = str(err)
    logger.info(f'Returning {status}: {msg}', exc_info=exc_info)
    abort(status, response=make_response({'error': msg}, status), **kwargs)


def pretty_link(url, text=None, user=None, **kwargs):
    """Wrapper around :func:`oauth_dropins.webutil.util.pretty_link` that converts Mastodon user URLs to @-@ handles.

    Eg for URLs like https://mastodon.social/@foo and
    https://mastodon.social/users/foo, defaults text to ``@foo@mastodon.social``
    if it's not provided.

    Args:
      url (str)
      text (str)
      user (models.User): current user
      kwargs: passed through to :func:`oauth_dropins.webutil.util.pretty_link`
    """
    if user and user.is_web_url(url):
        return user.html_link(handle=False, pictures=True)

    if text is None:
        match = re.match(r'https?://([^/]+)/(@|users/)([^/]+)$', url)
        if match:
            text = match.expand(r'@\3@\1')

    return util.pretty_link(url, text=text, **kwargs)


def content_type(resp):
    """Returns a :class:`requests.Response`'s Content-Type, without charset suffix."""
    type = resp.headers.get('Content-Type')
    if type:
        # TODO: don't remove profile
        # right now, when we remove it, and don't use it to compare against eg
        # as2.CONTENT_TYPE_LD, we end up accepting non-AS2 JSON-LD, eg:
        # Content-Type: application/ld+json; charset=UTF-8
        return type.split(';')[0]


def create_task(queue, app_id=GCP_PROJECT_ID, delay=None, app=None, **params):
    """Adds a Cloud Tasks task.

    If running in a local server, runs the task handler inline instead of
    creating a task.

    Args:
      queue (str): queue name
      delay (:class:`datetime.timedelta`): optional, used as task ETA (from now)
      app (flask.Flask): if not provided, defaults to ``router.app``
      params: form-encoded and included in the task request body

    Returns:
      flask.Response or (str, int): response from either running the task
      inline, if running in a local server, or the response from creating the
      task.
    """
    assert queue
    path = f'/queue/{queue}'

    # removed from "Added X task ..." log message below to cut logging costs
    # https://github.com/snarfed/bridgy-fed/issues/1149#issuecomment-2265861956
    # loggable = {k: '{...}' if isinstance(v, dict) else v for k, v in params.items()}
    params = {
        k: json_dumps(v, sort_keys=True) if isinstance(v, dict) else v
        for k, v in params.items()
        if v is not None
    }

    try:
        authorization = request.headers.get('Authorization') or ''
        traceparent = request.headers.get('traceparent') or ''
    except RuntimeError:  # not currently in a request context
        authorization = traceparent = ''

    if RUN_TASKS_INLINE or LOCAL_SERVER:
        logger.info(f'Running task inline: {queue} {params}')
        if not app:
            from router import app
        return app.test_client().post(path, data=params, headers={
              flask_util.CLOUD_TASKS_TASK_HEADER: 'inline',
              'Authorization': authorization,
        })

        # # alternative: run inline in this request context
        # request.form = params
        # endpoint, args = app.url_map.bind(request.server[0])\
        #                             .match(path, method='POST')
        # return app.view_functions[endpoint](**args)

    # determine task ETA
    eta = None
    now = util.now()
    if authed_as := params.get('authed_as'):
        eta = memcache.task_eta(queue, authed_as)

    if delay:
        if not eta:
            eta = now
        eta += delay

    schedule_time = None
    delay_msg = 'now'
    if eta and eta > now + timedelta(seconds=1):
        schedule_time = Timestamp(seconds=int(eta.timestamp()))
        # we use the received_at param to measure and log our task processing delay.
        # skip that if we're deliberately rate limiting/delaying the task.
        params.pop('received_at', None)
        delay_msg = f'in {eta - now}'

    # construct task object
    body = urllib.parse.urlencode(sorted(params.items())).encode()
    task = {
        'app_engine_http_request': {
            'http_method': 'POST',
            'relative_uri': path,
            'body': body,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': (request.headers.get('Authorization', '')
                                  if flask.has_request_context() else ''),
                # propagate trace id
                # https://cloud.google.com/trace/docs/trace-context#http-requests
                # https://stackoverflow.com/a/71343735/186123
                'traceparent': traceparent,
            },
        },
    }
    if schedule_time:
        task['schedule_time'] = schedule_time

    parent = tasks_client.queue_path(app_id, TASKS_LOCATION, queue)
    task = tasks_client.create_task(parent=parent, task=task)

    msg = f'Added {queue} {task.name.split("/")[-1]} {delay_msg}'
    if delay_msg or not traceparent:
        logger.info(msg)

    return msg, 202


def report_exception(**kwargs):
    return report_error(msg=None, exception=True, **kwargs)


def report_error(msg, *, exception=False, **kwargs):
    """Reports an error to StackDriver Error Reporting.

    https://cloud.google.com/python/docs/reference/clouderrorreporting/latest/google.cloud.error_reporting.client.Client

    If ``DEBUG`` and ``exception`` are ``True``, re-raises the exception instead.

    Duplicated in ``bridgy.util``.
    """
    if DEBUG or LOCAL_SERVER:
        if DEBUG and exception:
            raise
        else:
            # must be at warning level. logging with exception at error level or
            # above will report to prod error reporting
            logger.warning(msg, exc_info=exception)
            return

    http_context = build_flask_context(request) if has_request_context() else None

    try:
        if exception:
            logger.error(msg, exc_info=True)
            error_reporting_client.report_exception(msg, http_context=http_context,
                                                    **kwargs)
        else:
            logger.error(msg)
            error_reporting_client.report(msg, http_context=http_context, **kwargs)
    except BaseException:
        kwargs['exception'] = exception
        logger.warning(f'Failed to report error! {kwargs}', exc_info=exception)


def cache_policy(key):
    """In memory ndb cache.

    https://github.com/snarfed/bridgy-fed/issues/1149#issuecomment-2261383697

    Only cache kinds in memory that are immutable or largely harmless when changed.

    Keep an eye on this in case we start seeing problems due to this ndb bug
    where unstored in-memory modifications get returned by later gets:
    https://github.com/googleapis/python-ndb/issues/888

    Args:
      key (google.cloud.datastore.key.Key or google.cloud.ndb.key.Key):
        see https://github.com/googleapis/python-ndb/issues/987

    Returns:
      bool: whether to cache this object
    """
    if isinstance(key, Key):
        # use internal google.cloud.datastore.key.Key
        # https://github.com/googleapis/python-ndb/issues/987
        key = key._key

    return key and key.kind in ('AtpBlock', 'AtpSequence', 'Object')


def global_cache_policy(key):
    return True


def global_cache_timeout_policy(key):
    """Cache everything for 2h.

    Args:
      key (google.cloud.datastore.key.Key or google.cloud.ndb.key.Key):
        see https://github.com/googleapis/python-ndb/issues/987

    Returns:
      int: cache expiration for this object, in seconds
    """
    return int(NDB_MEMCACHE_TIMEOUT.total_seconds())


NDB_CONTEXT_KWARGS = {
    'cache_policy': cache_policy,
    'global_cache': memcache.global_cache,
    'global_cache_policy': global_cache_policy,
    'global_cache_timeout_policy': global_cache_timeout_policy,
}


def log_request():
    """Logs GET query params and POST form.

    Limits each value to 1000 chars."""
    logger.info(f'Params:\n' + '\n'.join(
        f'{k} = {v[:1000]}' for k, v in request.values.items()))


def secret_key_auth(fn):
    """Flask decorator that returns HTTP 401 if the request isn't authorized.

    Right now this only handles internal authorization: the ``Authorization`` header
    has to be set to the Flask secret key in the ``flask_secret_key`` file.

    Ignored if ``LOCAL_SERVER`` is True.

    Must be used *below* :meth:`flask.Flask.route`, eg:

        @app.route('/path')
        @secret_key_auth
        def handler():
            ...
    """
    @functools.wraps(fn)
    def decorated(*args, **kwargs):
        if request.headers.get('Authorization') != config.SECRET_KEY:
            return '', 401

        return fn(*args, **kwargs)

    return decorated


def make_jwt(*, user, scope, expiration=timedelta(weeks=1), **claims):
    """Makes a per-user JWT signed by our EncryptedProperty symmetric key.

    Args:
      user (User)
      scope (str)
      expiration (timedelta)
      **claims (str: str): optional additional claims

    Returns:
      str:
    """
    claims.update({
      'sub': user.key.id(),
      'scope': scope,
      'exp': util.now() + expiration,
    })
    return jwt.encode(claims, key=ENCRYPTED_PROPERTY_KEY_BYTES, algorithm='HS256')


def verify_jwt(token, *, user_id, scope, **claims):
    """Verifies a per-user JWT and checks that it matches a user, scope, etc.

    Raises the appropriate werkzeug HTTPException if the JWT doesn't verify or match,
    otherwise returns None.

    Args:
      token (str)
      user_id (str)
      scope (str)
      **claims (str: str): optional additional claims to check

    Raises:
      werkzeug.exceptions.Unauthorized: if the token is invalid
      werkzeug.exceptions.Forbidden: if the token is valid but for the wrong user or
        scope
    """
    decoded = jwt.decode(token, key=ENCRYPTED_PROPERTY_KEY_BYTES,
                         algorithms=['HS256'])

    for key, expected in list(claims.items()) + [('sub', user_id), ('scope', scope)]:
      if (got := decoded.get(key)) != expected:
        raise ValueError(f'expected {key} {expected}, got {got}')


class FlashErrors(View):
    """Wraps a Flask :class:`flask.view.View` and flashes errors.

    Mostly used with OAuth endpoints.
    """
    def dispatch_request(self):
        try:
            return super().dispatch_request()
        except (ValueError, requests.RequestException) as e:
            logger.warning(f'{self.__class__.__name__} error', exc_info=True)
            _, body = interpret_http_exception(e)
            flask_util.flash(util.linkify(body or str(e), pretty=True))
            return redirect('/login')


def render_template(template, **kwargs):
    return flask.render_template(
        template,
        isinstance=isinstance,
        request=request,
        set=set,
        util=util,
        **kwargs)
