"""Misc common utilities."""
import base64
from datetime import timedelta
import logging
from pathlib import Path
import re
import threading
import urllib.parse
from urllib.parse import urljoin, urlparse

import cachetools
from Crypto.Util import number
from flask import abort, g, make_response, request
from google.cloud.error_reporting.util import build_flask_context
from google.cloud.ndb.global_cache import _InProcessGlobalCache, MemcacheCache
from google.protobuf.timestamp_pb2 import Timestamp
from oauth_dropins.webutil import util, webmention
from oauth_dropins.webutil.appengine_config import error_reporting_client, tasks_client
from oauth_dropins.webutil import appengine_info
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil import flask_util
import pymemcache.client.base
from pymemcache.test.utils import MockMemcacheClient

logger = logging.getLogger(__name__)

# allow hostname chars (a-z, 0-9, -), allow arbitrary unicode (eg ☃.net), don't
# allow specific chars that we'll often see in webfinger, AP handles, etc. (@, :)
# https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
#
# TODO: preprocess with domain2idna, then narrow this to just [a-z0-9-]
DOMAIN_RE = r'^([^/:;@?!\']+\.)+[^/:@_?!\']+$'
TLD_BLOCKLIST = ('7z', 'asp', 'aspx', 'gif', 'html', 'ico', 'jpg', 'jpeg', 'js',
                 'json', 'php', 'png', 'rar', 'txt', 'yaml', 'yml', 'zip')

CONTENT_TYPE_HTML = 'text/html; charset=utf-8'

PRIMARY_DOMAIN = 'fed.brid.gy'
# protocol-specific subdomains are under this "super"domain
SUPERDOMAIN = '.brid.gy'
# TODO: add a Flask route decorator version of util.canonicalize_domain, then
# use it to canonicalize most UI routes from these to fed.brid.gy.
# TODO: unify with models.PROTOCOLS
PROTOCOL_DOMAINS = (
    'ap.brid.gy',
    'atproto.brid.gy',
    'bsky.brid.gy',
    'web.brid.gy',
    'eefake.brid.gy',
    'fa.brid.gy',
    'other.brid.gy',
)
OTHER_DOMAINS = (
    'bridgy-federated.appspot.com',
    'bridgy-federated.uc.r.appspot.com',
)
LOCAL_DOMAINS = (
  'localhost',
  'localhost:8080',
  'my.dev.com:8080',
)
DOMAINS = (PRIMARY_DOMAIN,) + PROTOCOL_DOMAINS + OTHER_DOMAINS + LOCAL_DOMAINS
# TODO: unify with Bridgy's
DOMAIN_BLOCKLIST = (
    'bsky.social',
    'facebook.com',
    'fb.com',
    't.co',
    'twitter.com',
    'x.com',
)

SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587

# populated in models.reset_protocol_properties
SUBDOMAIN_BASE_URL_RE = None
ID_FIELDS = ['id', 'object', 'actor', 'author', 'inReplyTo', 'url']

CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour

USER_AGENT = 'Bridgy Fed (https://fed.brid.gy/)'
util.set_user_agent(USER_AGENT)

# https://cloud.google.com/appengine/docs/locations
TASKS_LOCATION = 'us-central1'
RUN_TASKS_INLINE = False  # overridden by unit tests

# for Protocol.REQUIRES_OLD_ACCOUNT, how old is old enough
OLD_ACCOUNT_AGE = timedelta(days=14)

if appengine_info.DEBUG or appengine_info.LOCAL_SERVER:
    logger.info('Using in memory mock memcache')
    memcache = MockMemcacheClient()
    global_cache = _InProcessGlobalCache()
else:
    logger.info('Using production Memorystore memcache')
    memcache = pymemcache.client.base.PooledClient(
        '10.126.144.3', timeout=10, connect_timeout=10)  # seconds
    global_cache = MemcacheCache(memcache)


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


def host_url(path_query=None):
    base = request.host_url
    if (util.domain_or_parent_in(request.host, OTHER_DOMAINS)
            # when running locally against prod datastore
            or (not DEBUG and request.host in LOCAL_DOMAINS)):
        base = f'https://{PRIMARY_DOMAIN}'

    assert base
    return urljoin(base, path_query)


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
        return user.user_link()

    if text is None:
        match = re.match(r'https?://([^/]+)/(@|users/)([^/]+)$', url)
        if match:
            text = match.expand(r'@\3@\1')

    return util.pretty_link(url, text=text, **kwargs)


def content_type(resp):
    """Returns a :class:`requests.Response`'s Content-Type, without charset suffix."""
    type = resp.headers.get('Content-Type')
    if type:
        return type.split(';')[0]


def redirect_wrap(url):
    """Returns a URL on our domain that redirects to this URL.

    ...to satisfy Mastodon's non-standard domain matching requirement. :(

    Args:
      url (str)

    * https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
    * https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747

    Returns:
      str: redirect url
    """
    if not url or util.domain_from_link(url) in DOMAINS:
        return url

    return host_url('/r/') + url


def subdomain_wrap(proto, path=None):
    """Returns the URL for a given path on this protocol's subdomain.

    Eg for the path ``foo/bar`` on ActivityPub, returns
    ``https://ap.brid.gy/foo/bar``.

    Args:
      proto (subclass of :class:`protocol.Protocol`)

    Returns:
      str: URL
    """
    subdomain = proto.ABBREV if proto and proto.ABBREV else 'fed'
    return urljoin(f'https://{subdomain}{SUPERDOMAIN}/', path)


def unwrap(val, field=None):
    """Removes our subdomain/redirect wrapping from a URL, if it's there.

    ``val`` may be a string, dict, or list. dicts and lists are unwrapped
    recursively.

    Strings that aren't wrapped URLs are left unchanged.

    Args:
      val (str or dict or list)
      field (str): optional field name for this value

    Returns:
      str: unwrapped url
    """

    if isinstance(val, dict):
        # TODO: clean up. https://github.com/snarfed/bridgy-fed/issues/967
        id = val.get('id')
        if (id and urlparse(id).path.strip('/') in DOMAINS + ('',)
            and util.domain_from_link(id) in DOMAINS):
            # protocol bot user, don't touch its URLs
            return {**val, 'id': unwrap(id)}

        return {f: unwrap(v, field=f) for f, v in val.items()}

    elif isinstance(val, list):
        return [unwrap(v) for v in val]

    elif isinstance(val, str):
        if match := SUBDOMAIN_BASE_URL_RE.match(val):
            unwrapped = match.group('path')
            if field in ID_FIELDS and re.fullmatch(DOMAIN_RE, unwrapped):
                return f'https://{unwrapped}/'
            return unwrapped

    return val


def webmention_endpoint_cache_key(url):
    """Returns cache key for a cached webmention endpoint for a given URL.

    Just the domain by default. If the URL is the home page, ie path is ``/``,
    the key includes a ``/`` at the end, so that we cache webmention endpoints
    for home pages separate from other pages.
    https://github.com/snarfed/bridgy/issues/701

    Example: ``snarfed.org /``

    https://github.com/snarfed/bridgy-fed/issues/423

    Adapted from ``bridgy/util.py``.
    """
    parsed = urllib.parse.urlparse(url)
    key = parsed.netloc
    if parsed.path in ('', '/'):
        key += ' /'

    # logger.debug(f'wm cache key {key}')
    return key


@cachetools.cached(cachetools.TTLCache(50000, 60 * 60 * 2),  # 2h expiration
                   key=webmention_endpoint_cache_key,
                   lock=threading.Lock())
def webmention_discover(url, **kwargs):
    """Thin caching wrapper around :func:`oauth_dropins.webutil.webmention.discover`."""
    return webmention.discover(url, **kwargs)


def add(seq, val):
    """Appends ``val`` to ``seq`` if seq doesn't already contain it.

    Useful for treating repeated ndb properties like sets instead of lists.
    """
    if val not in seq:
        seq.append(val)


def remove(seq, val):
    """Removes ``val`` to ``seq`` if seq contains it.

    Useful for treating repeated ndb properties like sets instead of lists.
    """
    if val in seq:
        seq.remove(val)


def create_task(queue, delay=None, **params):
    """Adds a Cloud Tasks task.

    If running in a local server, runs the task handler inline instead of
    creating a task.

    Args:
      queue (str): queue name
      delay (:class:`datetime.timedelta`): optional, used as task ETA (from now)
      params: form-encoded and included in the task request body

    Returns:
      flask.Response or (str, int): response from either running the task
      inline, if running in a local server, or the response from creating the
      task.
    """
    assert queue
    path = f'/queue/{queue}'

    if RUN_TASKS_INLINE or appengine_info.LOCAL_SERVER:
        logger.info(f'Running task inline: {queue} {params}')
        from router import app
        return app.test_client().post(
            path, data=params, headers={flask_util.CLOUD_TASKS_QUEUE_HEADER: ''})

        # # alternative: run inline in this request context
        # request.form = params
        # endpoint, args = app.url_map.bind(request.server[0])\
        #                             .match(path, method='POST')
        # return app.view_functions[endpoint](**args)

    task = {
        'app_engine_http_request': {
            'http_method': 'POST',
            'relative_uri': path,
            'body': urllib.parse.urlencode(sorted(params.items())).encode(),
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
        },
    }
    if delay:
        eta_seconds = int(util.to_utc_timestamp(util.now()) + delay.total_seconds())
        task['schedule_time'] = Timestamp(seconds=eta_seconds)

    parent = tasks_client.queue_path(appengine_info.APP_ID, TASKS_LOCATION, queue)
    task = tasks_client.create_task(parent=parent, task=task)
    msg = f'Added {queue} task {task.name} : {params}'
    logger.info(msg)
    return msg, 202


def email_me(msg):
    assert False  # not working, SMTP woes :(
    if not DEBUG:
        util.send_email(smtp_host=SMTP_HOST, smtp_port=SMTP_PORT,
                        from_='scufflechuck@gmail.com', to='bridgy-fed@ryanb.org',
                        subject=util.ellipsize(msg), body=msg)


def report_error(msg, **kwargs):
    """Reports an error to StackDriver Error Reporting.

    https://cloud.google.com/error-reporting/docs/reference/libraries#client-libraries-install-python

    If ``DEBUG`` is ``True``, just logs the error.
    """
    if DEBUG:
        logger.error(msg)
    else:
        error_reporting_client.report(
            msg, http_context=build_flask_context(request), **kwargs)


def report_exception(**kwargs):
    """Reports the current exception to StackDriver Error Reporting.

    https://cloud.google.com/error-reporting/docs/reference/libraries#client-libraries-install-python

    If ``DEBUG`` is ``True``, re-raises the exception instead.

    Duplicated in ``bridgy.util``.
    """
    if DEBUG:
        raise

    try:
        error_reporting_client.report_exception(
            http_context=build_flask_context(request), **kwargs)
    except BaseException:
        if not DEBUG:
            logger.warning(f'Failed to report error! {kwargs}', exc_info=True)


PROFILE_ID_RE = re.compile(
    fr"""
      /users?/[^/]+$ |
      /app.bsky.actor.profile/self$ |
      ^did:[a-z0-9:.]+$ |
      ^https://{DOMAIN_RE[1:-1]}/?$
    """, re.VERBOSE)

def global_cache_timeout_policy(key):
    """Cache users and profile objects longer than other objects."""
    if (key and
            (key.kind in ('ActivityPub', 'ATProto', 'Follower', 'MagicKey')
             or key.kind == 'Object' and PROFILE_ID_RE.search(key.name))):
        return int(timedelta(hours=2).total_seconds())

    return int(timedelta(minutes=30).total_seconds())
