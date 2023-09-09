# coding=utf-8
"""Misc common utilities.
"""
import base64
from datetime import timedelta
import logging
import re
import threading
import urllib.parse

import cachetools
from Crypto.Util import number
from flask import abort, g, make_response, request
from oauth_dropins.webutil import util, webmention
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil import appengine_info
from oauth_dropins.webutil.appengine_info import APP_ID, DEBUG

logger = logging.getLogger(__name__)

# allow hostname chars (a-z, 0-9, -), allow arbitrary unicode (eg ☃.net), don't
# allow specific chars that we'll often see in webfinger, AP handles, etc. (@, :)
# https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
#
# TODO: preprocess with domain2idna, then narrow this to just [a-z0-9-]
DOMAIN_RE = r'^[^/:;@?!\']+\.[^/:@_?!\']+$'
TLD_BLOCKLIST = ('7z', 'asp', 'aspx', 'gif', 'html', 'ico', 'jpg', 'jpeg', 'js',
                 'json', 'php', 'png', 'rar', 'txt', 'yaml', 'yml', 'zip')

CONTENT_TYPE_HTML = 'text/html; charset=utf-8'

PRIMARY_DOMAIN = 'fed.brid.gy'
# protocol-specific subdomains are under this "super"domain
SUPERDOMAIN = '.brid.gy'
# TODO: add a Flask route decorator version of util.canonicalize_domain, then
# use it to canonicalize most UI routes from these to fed.brid.gy.
OTHER_DOMAINS = (
    'ap.brid.gy',
    'atp.brid.gy',
    'bluesky.brid.gy',
    'bsky.brid.gy',
    'bridgy-federated.appspot.com',
    'bridgy-federated.uc.r.appspot.com',
    'nostr.brid.gy',
    'web.brid.gy',
)
LOCAL_DOMAINS = (
  'localhost',
  'localhost:8080',
  'my.dev.com:8080',
)
DOMAINS = (PRIMARY_DOMAIN,) + OTHER_DOMAINS + LOCAL_DOMAINS
# TODO: unify with Bridgy's
DOMAIN_BLOCKLIST = (
    # https://github.com/snarfed/bridgy-fed/issues/348
    'aaronparecki.com',
    'facebook.com',
    'fb.com',
    't.co',
    'twitter.com',
)

CACHE_TIME = timedelta(seconds=60)

USER_AGENT = 'Bridgy Fed (https://fed.brid.gy/)'

TASKS_LOCATION = 'us-central1'


def base64_to_long(x):
    """Converts x from URL safe base64 encoding to a long integer.

    Originally from django_salmon.magicsigs. Used in :meth:`User.public_pem`
    and :meth:`User.private_pem`.
    """
    return number.bytes_to_long(base64.urlsafe_b64decode(x))


def long_to_base64(x):
    """Converts x from a long integer to base64 URL safe encoding.

    Originally from django_salmon.magicsigs. Used in :meth:`User.get_or_create`.
    """
    return base64.urlsafe_b64encode(number.long_to_bytes(x))


def host_url(path_query=None):
    base = request.host_url
    if (util.domain_or_parent_in(request.host, OTHER_DOMAINS)
            # when running locally against prod datastore
            or (not DEBUG and request.host in LOCAL_DOMAINS)):
        base = f'https://{PRIMARY_DOMAIN}'

    return urllib.parse.urljoin(base, path_query)


def error(msg, status=400, exc_info=None, **kwargs):
    """Like flask_util.error, but wraps body in JSON."""
    logger.info(f'Returning {status}: {msg}', exc_info=exc_info)
    abort(status, response=make_response({'error': msg}, status), **kwargs)


def pretty_link(url, text=None, **kwargs):
    """Wrapper around util.pretty_link() that converts Mastodon user URLs to @-@.

    Eg for URLs like https://mastodon.social/@foo and
    https://mastodon.social/users/foo, defaults text to @foo@mastodon.social if
    it's not provided.

    Args:
      url: str
      text: str
      kwargs: passed through to :func:`webutil.util.pretty_link`
    """
    if g.user and g.user.is_web_url(url):
        return g.user.user_page_link()

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
      url: string

    https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
    https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747

    Returns: string, redirect url
    """
    if not url or url.startswith(host_url()):
        return url

    return host_url('/r/') + url


def redirect_unwrap(val):
    """Removes our redirect wrapping from a URL, if it's there.

    val may be a string, dict, or list. dicts and lists are unwrapped
    recursively.

    Strings that aren't wrapped URLs are left unchanged.

    Args:
      val: string or dict or list

    Returns: string, unwrapped url
    """
    if isinstance(val, dict):
        return {k: redirect_unwrap(v) for k, v in val.items()}

    elif isinstance(val, list):
        return [redirect_unwrap(v) for v in val]

    elif isinstance(val, str):
        prefix = host_url('/r/')
        if val.startswith(prefix):
            unwrapped = val.removeprefix(prefix)
            if util.is_web(unwrapped):
                return unwrapped
        elif val.startswith(host_url()):
            path = val.removeprefix(host_url())
            if re.match(DOMAIN_RE, path):
                return f'https://{path}/'

    return val


def webmention_endpoint_cache_key(url):
    """Returns cache key for a cached webmention endpoint for a given URL.

    Just the domain by default. If the URL is the home page, ie path is / , the
    key includes a / at the end, so that we cache webmention endpoints for home
    pages separate from other pages. https://github.com/snarfed/bridgy/issues/701

    Example: 'snarfed.org /'

    https://github.com/snarfed/bridgy-fed/issues/423

    Adapted from bridgy/util.py.
    """
    parsed = urllib.parse.urlparse(url)
    key = parsed.netloc
    if parsed.path in ('', '/'):
        key += ' /'

    # logger.debug(f'wm cache key {key}')
    return key


@cachetools.cached(cachetools.TTLCache(50000, 60 * 60 * 2),  # 2h expiration
                   key=webmention_endpoint_cache_key,
                   lock=threading.Lock(),
                   info=True)
def webmention_discover(url, **kwargs):
    """Thin caching wrapper around :func:`web.discover`."""
    return webmention.discover(url, **kwargs)


def add(seq, val):
    """Appends val to seq if seq doesn't already contain it.

    Useful for treating repeated ndb properties like sets instead of lists.
    """
    if val not in seq:
        seq.append(val)


def create_task(queue, **params):
    """Adds a Cloud Tasks task.

    Args:
      queue: string, queue name
      params: form-encoded and included in the task request body
    """
    assert queue

    if appengine_info.LOCAL_SERVER:
        logger.info(f'Would add task: {queue} {params}')
    else:
        task = tasks_client.create_task(
            parent=tasks_client.queue_path(APP_ID, TASKS_LOCATION, queue),
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': f'/_ah/queue/{queue}',
                    'body': urllib.parse.urlencode(params).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            })
        logger.info(f'Added {queue} task {task.name} : {params}')
