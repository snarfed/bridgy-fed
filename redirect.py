"""Simple conneg endpoint that serves AS2 or redirects to to the original post.

Only for :class:`web.Web` users. Other protocols (including :class:`web.Web`
sometimes) use ``/convert/`` in convert.py instead.

Serves ``/r/https://foo.com/bar`` URL paths, where ``https://foo.com/bar`` is a
original post for a :class:`Web` user. Needed for Mastodon interop, they require
that AS2 object ids and urls are on the same domain that serves them.
Background:

* https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
* https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747

The conneg makes these ``/r/`` URLs searchable in Mastodon:
https://github.com/snarfed/bridgy-fed/issues/352
"""
from datetime import timedelta
import logging
import re
import urllib.parse

from flask import redirect, request
from granary import as1
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads

from activitypub import ActivityPub
from common import (
    as2_request_type,
    CACHE_CONTROL_VARY_ACCEPT,
    CONTENT_TYPE_HTML,
    SUPERDOMAIN,
)
from flask_app import app
import memcache
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)

DOMAIN_ALLOWLIST = frozenset((
    'bsky.app',
))


@app.get(r'/r/<path:to>')
@memcache.memoize(expire=timedelta(hours=1), key=lambda to: (to, as2_request_type()))
@flask_util.headers(CACHE_CONTROL_VARY_ACCEPT)
def redir(to):
    """Either redirect to a given URL or convert it to another format.

    E.g. redirects ``/r/https://foo.com/bar?baz`` to
    ``https://foo.com/bar?baz``, or if it's requested with AS2 conneg in the
    ``Accept`` header, fetches and converts and serves it as AS2.
    """
    to = to.strip()
    if request.args:
        to += '?' + urllib.parse.urlencode(request.args)
    # some browsers collapse repeated /s in the path down to a single slash.
    # if that happened to this URL, expand it back to two /s.
    to = re.sub(r'^(https?:/)([^/])', r'\1/\2', to)

    if not util.is_web(to):
        error(f'Expected fully qualified URL; got {to}')

    try:
        to_domain = urllib.parse.urlparse(to).hostname
    except ValueError as e:
        error(f'Invalid URL {to} : {e}')

    if to_domain and to_domain.endswith(SUPERDOMAIN):
        return redirect(to, code=301)

    # check conneg
    as2_request = as2_request_type()

    # check that we've seen this domain before so we're not an open redirect
    domains = set((util.domain_from_link(to, minimize=True),
                   util.domain_from_link(to, minimize=False),
                   to_domain))
    web_user = None
    for domain in domains:
        if domain:
            if domain in DOMAIN_ALLOWLIST:
                break
            if web_user := Web.get_by_id(domain):
                logger.debug(f'Found web user for domain {domain}')
                break
    else:
        if not as2_request:
            return f'No web user found for any of {domains}', 404

    if not as2_request:
        # redirect. include rel-alternate link to make posts discoverable by entering
        # https://fed.brid.gy/r/[URL] in a fediverse instance's search.
        logger.debug(f'redirecting to {to}')
        return f"""\
    <!doctype html>
    <html>
    <head>
    <link href="{request.url}" rel="alternate" type="application/activity+json">
    </head>
    <title>Redirecting...</title>
    <h1>Redirecting...</h1>
    <p>You should be redirected automatically to the target URL: <a href="{to}">{to}</a>. If not, click the link.
    </html>
    """, 301, {'Location': to}

    # AS2 requested, fetch and convert and serve
    proto = Protocol.for_id(to)
    if not proto:
        return f"Couldn't determine protocol for {to}", 404

    obj = proto.load(to)
    if not obj or obj.deleted:
        return f'Object not found: {to}', 404

    if proto == Web:
        if not web_user:
            return f'Object not found: {to}', 404
    else:
        if obj.type in as1.ACTOR_TYPES:
            user = proto.query(proto.obj_key == obj.key).get()
            if not user or not user.is_enabled(ActivityPub):
                return f'Object not found: {to}', 404

    ret = ActivityPub.convert(obj, from_user=web_user)
    # logger.info(f'Returning: {json_dumps(ret, indent=2)}')
    return ret, {
        'Content-Type': as2_request,
        'Access-Control-Allow-Origin': '*',
    }

