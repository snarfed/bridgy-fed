"""HTTP proxy that injects our webmention endpoint.
"""
import datetime
import urllib.parse

import flask
from flask import request
import requests

from app import app, cache
import common

LINK_HEADER = '<%s>; rel="webmention"'
CACHE_TIME = datetime.timedelta(seconds=15)


@app.route(r'/wm/<path:url>')
@cache.cached(timeout=CACHE_TIME.total_seconds(), query_string=True,
              response_filter=common.not_5xx)
def add_wm(url=None):
    """Proxies HTTP requests and adds Link header to our webmention endpoint."""
    url = urllib.parse.unquote(url)
    if not url.startswith('http://') and not url.startswith('https://'):
        common.error('URL must start with http:// or https://')

    try:
        got = common.requests_get(url)
    except requests.exceptions.Timeout as e:
        common.error(str(e), status=504, exc_info=True)
    except requests.exceptions.RequestException as e:
        common.error(str(e), status=502, exc_info=True)

    resp = flask.make_response(got.content, got.status_code, dict(got.headers))
    resp.headers.add('Link', LINK_HEADER % (request.args.get('endpoint') or
                                            request.host_url + 'webmention'))
    return resp
