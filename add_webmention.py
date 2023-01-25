"""HTTP proxy that injects our webmention endpoint.
"""
import datetime
import urllib.parse

import flask
from flask import request
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
import requests

from app import app, cache
import common

LINK_HEADER = '<%s>; rel="webmention"'


@app.get(r'/wm/<path:url>')
@flask_util.cached(cache, common.CACHE_TIME, http_5xx=True)
def add_wm(url=None):
    """Proxies HTTP requests and adds Link header to our webmention endpoint."""
    url = urllib.parse.unquote(url)
    if not util.is_web(url):
        error('URL must start with http:// or https://')

    try:
        got = util.requests_get(url)
    except requests.exceptions.Timeout as e:
        error(str(e), status=504, exc_info=True)
    except requests.exceptions.RequestException as e:
        error(str(e), status=502, exc_info=True)

    resp = flask.make_response(got.content, got.status_code, dict(got.headers))
    resp.headers.add('Link', LINK_HEADER % (request.args.get('endpoint') or
                                            common.host_url('webmention')))
    return resp
