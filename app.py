"""Main Flask application."""
import logging

from flask import Flask
from flask_caching import Cache
from werkzeug.exceptions import HTTPException

from oauth_dropins.webutil import appengine_info, appengine_config, handlers, util

app = Flask('bridgy-fed')
app.template_folder = './templates'
app.config.from_mapping(
    ENV='development' if appengine_info.DEBUG else 'PRODUCTION',
    CACHE_TYPE='SimpleCache',
    SECRET_KEY=util.read('flask_secret_key'),
    JSONIFY_PRETTYPRINT_REGULAR=True,
)
app.wsgi_app = handlers.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

cache = Cache(app)

@app.errorhandler(Exception)
def handle_exception(e):
    """A Flask error handler that propagates HTTP exceptions into the response."""
    code, body = util.interpret_http_exception(e)
    if code:
        return ((f'Upstream server request failed: {e}' if code in ('502', '504')
                 else f'HTTP Error {code}: {body}'),
                int(code))

    logging.error(f'{e.__class__}: {e}')
    if isinstance(e, HTTPException):
        return e
    else:
        raise e


# Add modern headers, but let the response override them
from common import MODERN_HEADERS

def default_modern_headers(resp):
    for name, value in MODERN_HEADERS.items():
        resp.headers.setdefault(name, value)

    return resp

app.after_request(default_modern_headers)


import activitypub, add_webmention, logs, redirect, render, salmon, superfeedr, webfinger, webmention
