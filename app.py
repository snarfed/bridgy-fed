"""Main Flask application."""
import logging

from flask import Flask
from flask_caching import Cache
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
    handlers,
    util,
)

import common


app = Flask('bridgy-fed')
app.template_folder = './templates'
app.config.from_mapping(
    ENV='development' if appengine_info.DEBUG else 'PRODUCTION',
    CACHE_TYPE='SimpleCache',
    SECRET_KEY=util.read('flask_secret_key'),
    JSONIFY_PRETTYPRINT_REGULAR=True,
)
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)

# don't redirect API requests with blank path elements
app.url_map.redirect_defaults = True

app.wsgi_app = handlers.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

cache = Cache(app)


import activitypub, add_webmention, logs, redirect, render, salmon, superfeedr, webfinger, webmention
