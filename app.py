"""Main Flask application."""
from pathlib import Path

from flask import Flask
from flask_caching import Cache
import flask_gae_static
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
    util,
)

import common


app = Flask(__name__, static_folder=None)
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(Path(__file__).parent / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)
if appengine_info.LOCAL:
    flask_gae_static.init_app(app)

# don't redirect API requests with blank path elements
app.url_map.redirect_defaults = True

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

cache = Cache(app)

util.set_user_agent('Bridgy Fed (https://fed.brid.gy/)')


import activitypub, add_webmention, follow, pages, redirect, render, salmon, superfeedr, webfinger, webmention
