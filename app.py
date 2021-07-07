"""Main Flask application."""
from flask import Flask
from flask_caching import Cache
from oauth_dropins.webutil import appengine_info, appengine_config, handlers, util

app = Flask('bridgy-fed')
app.template_folder = './templates'
app.config.from_mapping(
    ENV='development' if appengine_info.DEBUG else 'PRODUCTION',
    CACHE_TYPE='SimpleCache',
    SECRET_KEY=util.read('flask_secret_key'),
)
app.wsgi_app = handlers.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

cache = Cache(app)

import activitypub, add_webmention, logs, redirect, render, salmon, superfeedr, webfinger, webmention
