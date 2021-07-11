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
  return e

import activitypub, add_webmention, logs, redirect, render, salmon, superfeedr, webfinger, webmention
