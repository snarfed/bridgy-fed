"""Main Flask application."""
import json
import logging
from pathlib import Path
import sys

import arroba.server
from arroba import xrpc_repo, xrpc_server, xrpc_sync
from flask import Flask, g
from flask_caching import Cache
import flask_gae_static
from lexrpc.server import Server
import lexrpc.flask_server
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
)

logger = logging.getLogger(__name__)
# logging.getLogger('lexrpc').setLevel(logging.INFO)
logging.getLogger('negotiator').setLevel(logging.WARNING)

# add thread name to log prefix so we can trace log messages in
# Protocol.deliver, which is parallelized across threads
logging.getLogger().handlers[0].setFormatter(
    logging.Formatter(fmt='%(levelname)s:%(name)s:%(threadName)s:%(message)s'))

app_dir = Path(__file__).parent


app = Flask(__name__, static_folder=None)
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(app_dir / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)
if (appengine_info.LOCAL_SERVER
    # ugly hack to infer if we're running unit tests
    and 'unittest' not in sys.modules):
    flask_gae_static.init_app(app)


@app.before_request
def init_globals():
    """Set request globals.

    * g.user: current *actor* internal user we're operating on behalf of
    """
    g.user = None


# don't redirect API requests with blank path elements
app.url_map.merge_slashes = False
app.url_map.redirect_defaults = False

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client,
    # disable in-memory cache
    # (also in tests/testutil.py)
    # https://github.com/googleapis/python-ndb/issues/888
    cache_policy=lambda key: False,
)

cache = Cache(app)

lexrpc.flask_server.init_flask(arroba.server.server, app)
