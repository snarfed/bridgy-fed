"""Flask application for frontend ("default") service."""
import json
import logging
from pathlib import Path
import sys

import arroba.server
from arroba import xrpc_repo, xrpc_server, xrpc_sync
from flask import Flask, g
import flask_gae_static
from lexrpc.server import Server
import lexrpc.flask_server
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
)

import common

logger = logging.getLogger(__name__)
logging.getLogger('negotiator').setLevel(logging.WARNING)

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


# don't redirect API requests with blank path elements
app.url_map.merge_slashes = False
app.url_map.redirect_defaults = False

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client, **common.NDB_CONTEXT_KWARGS)

# deregister XRPC methods we don't support
for nsid in (
    'com.atproto.repo.applyWrites',
    'com.atproto.repo.createRecord',
    'com.atproto.repo.deleteRecord',
    'com.atproto.repo.putRecord',
    'com.atproto.repo.uploadBlob',
    'com.atproto.server.createSession',
    'com.atproto.server.getAccountInviteCodes',
    'com.atproto.server.getSession',
    'com.atproto.server.listAppPasswords',
    'com.atproto.server.refreshSession',
):
    del arroba.server.server._methods[nsid]

lexrpc.flask_server.init_flask(arroba.server.server, app)
