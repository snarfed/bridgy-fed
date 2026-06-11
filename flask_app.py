"""Flask application for frontend ("default") service."""
import json
import logging
from pathlib import Path
import sys

import arroba.server
from arroba import xrpc_repo, xrpc_server, xrpc_sync
from flask import Blueprint, Flask, g
from google.api_core.exceptions import PermissionDenied
from lexrpc.server import Server
import lexrpc.flask_server
import oauth_dropins
from webutil import (
    appengine_info,
    appengine_config,
    flask_util,
)

import common

logger = logging.getLogger(__name__)
logging.getLogger('negotiator').setLevel(logging.WARNING)

app_dir = Path(__file__).parent

app = Flask(__name__, static_folder='static')
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(app_dir / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)

app.register_error_handler(Exception, flask_util.handle_exception)
app.register_error_handler(PermissionDenied, flask_util.handle_read_only_permission_denied)

od_path = Path(oauth_dropins.__file__).parent
app.register_blueprint(Blueprint(
    'oauth_dropins_static', __name__, static_folder=od_path / 'static',
    static_url_path='/oauth_dropins_static'))
app.register_blueprint(Blueprint(
    'oauth_dropins_fonts', __name__, static_folder=od_path / 'fonts',
    static_url_path='/fonts'))

@app.get('/.well-known/security.txt')
def security_txt():
    return app.send_static_file('security.txt')

@app.get('/<any(favicon.ico,robots.txt):filename>')
def static_file(filename):
    return app.send_static_file(filename)


# don't redirect API requests with blank path elements
app.url_map.merge_slashes = False
app.url_map.redirect_defaults = False

ndb_context_kwargs = {
    **common.NDB_CONTEXT_KWARGS,
    'cache_policy': lambda key: False,
}
app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client, **ndb_context_kwargs)

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
