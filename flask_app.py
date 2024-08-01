"""Main Flask application."""
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

from common import cache_policy, global_cache, global_cache_timeout_policy

logger = logging.getLogger(__name__)
# logging.getLogger('lexrpc').setLevel(logging.INFO)
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
    app.wsgi_app, client=appengine_config.ndb_client,
    # limited context-local cache. avoid full one due to this bug:
    # https://github.com/googleapis/python-ndb/issues/888
    cache_policy=cache_policy,
    global_cache=global_cache,
    global_cache_timeout_policy=global_cache_timeout_policy)

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

###########################################

# https://github.com/googleapis/python-ndb/issues/743#issuecomment-2067590945
#
# fixes "RuntimeError: Key has already been set in this batch" errors due to
# tasklets in pages.serve_feed
from logging import error as log_error
from sys import modules

from google.cloud.datastore_v1.types.entity import Key
from google.cloud.ndb._cache import (
    _GlobalCacheSetBatch,
    global_compare_and_swap,
    global_set_if_not_exists,
    global_watch,
)
from google.cloud.ndb.tasklets import Future, Return, tasklet

GLOBAL_CACHE_KEY_PREFIX: bytes = modules["google.cloud.ndb._cache"]._PREFIX
LOCKED_FOR_READ: bytes = modules["google.cloud.ndb._cache"]._LOCKED_FOR_READ
LOCK_TIME: bytes = modules["google.cloud.ndb._cache"]._LOCK_TIME


@tasklet
def custom_global_lock_for_read(key: str, value: str):
    if value is not None:
        yield global_watch(key, value)
        lock_acquired = yield global_compare_and_swap(
            key, LOCKED_FOR_READ, expires=LOCK_TIME
        )
    else:
        lock_acquired = yield global_set_if_not_exists(
            key, LOCKED_FOR_READ, expires=LOCK_TIME
        )

    if lock_acquired:
        raise Return(LOCKED_FOR_READ)

modules["google.cloud.ndb._cache"].global_lock_for_read = custom_global_lock_for_read
