"""Single-instance hub for ATProto and Nostr websocket subscriptions."""
from datetime import datetime, timedelta
import json
import logging
import os
from pathlib import Path

import arroba.server
from arroba.datastore_storage import DatastoreStorage
from arroba.util import service_jwt
from arroba import xrpc_sync
from flask import Flask, request
import google.cloud.logging
import lexrpc.server
import lexrpc.flask_server
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
    util,
)
import requests

import atproto  # atproto-poll-notifs task handler
from common import USER_AGENT
import models

logger = logging.getLogger(__name__)

util.set_user_agent(USER_AGENT)

models.reset_protocol_properties()

#
# Flask app
#
app = Flask(__name__)
app.json.compact = False
app_dir = Path(__file__).parent
app.config.from_pyfile(app_dir / 'config.py')

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client,
    # disable in-memory cache
    # (also in tests/testutil.py)
    # https://github.com/googleapis/python-ndb/issues/888
    cache_policy=lambda key: False,
)


@app.get('/liveness_check')
@app.get('/readiness_check')
def health_check():
    """App Engine Flex health checks.

    https://cloud.google.com/appengine/docs/flexible/reference/app-yaml?tab=python#updated_health_checks
    """
    return 'OK'


#
# XRPC server
#
lexrpc.flask_server.init_flask(arroba.server.server, app)


@app.post('/_ah/queue/atproto-commit')
def atproto_commit():
    """Handler for atproto-commit tasks.

    Triggers `subscribeRepos` to check for new commits.
    """
    xrpc_sync.send_new_commits()
    return 'OK'
