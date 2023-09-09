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

from common import USER_AGENT

util.set_user_agent(USER_AGENT)

logger = logging.getLogger(__name__)


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
    """Handler for atproto-commit tasks. Enqueues the commit for subscribeRepos.
    """
    logger.info(f'Params: {request.values}')
    seq = request.form['seq']
    logger.info(f'Got atproto-commit task for seq {seq}')

    if not util.is_int(seq):
        flask_util.error(f'seq {seq} is not int')

    for commit_data in DatastoreStorage().read_commits_by_seq(start=int(seq)):
        logger.info(f'Enqueueing commit {commit_data.commit.cid}')
        xrpc_sync.enqueue_commit(commit_data)

    return 'OK'
