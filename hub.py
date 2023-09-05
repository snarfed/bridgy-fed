"""Single-instance hub for ATProto and Nostr websocket subscriptions."""
from datetime import datetime, timedelta
import json
import logging
import os
from pathlib import Path

import arroba.server
from arroba.util import service_jwt
from arroba import xrpc_sync
from flask import Flask
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


# #
# # App Engine config
# #
# if appengine_info.LOCAL:
#     logger.info('Running locally')
#     # creds = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
#     # assert not creds or creds.endswith('fake_user_account.json')
#     # os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = \
#     #     os.path.join(os.path.dirname(__file__), 'fake_user_account.json')
#     # os.environ.setdefault('CLOUDSDK_CORE_PROJECT', 'app')
#     # os.environ.setdefault('DATASTORE_DATASET', 'app')
#     # os.environ.setdefault('GOOGLE_CLOUD_PROJECT', 'app')
#     # os.environ.setdefault('DATASTORE_EMULATOR_HOST', 'localhost:8089')
# else:
#     logger.info('Running against production GAE')


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


# # requestCrawl in prod
# # not working because the BGS immediately tries to connect and errors if it can't,
# # and evidently we're not quite serving subscribeRepos here yet. not sure why not.
# if is_prod:
#     url = f'https://{os.environ["BGS_HOST"]}/xrpc/com.atproto.sync.requestCrawl'
#     logger.info(f'Fetching {url}')
#     jwt = service_jwt(os.environ['BGS_HOST'], TODO repo did, TODO repo key)
#     resp = requests.get(url, params={'hostname': os.environ['PDS_HOST']},
#                         headers={'User-Agent': USER_AGENT,
#                                  'Authorization': f'Bearer {jwt}',
#                                 })
#     logger.info(resp.content)
#     resp.raise_for_status()
#     logger.info('OK')
