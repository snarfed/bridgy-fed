"""Single-instance hub for ATProto subscription (firehose) server and client."""
import logging
import os
from pathlib import Path
import threading
from threading import Thread, Timer

import arroba.server
from arroba import xrpc_sync
from flask import Flask
import lexrpc.client
import lexrpc.flask_server
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER
from oauth_dropins.webutil import appengine_config, flask_util

# all protocols
import activitypub, atproto, web
import atproto_firehose
from common import global_cache, global_cache_timeout_policy, USER_AGENT
import models

logger = logging.getLogger(__name__)

models.reset_protocol_properties()

# Flask app
app = Flask(__name__)
app.json.compact = False
app_dir = Path(__file__).parent
app.config.from_pyfile(app_dir / 'config.py')

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client,
    global_cache=global_cache,
    global_cache_timeout_policy=global_cache_timeout_policy,
    # disable context-local cache due to this bug:
    # https://github.com/googleapis/python-ndb/issues/888
    cache_policy=lambda key: False)


@app.get('/liveness_check')
@app.get('/readiness_check')
def health_check():
    """App Engine Flex health checks.

    https://cloud.google.com/appengine/docs/flexible/reference/app-yaml?tab=python#updated_health_checks
    """
    return 'OK'


# ATProto XRPC server
lexrpc.flask_server.init_flask(arroba.server.server, app)


@app.post('/queue/atproto-commit')
@flask_util.cloud_tasks_only
def atproto_commit():
    """Handler for atproto-commit tasks.

    Triggers `subscribeRepos` to check for new commits.
    """
    xrpc_sync.send_events()
    return 'OK'


# start firehose consumer threads
if LOCAL_SERVER or not DEBUG:
    threads = [t.name for t in threading.enumerate()]
    assert 'atproto_firehose.subscriber' not in threads
    assert 'atproto_firehose.handler' not in threads

    Thread(target=atproto_firehose.subscriber, name='atproto_firehose.subscriber').start()
    Thread(target=atproto_firehose.handler, name='atproto_firehose.handler').start()


# send requestCrawl to relay
# delay because we're not up and serving XRPCs at this point yet. not sure why not.
if 'GAE_INSTANCE' in os.environ:  # prod
    def request_crawl():
        bgs = lexrpc.client.Client(f'https://{os.environ["BGS_HOST"]}',
                                   headers={'User-Agent': USER_AGENT})
        resp = bgs.com.atproto.sync.requestCrawl({'hostname': os.environ['PDS_HOST']})
        logger.info(resp)

    Timer(15, request_crawl).start()
    logger.info('Will send relay requestCrawl in 15s')
