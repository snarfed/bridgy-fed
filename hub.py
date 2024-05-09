"""Single-instance hub for ATProto and Nostr websocket subscriptions."""
import logging
import os
from pathlib import Path
import threading
from threading import Thread, Timer

import arroba.server
from arroba import xrpc_sync
from flask import Flask, request
import lexrpc.client
import lexrpc.flask_server
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER
from oauth_dropins.webutil import (
    appengine_config,
    flask_util,
    util,
)

# all protocols
import activitypub, atproto, atproto_firehose, web
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
# ATProto XRPC server, other URL routes
#
lexrpc.flask_server.init_flask(arroba.server.server, app)

app.add_url_rule('/queue/atproto-poll-notifs',
                 view_func=atproto.poll_notifications,
                 methods=['GET', 'POST'])

app.add_url_rule('/queue/atproto-poll-posts',
                 view_func=atproto.poll_posts,
                 methods=['GET', 'POST'])

@app.post('/queue/atproto-commit')
@flask_util.cloud_tasks_only
def atproto_commit():
    """Handler for atproto-commit tasks.

    Triggers `subscribeRepos` to check for new commits.
    """
    xrpc_sync.send_new_commits()
    return 'OK'


#
# ATProto firehose consumer
#
if LOCAL_SERVER or not DEBUG:
    def subscribe():
        with appengine_config.ndb_client.context():
            atproto_firehose.subscribe()

    assert 'atproto_firehose.subscribe' not in [t.name for t in threading.enumerate()]
    Thread(target=subscribe, name='atproto_firehose.subscribe').start()

    def handle():
        with appengine_config.ndb_client.context():
            atproto_firehose.handle()

    assert 'atproto_firehose.handle' not in [t.name for t in threading.enumerate()]
    Thread(target=handle, name='atproto_firehose.handle').start()


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
