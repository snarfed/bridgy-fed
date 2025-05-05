"""Single-instance hub for ATProto firehose client."""
import logging
import os
from pathlib import Path
import threading
from threading import Thread

from flask import Flask
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER
from oauth_dropins.webutil import appengine_config, flask_util

# all protocols
import activitypub, atproto, web
import atproto_firehose
import models

# WARNING: when this is higher than 1, we start seeing ndb context exceptions,
# "ContextError: No current context," in _handle, even though it has an ndb context
# from handler. No clue why. They happen more often as the number of threads
# increases. Are ndb clients/contexts not thread safe?!
# https://github.com/snarfed/bridgy-fed/issues/1315
# https://console.cloud.google.com/errors/detail/CJrBqKnRzPfNRA;time=PT1H;refresh=true;locations=global?project=bridgy-federated
HANDLE_THREADS = 10

logger = logging.getLogger(__name__)

models.reset_protocol_properties()

# Flask app
app = Flask(__name__)
app.json.compact = False
app_dir = Path(__file__).parent
app.config.from_pyfile(app_dir / 'config.py')

@app.get('/liveness_check')

@app.get('/readiness_check')
def health_check():
    """App Engine Flex health checks.

    https://cloud.google.com/appengine/docs/flexible/reference/app-yaml?tab=python#updated_health_checks
    """
    return 'OK'


# start firehose consumer threads
if LOCAL_SERVER or not DEBUG:
    threads = [t.name for t in threading.enumerate()]
    assert 'atproto_firehose.subscriber' not in threads
    assert 'atproto_firehose.handler' not in threads

    Thread(target=atproto_firehose.subscriber, name='atproto_firehose.subscriber',
           daemon=True).start()
    for i in range(HANDLE_THREADS):
        Thread(target=atproto_firehose.handler, name=f'atproto_firehose.handler-{i}',
               daemon=True).start()
