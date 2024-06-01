"""Background service for processing receive, send, poll-feed, etc tasks."""
from pathlib import Path

from flask import Flask
from oauth_dropins.webutil import (
    appengine_config,
    flask_util,
    util,
)

# all protocols
import activitypub, atproto, web
from common import USER_AGENT
import models
import protocol

util.set_user_agent(USER_AGENT)

models.reset_protocol_properties()

# Flask app
app = Flask(__name__)
app_dir = Path(__file__).parent
app.config.from_pyfile(app_dir / 'config.py')

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client,
    # disable in-memory cache
    # (also in tests/testutil.py)
    # https://github.com/googleapis/python-ndb/issues/888
    cache_policy=lambda key: False,
)

app.add_url_rule('/queue/poll-feed', view_func=web.poll_feed_task, methods=['POST'])
app.add_url_rule('/queue/receive', view_func=protocol.receive_task, methods=['POST'])
app.add_url_rule('/queue/send', view_func=protocol.send_task, methods=['POST'])
app.add_url_rule('/queue/webmention', view_func=web.webmention_task, methods=['POST'])


@app.get('/liveness_check')
@app.get('/readiness_check')
def health_check():
    """App Engine Flex health checks.

    https://cloud.google.com/appengine/docs/flexible/reference/app-yaml?tab=python#updated_health_checks
    """
    return 'OK'
