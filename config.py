"""Flask config and env vars.

https://flask.palletsprojects.com/en/latest/config/
"""
import logging
import os
import re
import traceback

from oauth_dropins.webutil import appengine_config, appengine_info, util

# This is primarily for flashed messages, since we don't use session data
# otherwise.
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
# Not strict because we flash messages after cross-site redirects for OAuth,
# which strict blocks.
SESSION_COOKIE_SAMESITE = 'Lax'
CACHE_THRESHOLD = 3000
# 10MiB. default is 500KiB, and we hit that on receive tasks for some web posts
# https://github.com/snarfed/bridgy-fed/issues/1593
MAX_FORM_MEMORY_SIZE = 10000000

# flask-sock, simple_websocket
# https://flask-sock.readthedocs.io/en/latest/quickstart.html#configuration
# https://simple-websocket.readthedocs.io/en/latest/api.html#the-server-class
SOCK_SERVER_OPTIONS = {
    'ping_interval': 25,
}

config_logger = logging.getLogger(__name__)

if appengine_info.DEBUG:
    ENV = 'development'
    CACHE_TYPE = 'NullCache'
    SECRET_KEY = 'sooper seekret'

else:
    ENV = 'production'
    CACHE_TYPE = 'SimpleCache'
    SECRET_KEY = util.read('flask_secret_key')

    logging.getLogger().setLevel(logging.INFO)
    if logging_client := getattr(appengine_config, 'logging_client'):
        logging_client.setup_logging(log_level=logging.INFO)

    for logger in ('atproto_firehose', 'lexrpc', 'oauth_dropins.webutil.webmention'):
        logging.getLogger(logger).setLevel(logging.DEBUG)

    logging.getLogger('lexrpc.flask_server').setLevel(logging.INFO)

# for debugging ndb. also needs NDB_DEBUG env var, set in *.yaml.
# https://github.com/googleapis/python-ndb/blob/c55ec62b5153787404488b046c4bf6ffa02fee64/google/cloud/ndb/utils.py#L78-L81
# logging.getLogger('google.cloud').propagate = True
# logging.getLogger('google.cloud.ndb').setLevel(logging.DEBUG)
# logging.getLogger('google.cloud.ndb._cache').setLevel(logging.DEBUG)
# logging.getLogger('google.cloud.ndb.global_cache').setLevel(logging.DEBUG)

KEYS_ID_RE = re.compile(f'name: "([^"]+)"')

def only_lookups(record):
    msg = record.getMessage()
    if '\nkeys {' in msg:
        if id := KEYS_ID_RE.search(msg):
            stack = [frame for frame in traceback.extract_stack()[:-1]
                     if (frame.filename.startswith('/workspace/')
                         or 'arroba' in frame.filename)
                        or (frame.filename.startswith('/Users/ryan/src/')
                            and '/lib/' not in frame.filename)]
            new_msg = id.group(1) + '\n' + ''.join(traceback.format_list(stack))
            config_logger.info(new_msg)

            # ideally I'd return a new log record here and let the
            # _datastore_api logger emit it, or just modify the record passed in
            # here and return True, but that makes tests try to talk to google
            # cloud's production logging (?)
            #
            # return logging.LogRecord(record.name, record.level, record.pathname,
            #                       record.lineno, new_msg, record.args,
            #                       record.exc_info))

    return False

# api_logger = logging.getLogger('google.cloud.ndb._datastore_api')
# api_logger.setLevel(logging.DEBUG)
# api_logger.addFilter(only_lookups)

os.environ.setdefault('APPVIEW_HOST', 'api.bsky.local')
os.environ.setdefault('BGS_HOST', 'bgs.bsky.local')
os.environ.setdefault('PLC_HOST', 'plc.bsky.local')

if repo_token := util.read('repo_token'):
    os.environ.setdefault('REPO_TOKEN', repo_token)
