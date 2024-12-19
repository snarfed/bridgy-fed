"""Flask config and env vars.

https://flask.palletsprojects.com/en/latest/config/
"""
import logging
import os

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

    for logger in ('oauth_dropins.webutil.webmention', 'lexrpc'):
        logging.getLogger(logger).setLevel(logging.DEBUG)

# for debugging ndb. also needs NDB_DEBUG env var.
# https://github.com/googleapis/python-ndb/blob/c55ec62b5153787404488b046c4bf6ffa02fee64/google/cloud/ndb/utils.py#L78-L81
# logging.getLogger('google.cloud.ndb').setLevel(logging.DEBUG)
# logging.getLogger('google.cloud.ndb._cache').setLevel(logging.DEBUG)

os.environ.setdefault('APPVIEW_HOST', 'api.bsky.local')
os.environ.setdefault('BGS_HOST', 'bgs.bsky.local')
os.environ.setdefault('PLC_HOST', 'plc.bsky.local')
