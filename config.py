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

    for logger in ('common', 'oauth_dropins.webutil.webmention', 'lexrpc'):
        logging.getLogger(logger).setLevel(logging.DEBUG)

os.environ.setdefault('APPVIEW_HOST', 'api.bsky.local')
os.environ.setdefault('BGS_HOST', 'bgs.bsky.local')
os.environ.setdefault('PLC_HOST', 'plc.bsky.local')
