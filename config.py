"""Flask config and env vars.

https://flask.palletsprojects.com/en/latest/config/
"""
import os

from oauth_dropins.webutil import appengine_info, util

# This is primarily for flashed messages, since we don't use session data
# otherwise.
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
# Not strict because we flash messages after cross-site redirects for OAuth,
# which strict blocks.
SESSION_COOKIE_SAMESITE = 'Lax'
CACHE_THRESHOLD = 3000

if appengine_info.DEBUG:
    ENV = 'development'
    CACHE_TYPE = 'NullCache'
    SECRET_KEY = 'sooper seekret'
else:
    ENV = 'production'
    CACHE_TYPE = 'SimpleCache'
    SECRET_KEY = util.read('flask_secret_key')

os.environ.setdefault('APPVIEW_HOST', 'api.bsky-sandbox.dev')
os.environ.setdefault('BGS_HOST', 'bgs.bsky-sandbox.dev')
os.environ.setdefault('PLC_HOST', 'plc.bsky-sandbox.dev')
