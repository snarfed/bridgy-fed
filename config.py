"""Flask config.

https://flask.palletsprojects.com/en/latest/config/
"""
from oauth_dropins.webutil import appengine_info, util

# This is primarily for flashed messages, since we don't use session data
# otherwise.
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
# Change to Lax if/when we add IndieAuth for anything.
SESSION_COOKIE_SAMESITE = 'Strict'

if appengine_info.DEBUG:
  ENV = 'development'
  CACHE_TYPE = 'NullCache'
  SECRET_KEY = 'sooper seekret'
else:
  ENV = 'production'
  CACHE_TYPE = 'SimpleCache'
  SECRET_KEY = util.read('flask_secret_key')
