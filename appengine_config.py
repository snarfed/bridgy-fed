"""Bridgy App Engine config.
"""
import os

from oauth_dropins.webutil.appengine_info import DEBUG, HOST, HOST_URL, SCHEME

if not DEBUG:
  HOST = 'fed.brid.gy'
  HOST_URL = '%s://%s' % (SCHEME, HOST)

# suppresses these INFO logs:
# Sandbox prevented access to file "/usr/local/Caskroom/google-cloud-sdk"
# If it is a static file, check that `application_readable: true` is set in your app.yaml
import logging

class StubsFilter(logging.Filter):
  def filter(self, record):
    msg = record.getMessage()
    if (msg.startswith('Sandbox prevented access to file') or
        msg.startswith('If it is a static file, check that')):
      return 0
    return 1

logging.getLogger().addFilter(StubsFilter())
