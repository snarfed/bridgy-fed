"""Bridgy App Engine config.
"""
import os

# Load packages from virtualenv
# https://cloud.google.com/appengine/docs/python/tools/libraries27#vendoring
from google.appengine.ext import vendor
try:
  vendor.add('local')
except ValueError as e:
  import logging
  logging.warning("Couldn't set up App Engine vendor virtualenv! %s", e)

from granary.appengine_config import *

# Make requests and urllib3 play nice with App Engine.
# https://github.com/snarfed/bridgy/issues/396
# http://stackoverflow.com/questions/34574740
from requests_toolbelt.adapters import appengine
appengine.monkeypatch()


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
