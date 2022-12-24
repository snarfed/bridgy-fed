"""Common test utility code."""
import datetime
import unittest

import requests

from app import app, cache
import common
from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.util import json_dumps, json_loads

NOW = datetime.datetime(2022, 12, 24, 22, 29, 19)


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()
        app.testing = True
        cache.clear()
        self.client = app.test_client()
        common.utcnow = lambda: NOW

        # clear datastore
        requests.post('http://%s/reset' % ndb_client.host)
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        super().tearDown()
