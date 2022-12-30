"""Common test utility code."""
import datetime
import unittest

import requests

from app import app, cache
from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.util import json_dumps, json_loads


# can't use webutil.testutil.TestCase because it mock out requests.* with mox,
# which collides with bridgy-at doing the same thing with unittest.mock.
class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()
        app.testing = True
        cache.clear()
        self.client = app.test_client()

        # clear datastore
        requests.post('http://%s/reset' % ndb_client.host)

        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

        util.now = lambda **kwargs: testutil.NOW

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        super().tearDown()
