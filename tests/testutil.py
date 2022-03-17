"""Common test utility code.
"""
import copy
import unittest
from unittest.mock import ANY, call

from app import app, cache
from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
import requests

import common


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

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        super().tearDown()

    def req(self, url, **kwargs):
        """Returns a mock requests call."""
        existing = kwargs.get('headers', {})
        if existing is not ANY:
            kwargs['headers'] = {
              'User-Agent': util.user_agent,
              **existing,
            }

        kwargs.setdefault('timeout', util.HTTP_TIMEOUT)
        kwargs.setdefault('stream', True)

        return call(url, **kwargs)

    def assert_req(self, mock, url, **kwargs):
        """Checks a mock requests call."""
        kwargs.setdefault('headers', {}).setdefault('User-Agent', 'Bridgy Fed (https://fed.brid.gy/)')
        kwargs.setdefault('stream', True)
        kwargs.setdefault('timeout', util.HTTP_TIMEOUT)

        mock.assert_any_call(url, **kwargs)
