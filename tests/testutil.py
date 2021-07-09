"""Common test utility code.
"""
import copy
import unittest
from unittest.mock import ANY, call

from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
import requests
import webapp2

import common


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super(TestCase, self).setUp()

        # clear datastore
        requests.post('http://%s/reset' % ndb_client.host)
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

        self.request = webapp2.Request.blank('/')
        self.response = webapp2.Response()
        # self.handler = common.Handler(self.request, self.response)

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        super(TestCase, self).tearDown()

    def req(self, url, **kwargs):
        """Returns a mock requests call."""
        existing = kwargs.get('headers', {})
        if existing is not ANY:
            headers = copy.deepcopy(common.HEADERS)
            headers.update(existing)
            kwargs['headers'] = headers

        kwargs.setdefault('timeout', util.HTTP_TIMEOUT)
        kwargs.setdefault('stream', True)

        return call(url, **kwargs)
