"""Common test utility code.
"""
import copy
import unittest

from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import testbed
from mock import ANY, call
from oauth_dropins.webutil import testutil, util

import common


class TestCase(unittest.TestCase, testutil.Asserts):

    maxDiff = None

    def setUp(self):
        super(TestCase, self).setUp()
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        hrd_policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=.5)
        self.testbed.init_datastore_v3_stub(consistency_policy=hrd_policy)
        self.datastore_stub = self.testbed.get_stub('datastore_v3')
        self.testbed.init_memcache_stub()
        self.testbed.init_mail_stub()

    def tearDown(self):
        self.testbed.deactivate()
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
