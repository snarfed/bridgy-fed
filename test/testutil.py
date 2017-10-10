"""Common test utility code.
"""
import unittest

from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import testbed

from oauth_dropins.webutil import testutil


class TestCase(unittest.TestCase, testutil.Asserts):

    maxDiff = None

    def setUp(self):
        super(TestCase, self).setUp()
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        hrd_policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=.5)
        self.testbed.init_datastore_v3_stub(consistency_policy=hrd_policy)
        self.testbed.init_memcache_stub()

    def tearDown(self):
        self.testbed.deactivate()
        super(TestCase, self).tearDown()
