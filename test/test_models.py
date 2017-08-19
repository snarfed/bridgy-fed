# coding=utf-8
"""Unit tests for models.py."""
import unittest

from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import testbed

import models


class ModelsTest(unittest.TestCase):

    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        hrd_policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=.5)
        self.testbed.init_datastore_v3_stub(consistency_policy=hrd_policy)
        self.testbed.init_memcache_stub()

    def tearDown(self):
        self.testbed.deactivate()

    def test_magic_key_get_or_create(self):
        key = models.MagicKey.get_or_create('x@y.z')
        assert key.mod
        assert key.public_exponent
        assert key.private_exponent

        same = models.MagicKey.get_or_create('x@y.z')
        self.assertEquals(same, key)

    def test_href(self):
        key = models.MagicKey.get_or_create('x@y.z')
        href = key.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(key.mod, href)
        self.assertIn(key.public_exponent, href)
