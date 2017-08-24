# coding=utf-8
"""Unit tests for models.py."""
from __future__ import unicode_literals

import models
import testutil


class ModelsTest(testutil.TestCase):

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
