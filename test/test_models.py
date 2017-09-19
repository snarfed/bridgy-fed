# coding=utf-8
"""Unit tests for models.py."""
from __future__ import unicode_literals

import models
import testutil


class ModelsTest(testutil.TestCase):

    def setUp(self):
        super(ModelsTest, self).setUp()
        self.key = models.MagicKey.get_or_create('y.z')

    def test_magic_key_get_or_create(self):
        assert self.key.mod
        assert self.key.public_exponent
        assert self.key.private_exponent

        same = models.MagicKey.get_or_create('y.z')
        self.assertEquals(same, self.key)

    def test_href(self):
        href = self.key.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(self.key.mod, href)
        self.assertIn(self.key.public_exponent, href)

    def test_public_pem(self):
        pem = self.key.public_pem()
        self.assertTrue(pem.startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.endswith('-----END PUBLIC KEY-----'), pem)

    def test_public_pem(self):
        pem = self.key.private_pem()
        self.assertTrue(pem.startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.endswith('-----END RSA PRIVATE KEY-----'), pem)
