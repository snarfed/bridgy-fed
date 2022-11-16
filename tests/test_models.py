# coding=utf-8
"""Unit tests for models.py."""
from app import app
from models import Domain, Activity
from . import testutil


class DomainTest(testutil.TestCase):

    def setUp(self):
        super(DomainTest, self).setUp()
        self.domain = Domain.get_or_create('y.z')

    def test_magic_key_get_or_create(self):
        assert self.domain.mod
        assert self.domain.public_exponent
        assert self.domain.private_exponent

        same = Domain.get_or_create('y.z')
        self.assertEqual(same, self.domain)

    def test_href(self):
        href = self.domain.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(self.domain.mod, href)
        self.assertIn(self.domain.public_exponent, href)

    def test_public_pem(self):
        pem = self.domain.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)

    def test_private_pem(self):
        pem = self.domain.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)


class ActivityTest(testutil.TestCase):

    def test_constructor(self):
        activity = Activity('abc', 'xyz')
        self.assertEqual('abc xyz', activity.key.id())

        activity = Activity('abc#1', 'xyz#Z')
        self.assertEqual('abc__1 xyz__Z', activity.key.id())

    def test_get_or_create(self):
        activity = Activity.get_or_create('abc', 'xyz')
        self.assertEqual('abc xyz', activity.key.id())

        activity = Activity.get_or_create('abc#1', 'xyz#Z')
        self.assertEqual('abc__1 xyz__Z', activity.key.id())

    def test_proxy_url(self):
        with app.test_request_context('/'):
            activity = Activity.get_or_create('abc', 'xyz')
            self.assertIsNone(activity.proxy_url())

            activity.source_as2 = 'as2'
            self.assertEqual('http://localhost/render?source=abc&target=xyz',
                             activity.proxy_url())
