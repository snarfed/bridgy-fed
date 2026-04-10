"""Unit tests for farcaster.py."""
from models import Object
from farcaster import Farcaster

from .testutil import TestCase


class FarcasterTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = Farcaster(id='farcaster://123')

    def test_handle_no_key(self):
        self.assertIsNone(Farcaster().handle)

    def test_owns_id(self):
        self.assertTrue(Farcaster.owns_id('farcaster://123'))
        self.assertTrue(Farcaster.owns_id('farcaster://123/0x456'))
        self.assertFalse(Farcaster.owns_id(''))
        self.assertFalse(Farcaster.owns_id('789'))
        self.assertFalse(Farcaster.owns_id('http://foo/bar'))

    def test_owns_handle(self):
        self.assertTrue(Farcaster.owns_handle('bob.eth'))
        self.assertIsNone(Farcaster.owns_handle('alice'))
        self.assertFalse(Farcaster.owns_handle('carolreallybiglongname'))
        self.assertFalse(Farcaster.owns_handle('@'))
        self.assertFalse(Farcaster.owns_handle('alice.com'))
        self.assertFalse(Farcaster.owns_handle('http://foo/bar'))

    def test_fid(self):
        self.assertEqual(123, self.user.fid)

    def test_handle_no_profile(self):
        self.assertEqual('123', self.user.handle)

    def test_handle_with_username(self):
        obj = Object(id='farcaster://123/0x456', our_as1={
            'objectType': 'person',
            'username': 'snarfed',
        })
        self.user.obj_key = obj.put()
        self.assertEqual('snarfed', self.user.handle)

    def test_web_url_no_key(self):
        self.assertIsNone(Farcaster().web_url())

    def test_web_url(self):
        self.assertEqual('https://farcaster.xyz/~/profiles/123', self.user.web_url())
