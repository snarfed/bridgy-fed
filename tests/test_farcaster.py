"""Unit tests for farcaster.py."""
from models import Object
from farcaster import Farcaster

from .testutil import TestCase


class FarcasterTest(TestCase):

    def test_handle_no_key(self):
        self.assertIsNone(Farcaster().handle)

    def test_handle_no_profile(self):
        user = Farcaster(id='123')
        self.assertEqual('123', user.handle)

    def test_handle_with_username(self):
        obj = Object(id='123', our_as1={
            'objectType': 'person',
            'username': 'snarfed',
        })
        user = Farcaster(id='123', obj_key=obj.put())
        self.assertEqual('snarfed', user.handle)

    def test_web_url_no_key(self):
        self.assertIsNone(Farcaster().web_url())

    def test_web_url(self):
        user = Farcaster(id='123')
        self.assertEqual('https://farcaster.xyz/~/profiles/123', user.web_url())
