"""Unit tests for nostr.py."""
from unittest.mock import patch

import common
from flask_app import app
import ids
from ids import translate_handle, translate_object_id, translate_user_id
from models import Target
from nostr import Nostr
from .testutil import Fake, TestCase


class NostrTest(TestCase):

    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

    def test_owns_id(self):
        for id in ('npub23', 'nevent123', 'note123', 'nprofile123', 'naddr123',
                   'nostr:nevent123'):
            with self.subTest(id=id):
                self.assertTrue(Nostr.owns_id(id))

        for id in ('abc', 'did:abc', 'foo.com', 'https://foo.com/',
                   'https://foo.com/bar', 'at://did:abc/x.y.z/123'):
            with self.subTest(id=id):
                self.assertFalse(Nostr.owns_id(id))

    def test_owns_handle(self):
        for handle in ('user@domain', 'user@domain.com', 'user.com@domain.com',
                       'user@domain', 'user@sub.do.main', '_@domain'):
            with self.subTest(handle=handle):
                self.assertTrue(Nostr.owns_handle(handle))

        for handle in ('domain', 'domain.com', '@user', '@user.com',
                       'http://user.com', '@user@web.brid.gy', '@user@domain',
                       '@user@sub.dom.ain', '_@'):
            with self.subTest(handle=handle):
                self.assertEqual(False, Nostr.owns_handle(handle))
