"""Unit tests for ui.py."""
from ui import UIProtocol

from .testutil import TestCase


class UIProtocolTest(TestCase):

    def test_ui_owns_id(self):
        self.assertTrue(UIProtocol.owns_id('ui:reply-foo'))
        for id in 'http://ui.org/obj', 'user.com', 'at://did:plc:foo/co.ll/123', '':
            with self.subTest(id=id):
                self.assertIs(False, UIProtocol.owns_id(id))

    def test_load_never_fetches(self):
        self.store_object(id='ui:reply-foo', source_protocol='ui',
                          our_as1={'objectType': 'comment', 'content': 'hi'})

        for remote in None, True:
            with self.subTest(remote=remote):
                loaded = UIProtocol.load('ui:reply-foo', remote=remote)
                self.assertEqual({
                    'id': 'ui:reply-foo',
                    'objectType': 'comment',
                    'content': 'hi',
                }, loaded.as1)

    def test_load_local_false_asserts(self):
        with self.assertRaises(AssertionError):
            UIProtocol.load('ui:reply-foo', local=False)
