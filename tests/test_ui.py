"""Unit tests for ui.py."""
from ui import UIProtocol

from .testutil import TestCase


class UIProtocolTest(TestCase):

    def test_ui_owns_id(self):
        self.assertTrue(UIProtocol.owns_id('ui:reply-foo'))
        for id in 'http://ui.org/obj', 'user.com', 'at://did:plc:foo/co.ll/123', '':
            with self.subTest(id=id):
                self.assertIs(False, UIProtocol.owns_id(id))
