"""Unit tests for ids.py."""
from activitypub import ActivityPub
from atproto import ATProto
from ids import convert_id
from models import Target
from web import Web
from .testutil import Fake, TestCase


class IdsTest(TestCase):
    def test_convert_id(self):
        Web(id='user.com', atproto_did='did:plc:123',
            copies=[Target(uri='did:plc:123', protocol='atproto')]).put()
        ActivityPub(id='https://server/user', atproto_did='did:plc:456',
                    copies=[Target(uri='did:plc:456', protocol='atproto')]).put()
        Fake(id='fake:user', atproto_did='did:plc:789',
             copies=[Target(uri='did:plc:789', protocol='atproto')]).put()

        for from_, id, to, expected in [
            (Web, 'user.com', ActivityPub, 'http://localhost/web/ap/user.com'),
            (Web, 'user.com', ATProto, 'did:plc:123'),
            (Web, 'user.com', Fake, 'fake:user.com'),
                # TODO: not a domain, is that ok?
            (ActivityPub, 'https://server/user', Web, 'https://server/user'),
            (ActivityPub, 'https://server/user', ATProto, 'did:plc:456'),
            (ActivityPub, 'https://server/user', Fake, 'fake:https://server/user'),
            (ATProto, 'did:plc:123', Web, 'user.com'),
            (ATProto, 'did:plc:456', ActivityPub, 'https://server/user'),
            (ATProto, 'did:plc:789', Fake, 'fake:user'),
            (Fake, 'fake:user', Web, 'fake:user'),
            (Fake, 'fake:user', ActivityPub, 'http://localhost/fa/ap/fake:user'),
            (Fake, 'fake:user', ATProto, 'did:plc:789'),
        ]:
            with self.subTest(from_=from_.LABEL, to=to.LABEL):
                self.assertEqual(expected, convert_id(
                    id=id, from_proto=from_, to_proto=to))

    def test_convert_id_no_atproto_did_stored(self):
        for proto in Web, ActivityPub, Fake:
            with self.subTest(proto=proto.LABEL):
                self.assertIsNone(convert_id(
                    id='foo', from_proto=proto, to_proto=ATProto))
                self.assertIsNone(convert_id(
                    id='did:plc:123', from_proto=ATProto, to_proto=proto))
