"""Unit tests for farcaster.py."""
from unittest.mock import patch

from google.protobuf import text_format
from granary.generated.farcaster.message_pb2 import (
    CastId,
    Message,
    MESSAGE_TYPE_CAST_ADD,
    MESSAGE_TYPE_USER_DATA_ADD,
    USER_DATA_TYPE_BIO,
    USER_DATA_TYPE_DISPLAY,
    USER_DATA_TYPE_USERNAME,
)
from granary.generated.farcaster.request_response_pb2 import (
    BulkMessageResponse,
    FidRequest,
    MessagesResponse,
    SubmitBulkMessagesRequest,
    SubmitBulkMessagesResponse,
    UsernameProofRequest,
)
from granary.generated.farcaster.username_proof_pb2 import UserNameProof
from granary.tests.test_farcaster import message, user_data_message

import farcaster
from farcaster import Farcaster
from models import Object, Target

from .testutil import TestCase


@patch('granary.farcaster.rpc_pb2_grpc.HubServiceStub')
class FarcasterTest(TestCase):
    """Tests for :class:`farcaster.Farcaster`.

    Note that we mock the snapchain gRPC :class:`HubServiceStub` directly,
    like granary's :class:`FarcasterClientTest`.
    """

    def setUp(self):
        super().setUp()
        farcaster._client = None
        self.user = Farcaster(id='farcaster://123')

    def test_handle_no_key(self, _):
        self.assertIsNone(Farcaster().handle)

    def test_owns_id(self, _):
        self.assertTrue(Farcaster.owns_id('farcaster://123'))
        self.assertTrue(Farcaster.owns_id('farcaster://123/0x456'))
        self.assertFalse(Farcaster.owns_id(''))
        self.assertFalse(Farcaster.owns_id('789'))
        self.assertFalse(Farcaster.owns_id('http://foo/bar'))

    def test_owns_handle(self, _):
        self.assertTrue(Farcaster.owns_handle('bob.eth'))
        self.assertIsNone(Farcaster.owns_handle('alice'))
        self.assertFalse(Farcaster.owns_handle('carolreallybiglongname'))
        self.assertFalse(Farcaster.owns_handle('@'))
        self.assertFalse(Farcaster.owns_handle('alice.com'))
        self.assertFalse(Farcaster.owns_handle('http://foo/bar'))

    def test_fid(self, _):
        self.assertEqual(123, self.user.fid)

    def test_handle_no_profile(self, _):
        self.assertEqual('123', self.user.handle)

    def test_handle_with_username(self, _):
        obj = Object(id='farcaster://123/0x456', our_as1={
            'objectType': 'person',
            'username': 'snarfed',
        })
        self.user.obj_key = obj.put()
        self.assertEqual('snarfed', self.user.handle)

    def test_web_url_no_key(self, _):
        self.assertIsNone(Farcaster().web_url())

    def test_web_url(self, _):
        self.assertEqual('https://farcaster.xyz/~/profiles/123', self.user.web_url())

    def test_id_uri(self, _):
        self.assertEqual('farcaster://123', self.user.id_uri())

    def test_target_for(self, _):
        obj = Object(id='farcaster://123/0x456')
        self.assertEqual(Farcaster.DEFAULT_TARGET, Farcaster.target_for(obj))

    def test_target_for_non_farcaster_id(self, _):
        self.assertIsNone(Farcaster.target_for(Object(id='https://x.com/y')))

    def test_handle_to_id(self, mock_stub):
        mock_stub.return_value.GetUsernameProof.return_value = \
            UserNameProof(fid=123, name=b'snarfed')

        self.assertEqual('farcaster://123', Farcaster.handle_to_id('snarfed'))
        mock_stub.return_value.GetUsernameProof.assert_called_once_with(
            UsernameProofRequest(name=b'snarfed'))

    def test_handle_to_id_invalid_handle(self, _):
        self.assertIsNone(Farcaster.handle_to_id('not a valid handle'))

    def test_handle_to_id_not_found(self, mock_stub):
        mock_stub.return_value.GetUsernameProof.return_value = UserNameProof()
        self.assertIsNone(Farcaster.handle_to_id('snarfed'))
        mock_stub.return_value.GetUsernameProof.assert_called_once_with(
            UsernameProofRequest(name=b'snarfed'))

    def test_fetch_cast(self, mock_stub):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body { text: "hello world" }
""")
        mock_stub.return_value.GetCast.return_value = msg

        obj = Object(id=f'farcaster://123/0x{msg.hash.hex()}')
        self.assertTrue(Farcaster.fetch(obj))
        self.assertEqual([msg.SerializeToString()], obj.farcaster)
        mock_stub.return_value.GetCast.assert_called_once_with(
            CastId(fid=123, hash=bytes.fromhex(msg.hash.hex())))

    def test_fetch_user_data(self, mock_stub):
        msg = user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'snarfed')
        mock_stub.return_value.GetUserDataByFid.return_value = \
            MessagesResponse(messages=[msg])

        obj = Object(id='farcaster://123')
        self.assertTrue(Farcaster.fetch(obj))
        self.assertEqual([msg.SerializeToString()], obj.farcaster)
        mock_stub.return_value.GetUserDataByFid.assert_called_once_with(
            FidRequest(fid=123))

    def test_fetch_user_data_empty(self, mock_stub):
        mock_stub.return_value.GetUserDataByFid.return_value = \
            MessagesResponse(messages=[])
        self.assertFalse(Farcaster.fetch(Object(id='farcaster://123')))
        mock_stub.return_value.GetUserDataByFid.assert_called_once_with(
            FidRequest(fid=123))

    def test_fetch_unsupported_id(self, _):
        self.assertFalse(Farcaster.fetch(Object(id='https://x.com/y')))

    def test_convert_uses_stored_farcaster(self, _):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body { text: "hi" }
""")
        obj = Object(id='farcaster://123/0x456', farcaster=[msg.SerializeToString()])

        expected = text_format.Merge(r"""
hash: "Uy\373U\312<\036S<@}\206\315\263\031C&\302\341\253"
hash_scheme: HASH_SCHEME_BLAKE3
data_bytes: "\010\001\020{\030\245\254\304\216\006 \001*\004\"\002hi"
""", msg)
        self.assertEqual([expected], Farcaster.convert(obj))

    def test_convert_empty(self, _):
        self.assertIsNone(Farcaster.convert(Object(id='farcaster://123')))

    def test_convert_cast(self, _):
        obj = Object(id='farcaster://123/0xabcd', source_protocol='ui', our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'author': 'farcaster://123',
        })
        self.assertEqual([message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""")], Farcaster.convert(obj))

    def test_convert_actor_multiple_user_data(self, _):
        obj = Object(id='farcaster://123', source_protocol='ui', our_as1={
            'objectType': 'person',
            'id': 'farcaster://123',
            'displayName': 'Alice',
            'username': 'alice',
            'summary': 'hi',
        })
        self.assertEqual([
            user_data_message(123, 'USER_DATA_TYPE_DISPLAY', 'Alice'),
            user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice'),
            user_data_message(123, 'USER_DATA_TYPE_BIO', 'hi'),
        ], Farcaster.convert(obj))

    def test_convert_from_user_sets_fid(self, _):
        # the message fid comes from from_user, overriding the object's author id
        obj = Object(id='farcaster://456/0xabcd', source_protocol='ui', our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'author': 'farcaster://456',
        })
        msgs = Farcaster.convert(obj, from_user=self.user)
        self.assertEqual([123], [msg.data.fid for msg in msgs])

    def test_convert_actor_from_user_sets_fid(self, _):
        # the object id isn't a farcaster:// uri so its fid can't be recovered,
        # eg an ATProto profile record id; the fid comes from from_user
        obj = Object(id='at://did:plc:abc/app.bsky.actor.profile/self',
                     source_protocol='atproto', our_as1={
            'objectType': 'person',
            'id': 'at://did:plc:abc/app.bsky.actor.profile/self',
            'displayName': 'Alice',
            'username': 'alice',
        })
        msgs = Farcaster.convert(obj, from_user=self.user)
        self.assertEqual([123, 123], [msg.data.fid for msg in msgs])

    def test_send_cast(self, mock_stub):
        resp = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body { text: "hello world" }
""")
        mock_stub.return_value.SubmitBulkMessages.return_value = \
            SubmitBulkMessagesResponse(messages=[BulkMessageResponse(message=resp)])

        obj = Object(id='farcaster://123/0xabcd', source_protocol='ui', our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'author': 'farcaster://123',
        })
        obj.put()

        self.assertTrue(Farcaster.send(obj, Farcaster.DEFAULT_TARGET,
                                       from_user=self.user))

        actual = mock_stub.return_value.SubmitBulkMessages.call_args[0][0]
        for m in actual.messages:
            m.ClearField('signature')
            m.ClearField('signer')
            m.ClearField('signature_scheme')
        self.assertEqual(SubmitBulkMessagesRequest(messages=[message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body { text: "hello world" }
""")]), actual)
        self.assertEqual(
            [Target(uri=f'farcaster://123/0x{resp.hash.hex()}',
                    protocol='farcaster')],
            obj.key.get().copies)

    def test_send_actor(self, mock_stub):
        resps = [
            user_data_message(123, 'USER_DATA_TYPE_DISPLAY', 'Alice'),
            user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice'),
            user_data_message(123, 'USER_DATA_TYPE_BIO', 'hi'),
        ]
        mock_stub.return_value.SubmitBulkMessages.return_value = \
            SubmitBulkMessagesResponse(messages=[
                BulkMessageResponse(message=m) for m in resps])

        obj = Object(id='farcaster://123', source_protocol='ui', our_as1={
            'objectType': 'person',
            'id': 'farcaster://123',
            'displayName': 'Alice',
            'username': 'alice',
            'summary': 'hi',
        })
        obj.put()

        self.assertTrue(Farcaster.send(obj, Farcaster.DEFAULT_TARGET,
                                       from_user=self.user))

        actual = mock_stub.return_value.SubmitBulkMessages.call_args[0][0]
        for m in actual.messages:
            m.ClearField('signature')
            m.ClearField('signer')
            m.ClearField('signature_scheme')
        self.assertEqual(SubmitBulkMessagesRequest(messages=[
            user_data_message(123, 'USER_DATA_TYPE_DISPLAY', 'Alice'),
            user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice'),
            user_data_message(123, 'USER_DATA_TYPE_BIO', 'hi\n\n🌉 bridged from 🏛️ https://farcaster.xyz/~/profiles/123 by https://fed.brid.gy/'),
        ]), actual)
        self.assertEqual(
            [Target(uri='farcaster://123', protocol='farcaster')],
            obj.key.get().copies)

    def test_bridged_web_url_for_self_no_copy(self, _):
        self.assertIsNone(Farcaster.bridged_web_url_for(self.user))
