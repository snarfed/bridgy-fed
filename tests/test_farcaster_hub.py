"""Unit tests for farcaster_hub.py."""
import base64
from datetime import datetime, timedelta
from unittest.mock import patch

from granary.generated.farcaster.hub_event_pb2 import (
    HUB_EVENT_TYPE_MERGE_MESSAGE,
    HubEvent,
    MergeMessageBody,
)
from granary.generated.farcaster.request_response_pb2 import MessagesResponse
from granary.tests.test_farcaster import message, user_data_message
from webutil.testutil import NOW
from webutil.util import json_dumps

import common
import farcaster_hub
import farcaster
from farcaster import Farcaster
from models import Cursor, Target
from protocol import DELETE_TASK_DELAY
from .testutil import Fake, TestCase


def merge_event(msg, id=1):
    return HubEvent(id=id, type=HUB_EVENT_TYPE_MERGE_MESSAGE,
                    merge_message_body=MergeMessageBody(message=msg))

def encode_messages(msgs):
    return json_dumps([base64.b64encode(msg.SerializeToString()).decode()
                       for msg in msgs])


@patch('granary.farcaster.rpc_pb2_grpc.HubServiceStub')
class FarcasterHubTest(TestCase):
    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False
        farcaster_hub.fids = set()
        farcaster_hub.bridged_fids = set()
        farcaster_hub.fids_loaded_at = datetime(1900, 1, 1)
        farcaster_hub.fids_initialized.clear()
        farcaster_hub.seen_hashes.clear()
        farcaster_hub.cursor = None
        farcaster._client = None

        # alice is a native, bridged out Farcaster user
        self.alice = self.make_user('farcaster://123', cls=Farcaster,
                                   enabled_protocols=['fake'])
        # bob is a non-Farcaster user bridged into Farcaster
        self.bob = self.make_user('fake:bob', cls=Fake, enabled_protocols=['farcaster'],
                                  copies=[Target(protocol='farcaster',
                                                uri='farcaster://456')])

    def serve_and_subscribe(self, events, mock_stub):
        farcaster_hub._load_fids()
        mock_stub.return_value.Subscribe.return_value = iter(events)
        farcaster_hub.subscribe()

    def test_init_load_fids(self, _):
        farcaster_hub._load_fids()
        self.assertEqual({123}, farcaster_hub.fids)
        self.assertEqual({456}, farcaster_hub.bridged_fids)

        eve = self.make_user('farcaster://789', cls=Farcaster,
                             enabled_protocols=['fake'])
        frank = self.make_user('fake:frank', cls=Fake, enabled_protocols=['farcaster'],
                               copies=[Target(protocol='farcaster',
                                             uri='farcaster://999')])

        farcaster_hub._load_fids()
        self.assertEqual({123, 789}, farcaster_hub.fids)
        self.assertEqual({456, 999}, farcaster_hub.bridged_fids)

    def test_subscribe_post_from_bridged_out_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://123/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://123',
                             farcaster=encode_messages([msg]))

    def test_subscribe_mention_of_bridged_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hi @bob"
  mentions: 456
  mentions_positions: 3
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://999/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://999',
                             farcaster=encode_messages([msg]))

    def test_subscribe_reply_to_bridged_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "replying"
  parent_cast_id {
    fid: 456
    hash: "\\253\\315x\\220\\022"
  }
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://999/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://999',
                             farcaster=encode_messages([msg]))

    def test_subscribe_reaction_on_bridged_users_cast(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_REACTION_ADD
reaction_body {
  type: REACTION_TYPE_LIKE
  target_cast_id {
    fid: 456
    hash: "\\357x\\220\\0224"
  }
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://999/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://999',
                             farcaster=encode_messages([msg]))

    def test_subscribe_follow_of_bridged_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_LINK_ADD
link_body {
  type: "follow"
  target_fid: 456
  displayTimestamp: 31633445
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://999/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://999',
                             farcaster=encode_messages([msg]))

    def test_subscribe_unfollow_of_bridged_user_delayed(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_LINK_REMOVE
link_body {
  type: "follow"
  target_fid: 456
  displayTimestamp: 31633445
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            delayed_eta = NOW.timestamp() + DELETE_TASK_DELAY.total_seconds()
            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://999/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://999',
                             farcaster=encode_messages([msg]),
                             eta_seconds=delayed_eta)

    def test_subscribe_cast_remove_from_bridged_out_user_delayed(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_REMOVE
cast_remove_body {
  target_hash: "\\253\\315x\\220\\022"
}
""", fid=123)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)

            delayed_eta = NOW.timestamp() + DELETE_TASK_DELAY.total_seconds()
            self.assert_task(mock_create_task, 'receive',
                             id=f'farcaster://123/0x{msg.hash.hex()}',
                             source_protocol='farcaster',
                             authed_as='farcaster://123',
                             farcaster=encode_messages([msg]),
                             eta_seconds=delayed_eta)

    def test_subscribe_unrelated_event(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=999)
            self.serve_and_subscribe([merge_event(msg)], mock_stub)
            mock_create_task.assert_not_called()

    def test_subscribe_dedupe_on_hash(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
            self.serve_and_subscribe([merge_event(msg, id=1), merge_event(msg, id=2)],
                                     mock_stub)
            mock_create_task.assert_called_once()

    def test_subscribe_profile_update_from_bridged_out_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            update_msg = user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice')
            full_msgs = [
                user_data_message(123, 'USER_DATA_TYPE_DISPLAY', 'Alice'),
                user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice'),
            ]
            mock_stub.return_value.GetUserDataByFid.return_value = \
                MessagesResponse(messages=full_msgs)

            self.serve_and_subscribe([merge_event(update_msg)], mock_stub)

            self.assert_task(mock_create_task, 'receive',
                             id='farcaster://123',
                             source_protocol='farcaster',
                             authed_as='farcaster://123',
                             farcaster=encode_messages(full_msgs))

    def test_subscribe_profile_update_non_bridged_user(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task') as mock_create_task:
            update_msg = user_data_message(999, 'USER_DATA_TYPE_USERNAME', 'eve')
            self.serve_and_subscribe([merge_event(update_msg)], mock_stub)
            mock_create_task.assert_not_called()
            mock_stub.return_value.GetUserDataByFid.assert_not_called()

    def test_subscribe_stores_cursor(self, mock_stub):
        with patch('webutil.appengine_config.tasks_client.create_task'):
            msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
            self.serve_and_subscribe([merge_event(msg, id=555)], mock_stub)

        self.assertEqual(555, Cursor.get_by_id(
            f'{farcaster_hub.SNAPCHAIN_HOST}:{farcaster_hub.SNAPCHAIN_PORT}').cursor)
