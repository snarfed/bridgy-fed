"""Unit tests for farcaster_hub.py."""
from datetime import datetime
from unittest.mock import patch

from google.protobuf import text_format
import granary.farcaster
from granary.generated.farcaster.hub_event_pb2 import (
    HUB_EVENT_TYPE_MERGE_MESSAGE,
    HubEvent,
    MergeMessageBody,
)
from granary.generated.farcaster.request_response_pb2 import MessagesResponse
from granary.tests.test_farcaster import message, user_data_message
from webutil.testutil import NOW

import common
import farcaster_hub
import farcaster
from farcaster import Farcaster
from models import Cursor, Target
from protocol import DELETE_TASK_DELAY
from .testutil import Fake, TestCase

EVENT_TIMESTAMP = granary.farcaster.to_timestamp(NOW)


def merge_event(msg, id=1, timestamp=EVENT_TIMESTAMP):
    return HubEvent(id=id, type=HUB_EVENT_TYPE_MERGE_MESSAGE, timestamp=timestamp,
                    merge_message_body=MergeMessageBody(message=msg))


def encode_messages(msgs):
    return [text_format.MessageToString(msg, as_one_line=True,
                                        use_short_repeated_primitives=True)
           for msg in msgs]


class FarcasterHubTest(TestCase):
    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False
        farcaster_hub.fids = set()
        farcaster_hub.bridged_fids = set()
        farcaster_hub.fids_loaded_at = datetime(1900, 1, 1)
        farcaster_hub.fids_initialized.clear()
        farcaster_hub.cursor = None
        farcaster_hub.last_event_at = None
        farcaster_hub.last_enqueued_at = None
        farcaster._client = None

        # alice is a native, bridged out Farcaster user
        self.alice = self.make_user('farcaster://123', cls=Farcaster,
                                   enabled_protocols=['fake'])
        # bob is a non-Farcaster user bridged into Farcaster
        self.bob = self.make_user('fake:bob', cls=Fake, enabled_protocols=['farcaster'],
                                  copies=[Target(protocol='farcaster',
                                                uri='farcaster://456')])

        create_task_patch = patch('webutil.appengine_config.tasks_client.create_task')
        self.mock_create_task = create_task_patch.start()
        self.addCleanup(create_task_patch.stop)

        stub_patch = patch('granary.farcaster.rpc_pb2_grpc.HubServiceStub')
        self.mock_stub = stub_patch.start()
        self.addCleanup(stub_patch.stop)

    def serve_and_subscribe(self, events):
        farcaster_hub._load_fids()
        self.mock_stub.return_value.Subscribe.return_value = iter(events)
        farcaster_hub.subscribe()

    def assert_enqueued(self, fid, msg, eta_seconds=None):
        self.assert_task(self.mock_create_task, 'receive',
                         id=f'farcaster://{fid}/0x{msg.hash.hex()}',
                         source_protocol='farcaster',
                         authed_as=f'farcaster://{fid}',
                         fc=encode_messages([msg]),
                         eta_seconds=eta_seconds,
                         **({} if eta_seconds else {'received_at': NOW.isoformat()}))

    def test_init_load_fids(self):
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

    def test_subscribe_post_from_bridged_out_user(self):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(123, msg)

    def test_subscribe_mention_of_bridged_user(self):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hi @bob"
  mentions: 456
  mentions_positions: 3
}
""", fid=999)
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(999, msg)

    def test_subscribe_reply_to_bridged_user(self):
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
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(999, msg)

    def test_subscribe_reaction_on_bridged_users_cast(self):
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
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(999, msg)

    def test_subscribe_reaction_from_bridged_out_user(self):
        # alice (bridged out) likes some unrelated, unbridged user's cast. it
        # should still be bridged, since alice herself is bridged, regardless
        # of the target
        msg = message("""
type: MESSAGE_TYPE_REACTION_ADD
reaction_body {
  type: REACTION_TYPE_LIKE
  target_cast_id {
    fid: 999
    hash: "\\357x\\220\\0224"
  }
}
""", fid=123)
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(123, msg)

    def test_subscribe_reaction_on_bridged_out_users_cast_unrelated(self):
        # an unrelated, unbridged user likes alice's (bridged out) cast. we
        # only check reaction targets against bridged_fids (non-Farcaster
        # users bridged in), not fids (native, bridged out users), so this
        # isn't bridged, same as nostr_hub, which only checks mentions
        # against bridged_pubkeys, not nostr_pubkeys
        msg = message("""
type: MESSAGE_TYPE_REACTION_ADD
reaction_body {
  type: REACTION_TYPE_LIKE
  target_cast_id {
    fid: 123
    hash: "\\357x\\220\\0224"
  }
}
""", fid=999)
        self.serve_and_subscribe([merge_event(msg)])
        self.mock_create_task.assert_not_called()

    def test_subscribe_follow_of_bridged_user(self):
        msg = message("""
type: MESSAGE_TYPE_LINK_ADD
link_body {
  type: "follow"
  target_fid: 456
  displayTimestamp: 31633445
}
""", fid=999)
        self.serve_and_subscribe([merge_event(msg)])
        self.assert_enqueued(999, msg)

    def test_subscribe_unfollow_of_bridged_user_delayed(self):
        msg = message("""
type: MESSAGE_TYPE_LINK_REMOVE
link_body {
  type: "follow"
  target_fid: 456
  displayTimestamp: 31633445
}
""", fid=999)
        self.serve_and_subscribe([merge_event(msg)])

        delayed_eta = NOW.timestamp() + DELETE_TASK_DELAY.total_seconds()
        self.assert_enqueued(999, msg, eta_seconds=delayed_eta)

    def test_subscribe_cast_remove_from_bridged_out_user_delayed(self):
        msg = message("""
type: MESSAGE_TYPE_CAST_REMOVE
cast_remove_body {
  target_hash: "\\253\\315x\\220\\022"
}
""", fid=123)
        self.serve_and_subscribe([merge_event(msg)])

        delayed_eta = NOW.timestamp() + DELETE_TASK_DELAY.total_seconds()
        self.assert_enqueued(123, msg, eta_seconds=delayed_eta)

    def test_subscribe_post_from_unbridged_user(self):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=999)
        self.serve_and_subscribe([merge_event(msg)])
        self.mock_create_task.assert_not_called()

    def test_subscribe_profile_update_from_bridged_out_user(self):
        username_msg = user_data_message(123, 'USER_DATA_TYPE_USERNAME', 'alice')
        display_msg = user_data_message(123, 'USER_DATA_TYPE_DISPLAY', 'Alice')

        self.mock_stub.return_value.GetUserDataByFid.return_value = \
            MessagesResponse(messages=[display_msg, username_msg])

        self.serve_and_subscribe([merge_event(username_msg)])
        self.assert_task(
            self.mock_create_task,
            'receive',
            id='farcaster://123#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            source_protocol='farcaster',
            authed_as='farcaster://123',
            fc=encode_messages([display_msg, username_msg]),
            received_at=NOW.isoformat())

    def test_subscribe_profile_update_non_bridged_user(self):
        update_msg = user_data_message(999, 'USER_DATA_TYPE_USERNAME', 'eve')
        self.serve_and_subscribe([merge_event(update_msg)])
        self.mock_create_task.assert_not_called()
        self.mock_stub.return_value.GetUserDataByFid.assert_not_called()

    def test_subscribe_stores_cursor(self):
        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
        self.serve_and_subscribe([merge_event(msg, id=555)])

        self.assertEqual(
            555, Cursor.get_by_id(f'{farcaster_hub.SNAPCHAIN_HOST} Subscribe').cursor)

    def test_subscribe_with_stored_cursor(self):
        Cursor(id=f'{farcaster_hub.SNAPCHAIN_HOST} Subscribe', cursor=100).put()

        msg = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
        self.serve_and_subscribe([merge_event(msg, id=200)])

        sent_request = self.mock_stub.return_value.Subscribe.call_args[0][0]
        self.assertEqual(101, sent_request.from_id)
        self.assertEqual(200, Cursor.get_by_id(
            f'{farcaster_hub.SNAPCHAIN_HOST} Subscribe').cursor)

    def test_subscribe_updates_last_event_and_enqueued_timestamps(self):
        bridged = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=123)
        unrelated = message("""
type: MESSAGE_TYPE_CAST_ADD
cast_add_body {
  text: "hello world"
}
""", fid=999)
        later_timestamp = EVENT_TIMESTAMP + 10
        self.serve_and_subscribe(
            [merge_event(bridged, id=1),
             merge_event(unrelated, id=2, timestamp=later_timestamp)])

        self.assertEqual(granary.farcaster.from_timestamp(later_timestamp),
                         farcaster_hub.last_event_at)
        self.assertEqual(NOW, farcaster_hub.last_enqueued_at)
