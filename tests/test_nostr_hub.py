"""Unit tests for nostr_hub.py."""
from datetime import datetime, timedelta
from unittest import skip
from unittest.mock import patch

from granary.nostr import (
    bech32_decode,
    bech32_encode,
    id_and_sign,
    id_to_uri,
    KIND_DELETE,
    KIND_NOTE,
)
from granary.tests.test_nostr import (
    fake_connect,
    FakeConnection,
    NOW_TS,
    NPUB_URI,
    NSEC_URI,
    PUBKEY,
)
from oauth_dropins.webutil import util
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

import common
from models import Target
import nostr_hub
from nostr import Nostr
from protocol import DELETE_TASK_DELAY
from .testutil import Fake, TestCase
from web import Web

BOB_PUBKEY = 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab'
BOB_NPUB_URI = 'nostr:npub140x3ydzk0zg2hn00zg69v7ys40x77y352eufp27daufrg4ncjz4skgrm7u'


@patch('secrets.token_urlsafe', return_value='sub123')
@patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
class NostrHubTest(TestCase):
    def setUp(self):
        super().setUp()
        FakeConnection.reset()
        common.RUN_TASKS_INLINE = False

        nostr_hub.nostr_pubkeys = set()
        nostr_hub.nostr_loaded_at = datetime(1900, 1, 1)
        nostr_hub.bridged_pubkeys = set()
        nostr_hub.bridged_loaded_at = datetime(1900, 1, 1)
        nostr_hub.protocol_bot_pubkeys = set()
        nostr_hub.pubkeys_initialized.clear()

        self.alice = self.make_user('fake:alice', cls=Fake,
                                    enabled_protocols=['nostr'],
                                    copies=[Target(uri=NPUB_URI, protocol='nostr')])

        self.bob = self.make_user(BOB_NPUB_URI, cls=Nostr, enabled_protocols=['fake'])

    def test_load_pubkeys(self, _, __):
        util.now = lambda: datetime.now().replace(tzinfo=None)

        nostr_hub.load_pubkeys()
        self.assertEqual(set((PUBKEY,)), nostr_hub.bridged_pubkeys)
        # TODO: nostr_hub.nostr_pubkeys is (BOB_PUBKEY,)

        eve_npub = 'npub1z24szqzphd'
        fake_user = self.make_user(
            'fake:eve', cls=Fake, enabled_protocols=['nostr'],
            copies=[Target(uri=f'nostr:{eve_npub}', protocol='nostr')])

        frank_npub = 'nostr:npub140qjxm63yry'
        frank = self.make_user(frank_npub, cls=Nostr, enabled_protocols=['fake'])

        nostr_hub.load_pubkeys()
        self.assertEqual(set((PUBKEY, bech32_decode(eve_npub))),
                         nostr_hub.bridged_pubkeys)
        # TODO: nostr_hub.nostr_pubkeys is (BOB_PUBKEY, bech32_decode(frank.key.id()))

    def test_subscribe_reply_to_bridged_user(self, mock_create_task, _):
        event = id_and_sign({
            'pubkey': PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello Alice!',
            'tags': [['p', PUBKEY]],
            'created_at': NOW_TS,
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri('nevent', event['id']),
                         source_protocol='nostr',
                         authed_as=NPUB_URI,
                         nostr=event)

    # TODO: uncomment when we support native Nostr users
    @skip
    def test_subscribe_post_from_native_nostr_user(self, mock_create_task, _):
        # Create a post event from Bob - need to use test PUBKEY that matches NSEC_URI
        event = id_and_sign({
            'pubkey': BOB_PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello world!',
            'tags': [],
            'created_at': NOW_TS,
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        bob_npub = bech32_encode('npub', BOB_PUBKEY)
        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri(event['id']),
                         source_protocol='nostr',
                         authed_as=f'nostr:{bob_npub}',
                         nostr=event)

    def test_subscribe_mention_protocol_bot(self, mock_create_task, _):
        # Create a protocol bot with a valid hex pubkey
        bot = self.make_user('fa.brid.gy', cls=Web, enabled_protocols=['nostr'],
                           copies=[Target(uri=BOB_NPUB_URI, protocol='nostr')])

        event = id_and_sign({
            'pubkey': PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello @fa.brid.gy!',
            'tags': [['p', BOB_PUBKEY]],
            'created_at': NOW_TS,
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri('nevent', event['id']),
                         source_protocol='nostr',
                         authed_as=NPUB_URI,
                         nostr=event)

    def test_subscribe_unrelated_event(self, mock_create_task, _):
        event = {
            'id': 'unrelated123',
            'pubkey': 'random_user1',
            'kind': KIND_NOTE,
            'content': 'Just chatting',
            'tags': [['p', 'random_user2']],
            'created_at': NOW_TS,
            'sig': 'foo',
        }

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        mock_create_task.assert_not_called()

    def test_subscribe_invalid_events(self, mock_create_task, _):
        # bad signature - use a different pubkey than what we sign with
        events = [
            id_and_sign({
                'pubkey': 'bad_not_hex',
                'kind': KIND_NOTE,
                'content': 'bad pubkey',
            }, privkey=NSEC_URI),
            id_and_sign({
                'pubkey': 'not_hex',
                'kind': KIND_NOTE,
                'content': 'bad sig',
            }, privkey=NSEC_URI),
        ]
        events[1]['sig'] = 'not-right'

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', events[0]],
            ['EVENT', 'sub123', events[1]],
        ]

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        mock_create_task.assert_not_called()

    # TODO: uncomment when we support native Nostr users
    @skip
    def test_subscribe_delete_event(self, mock_create_task, _):
        nostr_hub.nostr_pubkeys = {BOB_PUBKEY}

        delete_event = id_and_sign({
            'pubkey': PUBKEY,
            'kind': KIND_DELETE,
            'content': '',
            'tags': [['e', 'eventToDelete123']],
            'created_at': NOW_TS,
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', delete_event],
            ['EOSE', 'sub123'],
        ]
        FakeConnection.recv_err = ConnectionClosedOK(None, None)

        nostr_hub.load_pubkeys()
        nostr_hub.subscribe(limit=2)

        delayed_eta = NOW_TS + DELETE_TASK_DELAY.total_seconds()
        bob_npub = bech32_encode('npub', BOB_PUBKEY)
        self.assert_task(mock_create_task, 'receive',
                         id=f'nostr:nevent{delete_event["id"]}',
                         source_protocol='nostr',
                         authed_as=f'nostr:{bob_npub}',
                         nostr=delete_event,
                         eta_seconds=delayed_eta)

