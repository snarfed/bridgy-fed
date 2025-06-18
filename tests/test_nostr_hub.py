"""Unit tests for nostr_hub.py."""
from datetime import datetime
from unittest import skip
from unittest.mock import patch

from granary.nostr import (
    id_and_sign,
    id_to_uri,
    KIND_DELETE,
    KIND_NOTE,
    KIND_PROFILE,
    KIND_RELAYS,
    uri_for,
    uri_to_id,
)
from granary.tests.test_nostr import (
    FakeConnection,
    NOW_TS,
    NPUB_URI,
    NSEC_URI,
    PRIVKEY,
    PUBKEY,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from models import Object
import nostr_hub
from nostr import Nostr
from protocol import DELETE_TASK_DELAY
from .testutil import Fake, TestCase
from web import Web

BOB_PUBKEY = 'be7e55eb264470903bbcf1d02ea417b5e1d2cd788cd6155f8e0b361a2bea76ed'
BOB_NPUB_URI = 'nostr:npub1hel9t6exg3cfqwau78gzafqhkhsa9ntc3ntp2huwpvmp52l2wmksdr85t7'
BOB_NSEC_URI = 'nostr:nsec1al80skcswjnwpukq3cw24x9rvdwyel8qls6kcled3q9ethqflu4q30070v'
EVE_PUBKEY = 'bd19ea0297facfe0e766f08995a0a92ca1ea52bf5f664fe2487f7894a7b0a7ff'
EVE_NPUB_URI = 'nostr:npub1h5v75q5hlt87pemx7zyetg9f9js7554ltanylcjg0aufffas5lls5m6tcf'
EVE_NSEC_URI = 'nostr:nsec1ger8dg42xau7ctdaduv6wse8apzueqgye3l7ta6dcj4j7w07lqdq4d9rey'
FRANK_PUBKEY = '2032dba5fdf02ba4223381075da4ba7dc6cf976aacb2ca658f13e00d834a0e29'
FRANK_NPUB_URI = 'nostr:npub1yqedhf0a7q46gg3nsyr4mf960hrvl9m24jev5ev0z0sqmq62pc5stypxxz'
FRANK_NSEC_URI = 'nostr:nsec12hj6ylwt5kypmq6hs7tssy3h68hdy5kvwj9qwhgv60vh6qdud8vsd5c3ln'


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
        nostr_hub.subscribed_relays = []

        self.alice = self.make_user(
            'fake:alice', cls=Fake, enabled_protocols=['nostr'],
            nostr_key_bytes=bytes.fromhex(PRIVKEY))

        self.bob = self.make_user(BOB_NPUB_URI, cls=Nostr, enabled_protocols=['fake'])

    def test_init_load_users(self, _, __):
        nostr_hub.init(subscribe=False)
        self.assertEqual(set((PUBKEY,)), nostr_hub.bridged_pubkeys)
        self.assertEqual(set((BOB_PUBKEY,)), nostr_hub.nostr_pubkeys)

        eve = self.make_user('fake:eve', cls=Fake, enabled_protocols=['nostr'],
                             nostr_key_bytes=bytes.fromhex(uri_to_id(EVE_NSEC_URI)))
        frank = self.make_user(FRANK_NPUB_URI, cls=Nostr, enabled_protocols=['fake'])

        nostr_hub.init(subscribe=False)
        self.assertEqual(set((PUBKEY, EVE_PUBKEY)), nostr_hub.bridged_pubkeys)
        self.assertEqual(set((BOB_PUBKEY, FRANK_PUBKEY)), nostr_hub.nostr_pubkeys)

    def test_init_subscribe_to_relays(self, _, __):
        self.assertEqual([], FakeConnection.relays)
        nostr_hub.init()
        self.assertEqual([Nostr.DEFAULT_TARGET], FakeConnection.relays)

        profile = {
            'kind': KIND_PROFILE,
            'content': json_dumps({
                'name': 'Me',
                'picture': 'http://a/pic',
            }),
        }
        relays_a = Object(id='nostr:neventa', nostr={
            'kind': KIND_RELAYS,
            'tags': [['r', 'wss://a']],
        }).put()

        self.bob.obj_key = Object(id='bob', nostr={**profile, 'pubkey': BOB_PUBKEY}
                                  ).put()
        self.bob.relays = relays_a
        self.bob.put()

        FakeConnection.reset()
        nostr_hub.init()
        self.assertEqual(['wss://a'], FakeConnection.relays)

        eve = self.make_user(EVE_NPUB_URI, cls=Nostr, enabled_protocols=['fake'],
                             obj_nostr={**profile, 'pubkey': EVE_PUBKEY},
                             relays=relays_a)

        FakeConnection.reset()
        nostr_hub.init()
        self.assertEqual([], FakeConnection.relays)

        relays_b = Object(id='nostr:neventb', nostr={
            'kind': KIND_RELAYS,
            'tags': [['r', 'wss://b']],
        }).put()
        frank = self.make_user(FRANK_NPUB_URI, cls=Nostr, enabled_protocols=['fake'],
                               obj_nostr={**profile, 'pubkey': FRANK_PUBKEY},
                               relays=relays_b)

        FakeConnection.reset()
        nostr_hub.init()
        self.assertEqual(['wss://b'], FakeConnection.relays)

    def test_subscribe_reply_to_bridged_user(self, mock_create_task, _):
        event = id_and_sign({
            'pubkey': EVE_PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello Alice!',
            'tags': [['p', PUBKEY]],
            'created_at': NOW_TS,
        }, privkey=EVE_NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)
        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri('note', event['id']),
                         source_protocol='nostr',
                         authed_as=EVE_NPUB_URI,
                         nostr=event)

    def test_subscribe_post_from_native_nostr_user(self, mock_create_task, _):
        # Create a post event from Bob - need to use test PUBKEY that matches NSEC_URI
        event = id_and_sign({
            'pubkey': BOB_PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello world!',
            'created_at': NOW_TS,
        }, privkey=BOB_NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)
        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri('note', event['id']),
                         source_protocol='nostr',
                         authed_as=BOB_NPUB_URI,
                         nostr=event)

    def test_subscribe_mention_protocol_bot(self, mock_create_task, _):
        # Create a protocol bot with a valid hex pubkey
        bot = self.make_user('fa.brid.gy', cls=Web, enabled_protocols=['nostr'],
                             nostr_key_bytes=bytes.fromhex(uri_to_id(EVE_NSEC_URI)))
        bot_pubkey = EVE_PUBKEY

        event = id_and_sign({
            'pubkey': FRANK_PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Hello @fa.brid.gy!',
            'tags': [['p', bot_pubkey]],
            'created_at': NOW_TS,
        }, privkey=FRANK_NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY, bot_pubkey]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)
        self.assert_task(mock_create_task, 'receive',
                         id=id_to_uri('note', event['id']),
                         source_protocol='nostr',
                         authed_as=FRANK_NPUB_URI,
                         nostr=event)

    def test_subscribe_unrelated_event(self, mock_create_task, _):
        event = id_and_sign({
            'pubkey': EVE_PUBKEY,
            'kind': KIND_NOTE,
            'content': 'Just chatting',
            'tags': [['p', 'abc123']],
            'created_at': NOW_TS,
        }, EVE_NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)
        mock_create_task.assert_not_called()

    def test_subscribe_invalid_events(self, mock_create_task, _):
        events = [
            id_and_sign({
                'pubkey': 'bad_not_hex',
                'kind': KIND_NOTE,
                'content': 'bad pubkey',
            }, privkey=NSEC_URI),
            {
                'pubkey': PUBKEY,
                'id': 'bad_not_hex',
                'kind': KIND_NOTE,
                'content': 'bad id',
                'sig': 'unused',
            },
            id_and_sign({
                'pubkey': PUBKEY,
                'kind': KIND_NOTE,
                'content': 'bad sig',
            }, privkey=NSEC_URI),
        ]
        events[1]['sig'] = 'bad'

        FakeConnection.to_receive = [['EVENT', 'sub123', event] for event in events]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)
        mock_create_task.assert_not_called()

    def test_subscribe_delete_event(self, mock_create_task, _):
        event = id_and_sign({
            'pubkey': BOB_PUBKEY,
            'kind': KIND_DELETE,
            'content': '',
            'tags': [
                ['e', 'eventToDelete123'],
                ['p', PUBKEY],
            ],
            'created_at': NOW_TS,
        }, privkey=BOB_NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'sub123', event],
            ['EOSE', 'sub123'],
        ]

        nostr_hub.init(subscribe=False)
        nostr_hub.subscribe('wss://reelaay', limit=2)

        self.assertEqual(['wss://reelaay'], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'sub123',
             {'#p': [PUBKEY]},
             {'authors': [BOB_PUBKEY]},
             ]
        ], FakeConnection.sent)

        delayed_eta = NOW_TS + DELETE_TASK_DELAY.total_seconds()
        self.assert_task(mock_create_task, 'receive',
                         id=uri_for(event),
                         source_protocol='nostr',
                         authed_as=BOB_NPUB_URI,
                         nostr=event,
                         eta_seconds=delayed_eta)
