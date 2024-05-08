"""Unit tests for atproto_firehose.py."""
from unittest import skip
from unittest.mock import patch

import arroba.util
from carbox import read_car, write_car
from carbox.car import Block
import dag_cbor
from google.cloud.tasks_v2.types import Task
from granary.tests.test_bluesky import (
    ACTOR_PROFILE_BSKY,
    LIKE_BSKY,
    POST_BSKY,
    REPLY_BSKY,
    REPOST_BSKY,
)
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil import util
import simple_websocket

from atproto import ATProto
from atproto_firehose import new_commits, subscribe
import common
from models import Object, PROTOCOLS, Target
import protocol
from .testutil import ExplicitEnableFake, Fake, TestCase
from .test_atproto import DID_DOC

DID_DOC_ALICE = {
    **DID_DOC,
    'id': 'did:plc:alice',
}


class FakeWebsocketClient:
    """Fake of :class:`simple_websocket.Client`."""

    def __init__(self, url):
        FakeWebsocketClient.url = url

    def send(self, msg):
        self.sent.append(json.loads(msg))

    def receive(self):
        if not self.to_receive:
            raise simple_websocket.ConnectionClosed(message='foo')

        header, payload = self.to_receive.pop(0)
        return dag_cbor.encode(header) + dag_cbor.encode(payload)

    @classmethod
    def setup_receive(cls, path, record, action='create', repo='did:plc:user'):
        cid = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        block = Block(decoded=record)
        block_bytes = write_car([cid], [block])

        cls.to_receive = [({
            'op': 1,
            't': '#commit',
        }, {
            'blocks': block_bytes,
            'commit': cid,
            'ops': [{
                'action': action,
                'cid': block.cid,
                'path': path,
            }],
            'prev': None,
            'rebase': False,
            'repo': repo,
            'rev': 'abc',
            'seq': 123,
            'since': 'def',
            'time': util.now().isoformat(),
            'tooBig': False,
        })]


class ATProtoFirehoseSubscribeTest(TestCase):
    def setUp(self):
        super().setUp()

        simple_websocket.Client = FakeWebsocketClient
        FakeWebsocketClient.sent = []
        FakeWebsocketClient.to_receive = []

    def test_error(self):
        FakeWebsocketClient.to_receive = [(
            {'op': -1},
            {'error': 'ConsumerTooSlow', 'message': 'ketchup!'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_info(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#info'},
            {'name': 'OutdatedCursor'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_non_commit(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#handle'},
            {'seq': '123', 'did': 'did:abc', 'handle': 'hi.com'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_not_for_us(self):
        self.store_object(id='did:plc:alice', raw=DID_DOC_ALICE)
        self.make_user('did:plc:alice', cls=ATProto, enabled_protocols=['eefake'])
        self.make_user('eefake:bob', cls=ExplicitEnableFake,
                       enabled_protocols=['atproto'])
        self.assertEqual(2, Object.query().count())

        FakeWebsocketClient.setup_receive('app.bsky.feed.like/abc123', POST_BSKY)

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_post_by_atproto_user(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)
        self.assertEqual(2, Object.query().count())

        FakeWebsocketClient.setup_receive('app.bsky.feed.post/abc123', POST_BSKY)

        subscribe()
        self.assertEqual(('create', POST_BSKY), new_commits.get())
        self.assertTrue(new_commits.empty())

    def test_like_of_atproto_user(self):
        alice = self.make_user('eefake:alice', cls=ExplicitEnableFake,
                               copies=[Target(protocol='atproto', uri='did:alice')])

        FakeWebsocketClient.setup_receive('app.bsky.feed.like/abc123', LIKE_BSKY)

        subscribe()
        self.assertEqual(('create', LIKE_BSKY), new_commits.get())
        self.assertTrue(new_commits.empty())


class ATProtoFirehoseHandleTest(TestCase):
    @skip
    def test_handle(self):
        at_uri = 'at://did:plc:user/app.bsky.feed.like/abc123'
        user_key = ATProto(id='did:plc:user').key
        obj = self.assert_object(at_uri, bsky=LIKE_BSKY, status='new',
                                 source_protocol='bsky', users=[user_key],
                                 notify=alice.key)
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=obj.key.urlsafe(), authed_as='did:plc:user')
