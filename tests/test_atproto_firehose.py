"""Unit tests for atproto_firehose.py."""
from unittest.mock import patch

import arroba.util
from carbox import write_car
from carbox.car import Block
import dag_cbor
from google.cloud.tasks_v2.types import Task
from granary.tests.test_bluesky import (
    ACTOR_PROFILE_BSKY,
    POST_BSKY,
    REPLY_BSKY,
    LIKE_BSKY,
    REPOST_BSKY,
)
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil import util
import simple_websocket

from atproto import ATProto
from atproto_firehose import subscribe
import common
from models import Object, PROTOCOLS, Target
import protocol
from .testutil import ExplicitEnableFake, Fake, TestCase
from .test_atproto import DID_DOC


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


@patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
class ATProtoFirehoseTest(TestCase):
    def setUp(self):
        super().setUp()
        # self.client = Client('http://ser.ver', lexicons=LEXICONS)

        simple_websocket.Client = FakeWebsocketClient
        FakeWebsocketClient.sent = []
        FakeWebsocketClient.to_receive = []

    def test_error(self, mock_create_task):
        FakeWebsocketClient.to_receive = [(
            {'op': -1},
            {'error': 'ConsumerTooSlow', 'message': 'ketchup!'},
        )]

        # noop
        subscribe()
        self.assertEqual(0, Object.query().count())
        mock_create_task.assert_not_called()

    def test_info(self, mock_create_task):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#info'},
            {'name': 'OutdatedCursor'},
        )]

        # noop
        subscribe()
        self.assertEqual(0, Object.query().count())
        mock_create_task.assert_not_called()

    def test_non_commit(self, mock_create_task):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#handle'},
            {'seq': '123', 'did': 'did:abc', 'handle': 'hi.com'},
        )]

        # noop
        subscribe()
        self.assertEqual(0, Object.query().count())
        mock_create_task.assert_not_called()

    def test_not_for_us(self, mock_create_task):
        self.store_object(id='did:plc:alice', raw={**DID_DOC, 'id': 'did:plc:alice'})
        self.make_user('did:plc:alice', cls=ATProto, enabled_protocols=['eefake'])
        self.make_user('eefake:bob', cls=ExplicitEnableFake,
                       enabled_protocols=['atproto'])
        self.assertEqual(2, Object.query().count())

        FakeWebsocketClient.setup_receive('app.bsky.feed.like/abc123', POST_BSKY)

        subscribe()
        self.assertEqual(2, Object.query().count())
        mock_create_task.assert_not_called()
