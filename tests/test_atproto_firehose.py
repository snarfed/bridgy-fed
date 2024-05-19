"""Unit tests for atproto_firehose.py."""
import copy
from datetime import datetime, timedelta, timezone
from unittest import skip
from unittest.mock import patch

from arroba.datastore_storage import AtpRepo
import arroba.util
from carbox import read_car, write_car
from carbox.car import Block
import dag_cbor
from google.cloud.tasks_v2.types import Task
from granary.tests.test_bluesky import (
    ACTOR_PROFILE_BSKY,
    LIKE_BSKY,
    POST_AS,
    POST_BSKY,
    REPLY_BSKY,
    REPOST_BSKY,
)
from multiformats import CID
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import NOW
import simple_websocket

from atproto import ATProto, Cursor
import atproto_firehose
from atproto_firehose import handle, new_commits, Op, STORE_CURSOR_FREQ, subscribe
import common
from models import Object, PROTOCOLS, Target
import protocol
from .testutil import ExplicitEnableFake, Fake, TestCase
from .test_atproto import DID_DOC

A_CID = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')


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
    def setup_receive(cls, op):
        if op.action == 'delete':
            block_bytes = b''
        else:
            block = Block(decoded=op.record)
            block_bytes = write_car([A_CID], [block])

        cls.to_receive = [({
            'op': 1,
            't': '#commit',
        }, {
            'blocks': block_bytes,
            'commit': A_CID,
            'ops': [{
                'action': op.action,
                'cid': None if op.action == 'delete' else block.cid,
                'path': op.path,
            }],
            'prev': None,
            'rebase': False,
            'repo': op.repo,
            'rev': 'abc',
            'seq': op.seq,
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

        self.cursor = Cursor(id='bgs.local com.atproto.sync.subscribeRepos')
        self.cursor.put()
        assert new_commits.empty()

        atproto_firehose.atproto_dids = set()
        atproto_firehose.atproto_loaded_at = datetime(1900, 1, 1)
        atproto_firehose.bridged_dids = set()
        atproto_firehose.bridged_loaded_at = datetime(1900, 1, 1)
        atproto_firehose.dids_initialized.clear()

        AtpRepo(id='did:alice', head='', signing_key_pem=b'').put()
        self.store_object(id='did:plc:bob', raw=DID_DOC)
        ATProto(id='did:plc:bob').put()

    def assert_enqueues(self, record=None, repo='did:plc:user', action='create',
                        path='app.bsky.feed.post/abc123'):
        FakeWebsocketClient.setup_receive(
            Op(repo=repo, action=action, path=path, seq=789, record=record))
        subscribe()

        op = new_commits.get()
        self.assertEqual(repo, op.repo)
        self.assertEqual(action, op.action)
        self.assertEqual(path, op.path)
        self.assertEqual(789, op.seq)
        self.assertEqual(record, op.record)
        self.assertTrue(new_commits.empty())

    def assert_doesnt_enqueue(self, record=None, repo='did:plc:user', action='create',
                              path='app.bsky.feed.post/abc123'):
        FakeWebsocketClient.setup_receive(
            Op(repo=repo, action=action, path=path, seq=789, record=record))
        subscribe()
        self.assertTrue(new_commits.empty())

    def test_error_message(self):
        FakeWebsocketClient.to_receive = [(
            {'op': -1},
            {'error': 'ConsumerTooSlow', 'message': 'ketchup!'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_info_message(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#info'},
            {'name': 'OutdatedCursor'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())

    def test_cursor(self):
        self.cursor.cursor = 444
        self.cursor.put()

        subscribe()
        self.assertTrue(new_commits.empty())
        self.assertEqual(
            'https://bgs.local/xrpc/com.atproto.sync.subscribeRepos?cursor=445',
            FakeWebsocketClient.url)

    def test_non_commit(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#handle'},
            {'seq': '123', 'did': 'did:abc', 'handle': 'hi.com'},
        )]

        subscribe()
        self.assertTrue(new_commits.empty())
        self.assertEqual('https://bgs.local/xrpc/com.atproto.sync.subscribeRepos',
                         FakeWebsocketClient.url)

    def test_post_by_our_atproto_user(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)
        self.assert_enqueues(POST_BSKY, repo='did:plc:user')

    def test_post_by_other(self):
        self.store_object(id='did:plc:eve', raw={**DID_DOC, 'id': 'did:plc:eve'})
        self.make_user('did:plc:eve', cls=ATProto, enabled_protocols=['eefake'])
        self.assert_doesnt_enqueue(POST_BSKY, repo='did:plc:user')

    def test_reply_direct_to_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'parent': {
                    'uri': 'at://did:alice/app.bsky.feed.post/tid',
                    # test that we encode CIDs and bytes as JSON
                    'cid': A_CID,
                },
                'root': {
                    'uri': '-',
                    'cid': A_CID,
                },
            },
        })

    def test_reply_indirect_to_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
                'parent': {'uri': '-'},
            },
        })

    def test_reply_indirect_to_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'parent': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
                'root': {'uri': '-'},
            },
        })

    def test_mention_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:alice',
                }],
            }],
        })

    def test_mention_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.post',
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:eve',
                }],
            }],
        })

    def test_quote_of_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'embed': {
                '$type': 'app.bsky.embed.record',
                'record': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
            },
        })

    def test_quote_of_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.post',
            'embed': {
                '$type': 'app.bsky.embed.record',
                'record': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
            },
        })

    def test_quote_of_our_user_with_image(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'embed': {
                '$type': 'app.bsky.embed.recordWithMedia',
                'record': {
                    'record': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
                },
                'media': {'$type': 'app.bsky.embed.images'},
            },
        })

    def test_quote_of_other_with_image(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.post',
            'embed': {
                '$type': 'app.bsky.embed.recordWithMedia',
                'record': {
                    'record': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
                },
                'media': {'$type': 'app.bsky.embed.images'},
            },
        })

    def test_like_of_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })

    def test_like_of_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
        })

    def test_repost_of_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.repost',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })

    def test_repost_of_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.repost',
            'subject': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
        })

    def test_follow_of_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:alice',
        })

    def test_follow_of_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:eve',
        })

    def test_block_of_our_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.graph.block',
            'subject': 'did:alice',
        })

    def test_block_of_other(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.graph.block',
            'subject': 'did:eve',
        })

    def test_delete_by_our_atproto_user(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)

        path = 'app.bsky.feed.post/abc123'
        self.assert_enqueues(path=path, action='delete')

    def test_delete_by_other(self):
        self.assert_doesnt_enqueue(action='delete')

    def test_update_by_our_atproto_user(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)

        self.assert_enqueues(action='delete')

    def test_update_by_other(self):
        self.assert_doesnt_enqueue(action='delete')

    def test_update_like_of_our_user(self):
        self.assert_enqueues(action='update', record={
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })

    def test_uncaught_exception_skips_commit(self):
        self.cursor.cursor = 1
        self.cursor.put()

        FakeWebsocketClient.setup_receive(
            Op(repo='did:x', action='create', path='y', seq=4, record={'foo': 'bar'}))
        with patch('atproto_firehose.read_car', side_effect=RuntimeError('oops')), \
             self.assertRaises(RuntimeError):
            subscribe()

        self.assertTrue(new_commits.empty())
        self.assertEqual(
            'https://bgs.local/xrpc/com.atproto.sync.subscribeRepos?cursor=2',
            FakeWebsocketClient.url)

        self.assert_enqueues(action='update', record={
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })
        self.assertEqual(
            'https://bgs.local/xrpc/com.atproto.sync.subscribeRepos?cursor=5',
            FakeWebsocketClient.url)


@patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
class ATProtoFirehoseHandleTest(TestCase):
    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)

        self.cursor = Cursor(id='bgs.local com.atproto.sync.subscribeRepos')
        self.cursor.put()

        atproto_firehose.atproto_dids = None
        atproto_firehose.bridged_dids = None
        atproto_firehose.dids_initialized.clear()

    def test_create(self, mock_create_task):
        reply = copy.deepcopy(REPLY_BSKY)
        # test that we encode CIDs and bytes as JSON
        reply['reply']['root']['cid'] = reply['reply']['parent']['cid'] = A_CID

        new_commits.put(Op(repo='did:plc:user', action='create', seq=789,
                           path='app.bsky.feed.post/123', record=reply))

        handle(limit=1)

        expected = copy.deepcopy(REPLY_BSKY)
        expected['reply']['root']['cid'] = expected['reply']['parent']['cid'] = {
            '$link': A_CID.encode(),
        }
        user_key = ATProto(id='did:plc:user').key
        obj = self.assert_object('at://did:plc:user/app.bsky.feed.post/123',
                                 bsky=expected, source_protocol='atproto',
                                 status='new', users=[user_key],
                                 ignore=['our_as1'])
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=obj.key.urlsafe(), authed_as='did:plc:user')

    def test_delete(self, mock_create_task):
        new_commits.put(Op(repo='did:plc:user', action='delete', seq=789,
                           path='app.bsky.feed.post/123', record=POST_BSKY))

        handle(limit=1)

        obj_id = 'at://did:plc:user/app.bsky.feed.post/123'
        delete_id = f'{obj_id}#delete'
        user_key = ATProto(id='did:plc:user').key
        obj = self.assert_object(delete_id, source_protocol='atproto',
                                 status='new', users=[user_key], our_as1={
                                     'objectType': 'activity',
                                     'verb': 'delete',
                                     'id': delete_id,
                                     'actor': 'did:plc:user',
                                     'object': obj_id,
                                 })
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=obj.key.urlsafe(), authed_as='did:plc:user')

    def test_store_cursor(self, mock_create_task):
        now = None
        def _now(tz=None):
            assert tz is None
            nonlocal now
            return now

        util.now = _now

        self.cursor.cursor = 444
        self.cursor.put()

        op = Op(repo='did:plc:user', action='create', seq=789,
                path='app.bsky.feed.post/123', record=POST_BSKY)

        # hasn't quite been long enough to store new cursor
        now = (self.cursor.updated.replace(tzinfo=timezone.utc)
               + STORE_CURSOR_FREQ - timedelta(seconds=1))
        new_commits.put(op)
        handle(limit=1)
        self.assertEqual(444, self.cursor.key.get().cursor)

        # now it's been long enough
        now = (self.cursor.updated.replace(tzinfo=timezone.utc)
               + STORE_CURSOR_FREQ + timedelta(seconds=1))
        new_commits.put(op)
        handle(limit=1)
        self.assertEqual(789, self.cursor.key.get().cursor)
