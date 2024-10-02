"""Unit tests for atproto_firehose.py."""
import copy
from datetime import datetime, timedelta, timezone, UTC
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
from atproto_firehose import commits, handle, Op, STORE_CURSOR_FREQ
import common
from models import Object, Target
import protocol
from .testutil import TestCase
from .test_atproto import DID_DOC
from web import Web

A_CID = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')


def setup_firehose():
    simple_websocket.Client = FakeWebsocketClient
    FakeWebsocketClient.sent = []
    FakeWebsocketClient.to_receive = []

    assert commits.empty()

    atproto_firehose.cursor = None
    atproto_firehose.atproto_dids = set()
    atproto_firehose.atproto_loaded_at = datetime(1900, 1, 1)
    atproto_firehose.bridged_dids = set()
    atproto_firehose.bridged_loaded_at = datetime(1900, 1, 1)
    atproto_firehose.protocol_bot_dids = set()
    atproto_firehose.dids_initialized.clear()

    cursor = Cursor(id='bgs.local com.atproto.sync.subscribeRepos')
    cursor.put()
    return cursor


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


class ATProtoTestCase(TestCase):
    """Utilities used by both test classes."""
    def make_bridged_atproto_user(self, did='did:plc:user'):
        self.store_object(id=did, raw=DID_DOC)
        return self.make_user(did, cls=ATProto, enabled_protocols=['eefake'],
                              obj_bsky=ACTOR_PROFILE_BSKY)


class ATProtoFirehoseSubscribeTest(ATProtoTestCase):
    def setUp(self):
        super().setUp()

        self.cursor = setup_firehose()
        self.user = self.make_bridged_atproto_user()
        AtpRepo(id='did:alice', head='', signing_key_pem=b'').put()
        self.store_object(id='did:plc:bob', raw=DID_DOC)
        ATProto(id='did:plc:bob').put()

    @classmethod
    def subscribe(self):
        atproto_firehose.load_dids()
        atproto_firehose.subscribe()

    def assert_enqueues(self, record=None, repo='did:plc:user', action='create',
                        path='app.bsky.feed.post/abc123'):
        FakeWebsocketClient.setup_receive(
            Op(repo=repo, action=action, path=path, seq=789, record=record))
        self.subscribe()

        op = commits.get()
        self.assertEqual(repo, op.repo)
        self.assertEqual(action, op.action)
        self.assertEqual(path, op.path)
        self.assertEqual(789, op.seq)
        self.assertEqual(record, op.record)
        self.assertTrue(commits.empty())

    def assert_doesnt_enqueue(self, record=None, repo='did:plc:user', action='create',
                              path='app.bsky.feed.post/abc123'):
        FakeWebsocketClient.setup_receive(
            Op(repo=repo, action=action, path=path, seq=789, record=record))
        self.subscribe()
        self.assertTrue(commits.empty())

    def test_error_message(self):
        FakeWebsocketClient.to_receive = [(
            {'op': -1},
            {'error': 'ConsumerTooSlow', 'message': 'ketchup!'},
        )]

        self.subscribe()
        self.assertTrue(commits.empty())

    def test_info_message(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#info'},
            {'name': 'OutdatedCursor'},
        )]

        self.subscribe()
        self.assertTrue(commits.empty())

    def test_cursor(self):
        self.cursor.cursor = 444
        self.cursor.put()

        self.subscribe()
        self.assertTrue(commits.empty())
        self.assertEqual(
            'https://bgs.local/xrpc/com.atproto.sync.subscribeRepos?cursor=445',
            FakeWebsocketClient.url)

    def test_non_commit(self):
        FakeWebsocketClient.to_receive = [(
            {'op': 1, 't': '#handle'},
            {'seq': '123', 'did': 'did:abc', 'handle': 'hi.com'},
        )]

        self.subscribe()
        self.assertTrue(commits.empty())
        self.assertEqual('https://bgs.local/xrpc/com.atproto.sync.subscribeRepos',
                         FakeWebsocketClient.url)

    def test_post_by_our_atproto_user(self):
        self.assert_enqueues(POST_BSKY)

    def test_post_by_other(self):
        self.assert_doesnt_enqueue(POST_BSKY, repo='did:plc:bob')

    def test_skip_post_by_bridged_user(self):
        # reply to bridged user, but also from bridged user, so we should skip
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'parent': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
                'root': {'uri': '-'},
            },
        }, repo='did:alice')

    def test_like_by_our_atproto_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })

    def test_like_by_our_atproto_user_of_non_bridged_user(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:eve/app.bsky.feed.post/tid'},
        })

    def test_skip_unsupported_type(self):
        self.assert_doesnt_enqueue({
            '$type': 'app.bsky.nopey.nope',
        }, repo='did:plc:user')

    def test_reply_direct_to_atproto_user(self):
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'parent': {
                    'uri': 'at://did:alice/app.bsky.feed.post/tid',
                    # test that we handle CIDs
                    'cid': A_CID.encode(),
                },
            },
        })

    def test_reply_direct_to_bridged_user(self):
        self.make_bridged_atproto_user('did:web:carol.com')
        self.assert_enqueues({
            '$type': 'app.bsky.feed.post',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'parent': {
                    'uri': 'at://did:web:carol.com/app.bsky.feed.post/tid',
                    'cid': A_CID.encode(),
                },
            },
        })

    def test_reply_indirect_to_our_user(self):
        self.assert_doesnt_enqueue({
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

    def test_follow_of_protocol_bot_account_by_unbridged_user(self):
        self.user.enabled_protocols = []
        self.user.put()

        self.make_user('fa.brid.gy', cls=Web, enabled_protocols=['atproto'],
                       copies=[Target(protocol='atproto', uri='did:fa')])
        AtpRepo(id='did:fa', head='', signing_key_pem=b'').put()

        self.assert_enqueues({
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:fa',
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
        path = 'app.bsky.feed.post/abc123'
        self.assert_enqueues(path=path, action='delete')

    def test_delete_by_other(self):
        self.assert_doesnt_enqueue(action='delete', repo='did:plc:carol')

    def test_update_by_our_atproto_user(self):
        self.assert_enqueues(action='update', record=POST_BSKY)

    def test_update_by_other(self):
        self.assert_doesnt_enqueue(action='update', repo='did:plc:carol',
                                   record=POST_BSKY)

    def test_update_like_of_our_user(self):
        self.assert_enqueues(action='update', record={
            '$type': 'app.bsky.feed.like',
            'subject': {'uri': 'at://did:alice/app.bsky.feed.post/tid'},
        })

    def test_uncaught_exception_skips_commit(self):
        self.cursor.cursor = 1
        self.cursor.put()

        FakeWebsocketClient.setup_receive(Op(repo='did:plc:user', action='create',
                                             path='y', seq=4, record={'foo': 'bar'}))
        with patch('libipld.decode_car', side_effect=RuntimeError('oops')), \
              self.assertRaises(RuntimeError):
            self.subscribe()

        self.assertTrue(commits.empty())
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

    def test_load_dids_updated_atproto_user(self):
        self.cursor.cursor = 1
        self.cursor.put()

        self.store_object(id='did:plc:eve', raw=DID_DOC)
        eve = self.make_user('did:plc:eve', cls=ATProto)
        util.now = lambda: datetime.now(UTC).replace(tzinfo=None)
        self.assertLess(eve.created, util.now())

        self.subscribe()
        self.assertTrue(commits.empty())
        self.assertNotIn('did:plc:eve', atproto_firehose.atproto_dids)

        # updating a previously created ATProto should be enough to load it into
        # atproto_dids
        eve.enabled_protocols = ['eefake']
        eve.put()
        self.assertGreater(eve.updated, atproto_firehose.atproto_loaded_at)

        self.assert_enqueues({'$type': 'app.bsky.feed.post'}, repo='did:plc:eve')
        self.assertIn('did:plc:eve', atproto_firehose.atproto_dids)

    def test_load_dids_atprepo(self):
        FakeWebsocketClient.to_receive = [({'op': 1, 't': '#info'}, {})]
        self.subscribe()

        # new AtpRepo should be loaded into bridged_dids
        AtpRepo(id='did:plc:eve', head='', signing_key_pem=b'').put()
        self.assert_enqueues({
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:eve',
        })
        self.assertIn('did:plc:eve', atproto_firehose.bridged_dids)

    def test_load_dids_tombstoned_atprepo(self):
        FakeWebsocketClient.to_receive = [({'op': 1, 't': '#info'}, {})]

        AtpRepo(id='did:plc:eve', head='', signing_key_pem=b'',
                status=arroba.util.TOMBSTONED).put()

        self.subscribe()

        # tombstoned AtpRepo shouldn't be loaded into bridged_dids
        self.assertNotIn('did:plc:eve', atproto_firehose.bridged_dids)

    def test_store_cursor(self):
        now = None
        def _now(tz=None):
            assert tz is None
            nonlocal now
            return now

        util.now = _now

        self.cursor.cursor = 444
        self.cursor.put()

        op = Op(repo='did:x', action='create', path='y', seq=789, record={'a': 'b'})
        # hasn't quite been long enough to store new cursor
        now = (self.cursor.updated.replace(tzinfo=timezone.utc)
               + STORE_CURSOR_FREQ - timedelta(seconds=1))
        FakeWebsocketClient.setup_receive(op)
        self.subscribe()
        self.assertEqual(444, self.cursor.key.get().cursor)

        # now it's been long enough
        now = (self.cursor.updated.replace(tzinfo=timezone.utc)
               + STORE_CURSOR_FREQ + timedelta(seconds=1))
        FakeWebsocketClient.setup_receive(op)
        self.subscribe()
        self.assertEqual(790, self.cursor.key.get().cursor)


@patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
class ATProtoFirehoseHandleTest(ATProtoTestCase):
    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

        self.make_bridged_atproto_user()
        atproto_firehose.atproto_dids = None
        atproto_firehose.bridged_dids = None
        atproto_firehose.dids_initialized.clear()

    def test_create(self, mock_create_task):
        reply = copy.deepcopy(REPLY_BSKY)
        # test that we handle actual CIDs
        reply['reply']['root']['cid'] = \
            reply['reply']['parent']['cid'] = A_CID.encode()

        commits.put(Op(repo='did:plc:user', action='create', seq=789,
                       path='app.bsky.feed.post/123', record=reply))

        handle(limit=1)

        user_key = ATProto(id='did:plc:user').key
        self.assert_task(mock_create_task, 'receive',
                         id='at://did:plc:user/app.bsky.feed.post/123',
                         bsky=reply, source_protocol='atproto',
                         authed_as='did:plc:user')

    def test_delete_post(self, mock_create_task):
        commits.put(Op(repo='did:plc:user', action='delete', seq=789,
                       path='app.bsky.feed.post/123'))
        handle(limit=1)

        obj_id = 'at://did:plc:user/app.bsky.feed.post/123'
        delete_id = f'{obj_id}#delete'
        user_key = ATProto(id='did:plc:user').key
        expected_as1 = {
            'objectType': 'activity',
            'verb': 'delete',
            'id': delete_id,
            'actor': 'did:plc:user',
            'object': obj_id,
        }
        self.assert_task(mock_create_task, 'receive', id=delete_id,
                         our_as1=expected_as1, source_protocol='atproto',
                         authed_as='did:plc:user')

    def test_delete_block_is_undo(self, mock_create_task):
        commits.put(Op(repo='did:plc:user', action='delete', seq=789,
                       path='app.bsky.graph.block/123'))
        handle(limit=1)

        obj_id = 'at://did:plc:user/app.bsky.graph.block/123'
        undo_id = f'{obj_id}#undo'
        user_key = ATProto(id='did:plc:user').key

        expected_as1 = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': undo_id,
            'actor': 'did:plc:user',
            'object': obj_id,
        }
        self.assert_task(mock_create_task, 'receive', id=undo_id,
                         our_as1=expected_as1, source_protocol='atproto',
                         authed_as='did:plc:user')

    def test_unsupported_type(self, mock_create_task):
        orig_objs = Object.query().count()

        commits.put(Op(repo='did:plc:user', action='update', seq=789,
                       path='app.bsky.graph.listitem/123', record={
                           '$type': 'app.bsky.graph.listitem',
                           'subject': 'did:bob',
                           'list': 'at://did:alice/app.bsky.graph.list/456',
                           'a_cid': A_CID,  # check that we encode this ok
                       }))
        handle(limit=1)

        self.assertEqual(orig_objs, Object.query().count())
        mock_create_task.assert_not_called()

    def test_delete_unsupported_type_no_record(self, mock_create_task):
        orig_objs = Object.query().count()

        commits.put(Op(repo='did:plc:user', action='delete', seq=789,
                       path='app.bsky.graph.listitem/123', record=None))
        handle(limit=1)

        self.assertEqual(orig_objs, Object.query().count())
        mock_create_task.assert_not_called()

    def test_missing_type(self, mock_create_task):
        orig_objs = Object.query().count()

        commits.put(Op(repo='did:plc:user', action='delete', seq=789,
                       path='app.bsky.graph.listitem/123', record={'foo': 'bar'}))
        handle(limit=1)

        self.assertEqual(orig_objs, Object.query().count())
        mock_create_task.assert_not_called()

    @patch.object(common.error_reporting_client, 'report_exception')
    @patch.object(Object, 'get_or_create', side_effect=RuntimeError('oops'))
    @patch('common.DEBUG', new=False)  # with DEBUG True, report_error just raises
    def test_exception_continues(self, mock_create_task, _, __):
        commits.put(Op(repo='did:plc:user', action='create', seq=789,
                       path='app.bsky.feed.post/123', record=REPLY_BSKY))
        handle(limit=1)
        # just check that we return instead of raising
