"""Unit tests for atproto.py."""
from base64 import b64encode
import copy
import random
from unittest import skip
from unittest.mock import patch

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import dag_cbor.decoding, dag_cbor.encoding
from granary import as2, bluesky
from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_PROFILE_BSKY,
    POST_AS,
    POST_BSKY,
    REPLY_AS,
    REPLY_BSKY,
    REPOST_AS,
    REPOST_BSKY,
)
from multiformats import CID
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW

import atproto
from atproto_mst import dag_cbor_cid
from flask_app import app
from models import Follower, Object, User
from . import testutil

# # atproto_mst.Data entry for MST with POST_AS, REPLY_AS, and REPOST_AS
# POST_CID = 'bafyreic5xwex7jxqvliumozkoli3qy2hzxrmui6odl7ujrcybqaypacfiy'
# REPLY_CID = 'bafyreib55ro37wasiflouvlfenhzllorcthm7flr2nj4fnk7yjo54cagvm'
# REPOST_CID = 'bafyreiek3jnp6e4sussy4c7pwtbkkf3kepekzycylowwuepmnvq7aeng44'
# ACTOR_CID = dag_cbor_cid(ACTOR_PROFILE_BSKY)
# HEAD_CID = 'bafyreiagk7qmor3gckkm6dts7c32frtnyn4reznclojgjraqwoumecenx4'
# HEAD_CID_EMPTY = 'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm'
# REPO_ENTRIES = {
#     'l': CID.decode(HEAD_CID),
#     'e': [{
#         'k': b'app.bsky.feed.feedViewPost/baxkjoxgdgnaqbbi',
#         'v': CID.decode(POST_CID),
#         'p': 0,
#         't': None,
#     }, {
#         'k': b'babbi',
#         'v': CID.decode(REPLY_CID),
#         'p': 38,
#         't': None,
#     }, {
#         'k': b'qbbi',
#         'v': CID.decode(REPOST_CID),
#         'p': 39,
#         't': None,
#     }],
# }


class AtProtoTest(testutil.TestCase):

    def setUp(self):
        super().setUp()

        atproto._clockid = 17  # need this to be deterministic

        # used in now(), injected into Object.created so that TIDs are deterministic
        self.last_now = NOW.replace(tzinfo=None)

    def now(self):
        self.last_now = self.last_now.replace(microsecond=self.last_now.microsecond + 1)
        return self.last_now

    def test_datetime_to_tid(self):
        self.assertEqual('3iom4o4g6u2l2', atproto.datetime_to_tid(NOW))

    def test_tid_to_datetime(self):
        self.assertEqual(NOW, atproto.tid_to_datetime('3iom4o4g6u2l2'))

    @patch('models.Object.created._now')
    def make_objects(self, mock_now):
        mock_now.side_effect = self.now

        with app.test_request_context('/'):
            Object(id='a', domains=['user.com'], labels=['user'], as2=POST_AS).put()
            Object(id='b', domains=['user.com'], labels=['user'], our_as1=REPLY_AS).put()
            Object(id='c', domains=['user.com'], labels=['user'], our_as1=REPOST_AS).put()
            # not outbound from user
            Object(id='d', domains=['user.com'], labels=['feed'], our_as1=POST_AS).put()
            # other user's
            Object(id='f', domains=['bar.org'], labels=['user'], our_as1=POST_AS).put()

    @skip
    def test_get_blocks_empty(self):
        self.make_user('user.com')

        resp = self.client.get('/xrpc/com.atproto.sync.getBlocks', query_string={
            'did': 'did:web:user.com',
            'cids': [],
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual([], dag_cbor.decoding.decode(resp.get_data()))

    @skip
    def test_get_blocks(self):
        self.make_user('user.com')
        self.make_objects()

        resp = self.client.get('/xrpc/com.atproto.sync.getBlocks', query_string={
            'did': 'did:web:user.com',
            'cids': [REPLY_CID, REPOST_CID],
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual([REPLY_BSKY, REPOST_BSKY],
                         dag_cbor.decoding.decode(resp.get_data()))

    def test_get_blocks_error_not_did_web(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getBlocks', query_string={
            'did': 'did:plc:foo',
            'cids': [],
        })
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    def test_get_blocks_error_no_domain_in_did(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getBlocks', query_string={
            'did': 'did:web:',
            'cids': [],
        })
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    def test_get_blocks_error_no_user(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getBlocks', query_string={
            'did': 'did:web:nope.com',
            'cids': [],
        })
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    # def test_get_checkout(self):


    # def test_get_commit_path(self):


    @skip
    def test_get_head_empty(self):
        self.make_user('user.com')

        resp = self.client.get('/xrpc/com.atproto.sync.getHead', query_string={
            'did': 'did:web:user.com',
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual({'root': HEAD_CID_EMPTY}, resp.json)

    @skip
    def test_get_head(self):
        self.make_user('user.com')
        self.make_objects()

        resp = self.client.get('/xrpc/com.atproto.sync.getHead', query_string={
            'did': 'did:web:user.com',
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual({'root': HEAD_CID}, resp.json)

        # alone: bafyreidk5xw2dqskokvhioznjhnha5am4nstrrmd2in7w7bmbuzpwnxlhq
        # with test_get_repo: bafyreif754hxy2df3hkhzqbwccvd53imxex35zrx4gou3dvjql6mavxo6a

    # def test_get_record(self):

    @skip
    def test_get_repo_empty_user(self):
        self.make_user('user.com')

        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:user.com'})
        self.assertEqual(200, resp.status_code)

    def test_get_repo_profile(self):
        user = self.make_user('user.com', actor_as2=as2.from_as1(ACTOR_AS))

        mst = {
            'e': [{
                'k': b'app.bsky.actor.profile/self',
                'v': dag_cbor_cid(ACTOR_PROFILE_BSKY),
                'p': 0,
                't': None,
            }],
            'l': CID.decode('bafyreiceqwd3lxb3u5pqe5qjp6v7cq7jxinbspknekibbpm4bfv54fedoe'),
        }
        commit = {
            'version': 2,
            'did': 'did:web:user.com',
            'data': dag_cbor_cid(mst),
            'prev': None,
        }

        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:user.com'})
        self.assertEqual(200, resp.status_code)
        got = dag_cbor.decoding.decode(resp.get_data())

        # extract and verify signature
        sig = got[2].pop('sig')
        key = ECC.import_key(user.p256_key)
        verifier = DSS.new(key.public_key(), 'fips-186-3', randfunc=random.randbytes)
        verifier.verify(SHA256.new(dag_cbor.encoding.encode(commit)), sig)

        self.assertEqual([
            ACTOR_PROFILE_BSKY,
            mst,
            commit,
        ], got)

    @skip
    def test_get_repo(self):
        self.make_user('user.com')
        self.make_objects()

        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:user.com'})
        self.assertEqual(200, resp.status_code)

        decoded = dag_cbor.decoding.decode(resp.get_data())
        self.assertEqual(REPO_ENTRIES, decoded)

    @skip
    def test_get_repo_latest_earliest(self):
        self.make_user('user.com')
        self.make_objects()

        resp = self.client.get('/xrpc/com.atproto.sync.getRepo', query_string={
            'did': 'did:web:user.com',
            'latest': REPO_ENTRIES['e'][1]['v'].encode('base32'),
            'earliest': REPO_ENTRIES['e'][0]['v'].encode('base32'),
        })
        self.assertEqual(200, resp.status_code)

        decoded = dag_cbor.decoding.decode(resp.get_data())
        self.assertEqual({
            'l': CID.decode(
                'bafyreieohwgp723mmvfsrg3mxle3azuf2u5ly6h3azlslubalqh5thwrxq'),
            'e': [{
                'k': b'app.bsky.feed.feedViewPost/baxkjoxgdgnbabce',
                'v': CID.decode(
                    'bafyreib55ro37wasiflouvlfenhzllorcthm7flr2nj4fnk7yjo54cagvm'),
                'p': 0,
                't': None,
            }],
        }, decoded)

    def test_get_repo_error_not_did_web(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:plc:foo'})
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    def test_get_repo_error_no_domain_in_did(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:'})
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    def test_get_repo_error_no_user(self):
        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:nope.com'})
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    # def test_list_blobs(self):

    def test_list_repos_empty(self):
        resp = self.client.get('/xrpc/com.atproto.sync.listRepos')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'repos': []}, resp.json)

    @skip
    def test_list_repos(self):
        self.make_user('user.com')
        self.make_objects()
        self.make_user('other.com')

        resp = self.client.get('/xrpc/com.atproto.sync.listRepos')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'repos': [{
            'did': 'did:web:other.com',
            'head': HEAD_CID_EMPTY,
        }, {
            'did': 'did:web:user.com',
            'head': HEAD_CID,
        }]}, resp.json)

    #     # /Users/ryan/src/atproto/packages/pds/tests/sync/list.test.ts

    # def test_notify_of_update(self):


    # def test_request_crawl(self):


    # def test_subscribe_repos(self):
