"""Unit tests for atproto.py."""
from unittest.mock import patch

import dag_cbor.decoding
from granary import as2, bluesky
from granary.tests.test_bluesky import (
    POST_BSKY,
    POST_AS,
    REPLY_BSKY,
    REPLY_AS,
    REPOST_BSKY,
    REPOST_AS,
)
from multiformats import CID, multibase
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW

from flask_app import app
from models import Object, User
from . import testutil


last_now = NOW.replace(tzinfo=None)

def next_now():
    global last_now
    last_now = last_now.replace(microsecond=last_now.microsecond + 1)
    return last_now


class AtProtoTest(testutil.TestCase):

    # def test_get_blob(input, ):


    # def test_get_blocks(self):


    # def test_get_checkout(self):


    # def test_get_commit_path(self):


    # def test_get_head(self):


    # def test_get_record(self):

    @patch('models.Object.created._now', side_effect=next_now)
    def test_get_repo(self, _):
        self.make_user('user.com')

        with app.test_request_context('/'):
            Object(id='a', domains=['user.com'], labels=['user'], as2=POST_AS).put()
            Object(id='b', domains=['user.com'], labels=['user'], our_as1=REPLY_AS).put()
            Object(id='c', domains=['user.com'], labels=['user'], our_as1=REPOST_AS).put()
            # not outbound from user
            Object(id='d', domains=['user.com'], labels=['feed'], our_as1=POST_AS).put()
            # other user's
            Object(id='f', domains=['bar.org'], labels=['user'], our_as1=POST_AS).put()

        resp = self.client.get('/xrpc/com.atproto.sync.getRepo',
                               query_string={'did': 'did:web:user.com'})
        self.assertEqual(200, resp.status_code)

        decoded = dag_cbor.decoding.decode(resp.get_data())
        self.assertEqual({
            'l': CID.decode(multibase.decode(
                'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm')),
            'e': [{
                'k': b'app.bsky.feed.feedViewPost/baxkjoxgdgnaqbbi',
                'v': CID.decode(multibase.decode(
                    'bafyreic5xwex7jxqvliumozkoli3qy2hzxrmui6odl7ujrcybqaypacfiy')),
                'p': 0,
                't': None,
            }, {
                'k': b'babbi',
                'v': CID.decode(multibase.decode(
                    'bafyreib55ro37wasiflouvlfenhzllorcthm7flr2nj4fnk7yjo54cagvm')),
                'p': 38,
                't': None,
            }, {
                'k': b'qbbi',
                'v': CID.decode(multibase.decode(
                    'bafyreiek3jnp6e4sussy4c7pwtbkkf3kepekzycylowwuepmnvq7aeng44')),
                'p': 39,
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

    # def test_list_repos(self):
    #     # /Users/ryan/src/atproto/packages/pds/tests/sync/list.test.ts

    # def test_notify_of_update(self):


    # def test_request_crawl(self):


    # def test_subscribe_repos(self):
