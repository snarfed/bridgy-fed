"""Unit tests for atproto.py."""
import base64
import copy
from unittest import skip
from unittest.mock import ANY, call, MagicMock, patch

from arroba.datastore_storage import AtpBlock, AtpRemoteBlob, AtpRepo, DatastoreStorage
from arroba.did import encode_did_key
from arroba.repo import Repo, Write
from arroba.storage import Action, SUBSCRIBE_REPOS_NSID
import arroba.util
from dns.resolver import NXDOMAIN
import google.cloud.dns.client
from google.cloud.dns.zone import ManagedZone
from google.cloud.tasks_v2.types import Task
from granary.bluesky import NO_AUTHENTICATED_LABEL
from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_PROFILE_BSKY,
    POST_AS,
)
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import NOW, NOW_SECONDS, requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads, trim_nulls
from requests.exceptions import HTTPError
from werkzeug.exceptions import BadRequest

import atproto
from atproto import (
    ATProto,
    DatastoreClient,
    DNS_GCP_PROJECT,
    DNS_ZONE,
)
import common
from models import Follower, Object, PROTOCOLS, Target
import protocol
from .testutil import ATPROTO_KEY, Fake, TestCase
from . import test_activitypub
from web import Web


DID_DOC = {
    'id': 'did:plc:user',
    'alsoKnownAs': ['at://ha.nl'],
    'verificationMethod': [{
        'id': 'did:plc:user#atproto',
        'type': 'Multikey',
        'controller': 'did:plc:user',
        'publicKeyMultibase': 'did:key:xyz',
    }],
    'service': [{
        'id': '#atproto_pds',
        'type': 'AtprotoPersonalDataServer',
        'serviceEndpoint': 'https://some.pds',
    }],
}
BLOB_CID = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')

NOTE_AS = {
    'objectType': 'note',
    'id': 'fake:post',
    'content': 'My original post',
    'author': 'fake:user',
    'published': '2007-07-07T03:04:05.000Z',
}
NOTE_BSKY = {
  '$type': 'app.bsky.feed.post',
  'text': 'My original post',
  'bridgyOriginalText': 'My original post',
  'bridgyOriginalUrl': 'fake:post',
  'createdAt': '2007-07-07T03:04:05.000Z',
}


@patch('ids.COPIES_PROTOCOLS', ['atproto'])
class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()
        self.storage = DatastoreStorage()
        common.RUN_TASKS_INLINE = False
        arroba.util.now = lambda **kwargs: NOW

    def make_user_and_repo(self, cls=Fake, id='fake:user', **kwargs):
        atp_copy = Target(uri='did:plc:user', protocol='atproto')
        self.user = self.make_user(id=id, cls=cls, copies=[atp_copy], **kwargs)

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = ATProto.PDS_URL
        self.store_object(id='did:plc:user', raw=did_doc)
        self.repo = Repo.create(self.storage, 'did:plc:user', handle='han.dull',
                                signing_key=ATPROTO_KEY)

        return self.user

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_put_validates_id(self, mock_get):
        for bad in (
            '',
            'not a did',
            'https://not.a/did',
            'at://not.a/did',
            'did:other:foo',
            'did:web:foo',  # not a domain
            'did:web:fed.brid.gy',
            'did:web:foo.ap.brid.gy',
            'did:plc:'  # blank
        ):
            with self.assertRaises(AssertionError):
                ATProto(id=bad).put()

        ATProto(id='did:web:foo.com').put()
        ATProto(id='did:plc:user').put()

    def test_handle(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('ha.nl', ATProto(id='did:plc:user').handle)

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_get_or_create(self, _):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('ha.nl', user.key.get().handle)

    def test_owns_id(self):
        self.assertFalse(ATProto.owns_id('http://foo'))
        self.assertFalse(ATProto.owns_id('https://bar.baz/biff'))
        self.assertFalse(ATProto.owns_id('e45fab982'))

        self.assertTrue(ATProto.owns_id('at://did:plc:user/bar/123'))
        self.assertTrue(ATProto.owns_id('did:plc:user'))
        self.assertTrue(ATProto.owns_id('did:web:bar.com'))
        self.assertTrue(ATProto.owns_id(
            'https://bsky.app/profile/snarfed.org/post/3k62u4ht77f2z'))

    def test_owns_handle(self):
        self.assertIsNone(ATProto.owns_handle('foo.com'))
        self.assertIsNone(ATProto.owns_handle('foo.bar.com'))

        self.assertFalse(ATProto.owns_handle('foo'))
        self.assertFalse(ATProto.owns_handle('@foo'))
        self.assertFalse(ATProto.owns_handle('@foo.com'))
        self.assertFalse(ATProto.owns_handle('@foo@bar.com'))
        self.assertFalse(ATProto.owns_handle('foo@bar.com'))
        self.assertFalse(ATProto.owns_handle('localhost'))

        self.assertFalse(ATProto.owns_handle('_foo.com'))
        self.assertFalse(ATProto.owns_handle('-foo.com'))
        self.assertFalse(ATProto.owns_handle('foo_.com'))
        self.assertFalse(ATProto.owns_handle('foo-.com'))

        # TODO: this should be False
        self.assertIsNone(ATProto.owns_handle('web.brid.gy'))

    def test_handle_to_id(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('did:plc:user', ATProto.handle_to_id('ha.nl'))

    def test_handle_to_id_bad(self):
        for bad in None, '', '.bsky.social':
            with self.subTest(bad=bad):
                self.assertIsNone(ATProto.handle_to_id(bad))

    def test_handle_to_id_first_opted_out(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto)

        self.store_object(id='did:plc:other', raw=DID_DOC)
        other = self.make_user('did:plc:other', cls=ATProto, manual_opt_out=True)

        # check that the datastore query returns other first, so that we have to
        # skip it
        self.assertEqual([other, user],
                         ATProto.query(ATProto.handle == 'ha.nl').fetch())

        self.assertEqual('did:plc:user', ATProto.handle_to_id('ha.nl'))

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    # resolving handle, HTTPS method, not found
    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_to_id_not_found(self, *_):
        self.assertIsNone(ATProto.handle_to_id('ha.nl'))

    def test_bridged_web_url_for(self):
        self.assertIsNone(ATProto.bridged_web_url_for(ATProto(id='did:plc:foo')))

        fake = Fake(id='fake:user')
        self.assertIsNone(ATProto.bridged_web_url_for(fake))

        fake.copies = [Target(uri='did:plc:user', protocol='atproto')]
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('https://bsky.app/profile/ha.nl',
                         ATProto.bridged_web_url_for(fake))

    def test_pds_for_did_no_doc(self):
        self.assertIsNone(ATProto.pds_for(Object(id='did:plc:user')))

    def test_pds_for_stored_did(self):
        obj = self.store_object(id='did:plc:user', raw=DID_DOC)
        got = ATProto.pds_for(obj)
        self.assertEqual('https://some.pds', got)

    def test_pds_for_record_stored_did(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        got = ATProto.pds_for(Object(id='at://did:plc:user/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    def test_pds_for_bsky_record_stored_did(self):
        # check that we don't use Object.as1, which would cause an infinite loop
        self.assertIsNone(ATProto.pds_for(Object(id='at://did:bo:b/co.l.l/post', bsky={
            '$type': 'app.bsky.feed.post',
            'uri': 'at://did:bo:b/co.l.l/post',
            'cid': 'my++sidd',
        })))

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_pds_for_fetch_did(self, mock_get):
        got = ATProto.pds_for(Object(id='at://did:plc:user/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    def test_pds_for_user_with_stored_did(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('fake:user', cls=Fake,
                       copies=[Target(uri='did:plc:user', protocol='atproto')])
        got = ATProto.pds_for(Object(id='fake:post', our_as1=NOTE_AS))
        self.assertEqual('https://some.pds', got)

    def test_pds_for_user_no_stored_did(self):
        self.make_user('fake:user', cls=Fake)
        self.assertIsNone(ATProto.pds_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })))

    def test_pds_for_bsky_app_url_did_stored(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('fake:user', cls=Fake,
                       copies=[Target(uri='did:plc:user', protocol='atproto')])

        got = ATProto.pds_for(Object(
            id='https://bsky.app/profile/did:plc:user/post/123'))
        self.assertEqual('https://some.pds', got)

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    @patch('requests.get', side_effect=[
        # resolving handle, HTTPS method
        requests_response('did:plc:user', content_type='text/plain'),
        # fetching DID doc
        requests_response(DID_DOC),
    ])
    def test_pds_for_bsky_app_url_resolve_handle(self, mock_get, _):
        got = ATProto.pds_for(Object(
            id='https://bsky.app/profile/baz.com/post/123'))
        self.assertEqual('https://some.pds', got)

        mock_get.assert_has_calls((
            self.req('https://baz.com/.well-known/atproto-did'),
            self.req('https://plc.local/did:plc:user'),
        ))

    def test_no_authenticated_label_opt_out(self):
        # !no-authenticated label is for users who disable logged out visibility,
        # ie only show their profile to users who are logged into Bluesky
        self.store_object(id='did:plc:user', raw=DID_DOC)
        obj = self.store_object(id='at://did:plc:user/app.bsky.actor.profile/self',
                                bsky={
                                    **ACTOR_PROFILE_BSKY,
                                    'labels': {
                                        'values': [{
                                            'val' : NO_AUTHENTICATED_LABEL,
                                            'neg' : False,
                                        }],
                                    },
                                })
        user = self.make_user('did:plc:user', cls=ATProto, obj_key=obj.key)

        self.assertEqual('opt-out', user.status)

    def test_target_for_user_no_stored_did(self):
        self.assertEqual('https://atproto.brid.gy', ATProto.target_for(
            Object(id='at://foo')))
        self.assertIsNone(ATProto.target_for(Object(id='fake:post')))

    @patch('requests.get', return_value=requests_response({'foo': 'bar'}))
    def test_fetch_did_plc(self, mock_get):
        obj = Object(id='did:plc:123')
        self.assertTrue(ATProto.fetch(obj))
        self.assertEqual({'foo': 'bar'}, obj.raw)

        mock_get.assert_has_calls((
            self.req('https://plc.local/did:plc:123'),
        ))

    @patch('requests.get', return_value=requests_response({'foo': 'bar'}))
    def test_fetch_did_web(self, mock_get):
        obj = Object(id='did:web:user.com')
        self.assertTrue(ATProto.fetch(obj))
        self.assertEqual({'foo': 'bar'}, obj.raw)

        mock_get.assert_has_calls((
            self.req('https://user.com/.well-known/did.json'),
        ))

    @patch('requests.get', return_value=requests_response('not json'))
    def test_fetch_did_plc_not_json(self, mock_get):
        obj = Object(id='did:web:user.com')
        self.assertFalse(ATProto.fetch(obj))
        self.assertIsNone(obj.raw)

    @patch('requests.get', return_value=requests_response({
        'uri': 'at://did:plc:abc/app.bsky.feed.post/123',
        'cid': 'bafyreigd',
        'value': {'foo': 'bar'},
    }))
    def test_fetch_at_uri_record(self, mock_get):
        obj = Object(id='at://did:plc:abc/app.bsky.feed.post/123')
        self.assertTrue(ATProto.fetch(obj))
        self.assertEqual({
            'foo': 'bar',
            'cid': 'bafyreigd',
        }, obj.bsky)
        # eg https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        mock_get.assert_called_once_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc&collection=app.bsky.feed.post&rkey=123',
            json=None, data=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            },
        )

    @patch('requests.get', return_value=requests_response({
        'error':'InvalidRequest',
        'message':'Could not locate record: at://did:plc:abc/app.bsky.feed.post/123',
    }, status=400))
    def test_fetch_at_uri_record_error(self, mock_get):
        obj = Object(id='at://did:plc:abc/app.bsky.feed.post/123')
        self.assertFalse(ATProto.fetch(obj))
        mock_get.assert_called_once_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc&collection=app.bsky.feed.post&rkey=123',
            json=None, data=None, headers=ANY)

    def test_fetch_bsky_app_url_fails(self):
        for uri in ('https://bsky.app/profile/ha.nl',
                    'https://bsky.app/profile/ha.nl/post/789'):
            with self.assertRaises(AssertionError):
                ATProto.fetch(Object(id=uri))

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    @patch('requests.get', return_value=requests_response(status=404))
    def test_fetch_resolve_handle_fails(self, mock_get, _):
        obj = Object(id='at://bad.com/app.bsky.feed.post/789')
        self.assertFalse(ATProto.fetch(obj))

    def test_load_did_doc(self):
        obj = self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assert_entities_equal(obj, ATProto.load('did:plc:user', did_doc=True))

    def test_load_did_doc_false_loads_profile(self):
        did_doc = self.store_object(id='did:plc:user', raw=DID_DOC)
        profile = self.store_object(id='at://did:plc:user/app.bsky.actor.profile/self',
                                    bsky=ACTOR_PROFILE_BSKY)
        self.assert_entities_equal(profile, ATProto.load('did:plc:user'))

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    @patch('requests.get', side_effect=[
        # resolving handle, HTTPS method
        requests_response('did:plc:user', content_type='text/plain'),
        # AppView getRecord
        requests_response({
            'uri': 'at://did:plc:user/app.bsky.actor.profile/self',
            'cid': 'bafyreigd',
            'value': {'$type': 'app.bsky.actor.profile', 'bar': 'baz'},
        }),
        # fetching DID doc
        requests_response(DID_DOC),
    ])
    def test_load_bsky_app_post_url(self, mock_get, _):
        obj = ATProto.load('https://bsky.app/profile/ha.nl/post/789')
        self.assertEqual('at://did:plc:user/app.bsky.feed.post/789', obj.key.id())
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'bar': 'baz',
            'cid': 'bafyreigd',
        }, obj.bsky)

        mock_get.assert_any_call(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Auser&collection=app.bsky.feed.post&rkey=789',
            json=None, data=None, headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            })
        self.assert_req(mock_get, 'https://plc.local/did:plc:user')

    @patch('requests.get', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.actor.profile/self',
        'cid': 'bafyreigd',
        'value': {'$type': 'app.bsky.actor.profile', 'bar': 'baz'},
    }))
    def test_load_bsky_profile_url(self, mock_get):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('did:plc:user', cls=ATProto)

        obj = ATProto.load('https://bsky.app/profile/ha.nl')
        self.assertEqual('at://did:plc:user/app.bsky.actor.profile/self', obj.key.id())
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'bar': 'baz',
            'cid': 'bafyreigd',
        }, obj.bsky)

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Auser&collection=app.bsky.actor.profile&rkey=self',
            json=None, data=None, headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            },
        )

    def test_convert_bsky_pass_through(self):
        self.store_object(id='did:plc:alice', raw=DID_DOC)
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'foo': 'bar',
        }, ATProto.convert(Object(id='at://did:plc:alice', bsky={
            '$type': 'app.bsky.actor.profile',
            'foo': 'bar',
        })))

    def test_convert_populate_cid(self):
        self.store_object(id='did:plc:bob', raw={
            **DID_DOC,
            'id': 'did:plc:bob',
        })
        post = self.store_object(id='at://did:plc:bob/app.bsky.feed.post/tid', bsky={
            '$type': 'app.bsky.feed.post',
            'cid': 'my++sidd',
        })

        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                'cid': 'my++sidd',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

        self.assertEqual({
            '$type': 'app.bsky.feed.repost',
            'subject': {
                'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                'cid': 'my++sidd',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'object': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

        # reply
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
            'bridgyOriginalText': 'foo',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                    'cid': 'my++sidd',
                },
                'parent': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                    'cid': 'my++sidd',
                },
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'comment',
            'content': 'foo',
            'inReplyTo': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

        # reply to reply
        post.bsky['reply'] = {
            'parent': {
                'cid': 'parent sidd',
                'uri': 'at://did:plc:bob/app.bsky.feed.post/parent-tid',
            },
            'root': {
                'cid': 'root+sidd',
                'uri': 'at://did:plc:bob/app.bsky.feed.post/root-tid',
            },
        }
        post.put()

        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
            'bridgyOriginalText': 'foo',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/root-tid',
                    'cid': 'root+sidd',
                },
                'parent': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                    'cid': 'my++sidd',
                },
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'comment',
            'content': 'foo',
            'inReplyTo': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    @patch('requests.get', side_effect=[
        # appview resolveHandle
        requests_response({'did': 'did:plc:user'}),
        # AppView getRecord
        requests_response({
            'uri': 'at://did:plc:user/app.bsky.feed.post/tid',
            'cid': 'my++sidd',
            'value': {
                '$type': 'app.bsky.feed.post',
                'text': 'foo',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }),
    ])
    def test_convert_populate_cid_fetch_remote_record_handle(self, mock_get, _):
        self.store_object(id='did:plc:user', raw=DID_DOC)

        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:user/app.bsky.feed.post/tid',
                'cid': 'my++sidd',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'like',
            # handle here should be replaced with DID in returned record's URI
            'object': 'at://ha.nl/app.bsky.feed.post/tid',
        })))
        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Auser&collection=app.bsky.feed.post&rkey=tid',
            json=None, data=None, headers=ANY)

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    # appview resolveHandle
    @patch('requests.get', return_value=requests_response(status=404))
    def test_convert_populate_cid_fetch_remote_record_bad_handle(self, _, __):
        # skips getRecord because handle didn't resolve
        self.assertEqual({}, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'at://bob.net/app.bsky.feed.post/tid',
        })))

    def test_convert_generate_cid(self):
        # existing Object with post but missing cid
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.store_object(id='at://did:plc:user/app.bsky.feed.post/tid', bsky={
            '$type': 'app.bsky.feed.post',
            'cid': '',
        })

        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:user/app.bsky.feed.post/tid',
                'cid': 'bafyreibxlmh4wviq5pgc2mllp7zjkjnnp3vhmjvh5r3qpyaonnoh2ylusm',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'at://did:plc:user/app.bsky.feed.post/tid',
        })))

    def test_convert_fetch_blobs_false(self):
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed'}],
            },
            'bridgyOriginalUrl': 'did:web:alice.com',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }), fetch_blobs=False))

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='image/png'))
    def test_convert_fetch_blobs_true(self, mock_get):
        cid = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'avatar': {
                '$type': 'blob',
                'ref': cid,
                'mimeType': 'image/png',
                'size': 13,
            },
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed'}],
            },
            'bridgyOriginalUrl': 'did:web:alice.com',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }), fetch_blobs=True))

        mock_get.assert_has_calls([self.req('http://my/pic')])

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='video/mp4'))
    def test_convert_fetch_blobs_true_video(self, mock_get):
        cid = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': 'foo bar',
            'embed': {
                '$type': 'app.bsky.embed.video',
                'video': {
                    '$type': 'blob',
                    'mimeType': 'video/mp4',
                    'ref': cid,
                    'size': 13,
                },
                'alt': 'my alt',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
            'bridgyOriginalText': 'foo bar',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'note',
            'content': 'foo bar',
            'attachments': [{
                'objectType': 'video',
                'stream': {'url': 'https://my/vid'},
                'mimeType': 'video/mp4',
                'displayName': 'my alt',
            }],
        }), fetch_blobs=True))

        mock_get.assert_has_calls([self.req('https://my/vid')])

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='video/mp4', headers={
            'Content-Length': str(atproto.appview.defs['app.bsky.embed.video']['properties']['video']['maxSize'] + 1),
        }))
    def test_convert_fetch_blobs_true_video_over_maxSize(self, mock_get):
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': 'foo bar',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'bridgyOriginalText': 'foo bar',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'note',
            'content': 'foo bar',
            'attachments': [{
                'objectType': 'video',
                'stream': {'url': 'https://my/vid'},
                'mimeType': 'video/mp4',
                'displayName': 'my alt',
            }],
        }), fetch_blobs=True))

        mock_get.assert_has_calls([self.req('https://my/vid')])

    @patch('requests.get', side_effect=[
        requests_response(status=404),
        requests_response('second blob contents', content_type='image/png')
    ])
    def test_convert_fetch_blobs_true_image_fetch_fails_then_succeeds(self, mock_get):
        cid = CID.decode('bafkreigapis7qpqslq2njkxnn6lgbrnf75byeilrt52ufhpr3uz2vrugfe')
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': '',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'embed': {
                '$type': 'app.bsky.embed.images',
                'images': [{
                    '$type': 'app.bsky.embed.images#image',
                    'alt': '',
                    'image': {
                        '$type': 'blob',
                        'mimeType': 'image/png',
                        'ref': cid,
                        'size': 20,
                    },
                }],
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'note',
            'image': [
                {'url': 'http://my/pic/1'},
                {'url': 'http://my/pic/2'},
            ],
        }), fetch_blobs=True))
        mock_get.assert_has_calls([self.req('http://my/pic/1'), self.req('http://my/pic/2')])

    def test_convert_fetch_blobs_true_existing_atp_remote_blob(self):
        cid = 'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq'
        AtpRemoteBlob(id='http://my/pic', cid=cid, size=8,
                      mime_type='image/png').put()

        self.assert_equals({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'avatar': {
                '$type': 'blob',
                'ref': CID.decode(cid),
                'mimeType': 'image/png',
                'size': 8,
            },
            'bridgyOriginalUrl': 'did:web:alice.com',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }), fetch_blobs=True), ignore=('labels',))

    # resolveHandle
    @patch('requests.get', return_value=requests_response({'did': 'did:plc:user'}))
    def test_convert_resolve_mention_handle(self, mock_get):
        self.store_object(id='did:plc:user', raw=DID_DOC)

        content = 'hi <a href="https://bsky.app/profile/ha.nl">@ha.nl</a> hows it going'
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'text': 'hi @ha.nl hows it going',
            'bridgyOriginalText': content,
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:plc:user',
                }],
                'index': {
                    'byteEnd': 9,
                    'byteStart': 3,
                },
            }],
        }, ATProto.convert(Object(our_as1={
            # this mention has the DID in url, and it will also be extracted
            # from the link in content. make sure we merge the two and don't end
            # up with a duplicate mention of the DID or a mention of the handle.
            'objectType': 'note',
            'content': content,
            'tags': [{
                'objectType': 'mention',
                'url': 'did:plc:user',
                'displayName': '@ha.nl'
            }],
        })))

    # resolveHandle
    @patch('requests.get', return_value=requests_response({'did': 'did:plc:user'}))
    def test_convert_resolve_mention_handle_drop_server(self, mock_get):
        self.store_object(id='did:plc:user', raw=DID_DOC)

        content = 'hi <a href="https://bsky.brid.gy/ap/did:plc:user">@<span>ha.nl</span></a> hows it going'
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'text': 'hi @ha.nl hows it going',
            'bridgyOriginalText': content,
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:plc:user',
                }],
                'index': {
                    'byteEnd': 9,
                    'byteStart': 3,
                },
            }],
        }, ATProto.convert(Object(our_as1={
            'objectType': 'comment',
            'content': content,
            'tags': [{
                'objectType': 'mention',
                'url': 'did:plc:user',
                # we should find the mentioned handle in the content text even
                # if it doesn't have @ser.ver
                # https://github.com/snarfed/bridgy-fed/issues/957
                'displayName': '@ha.nl@ser.ver'
            }],
        })))

    def test_convert_quote_post_translate_attachment_url_with_copy_id(self):
        self.make_user_and_repo()

        self.store_object(id='fake:orig-post', copies=[
            Target(protocol='atproto', uri='at://did:plc:user/co.l.l/tid'),
        ])
        self.repo.apply_writes([Write(action=Action.CREATE, collection='co.l.l',
                                      rkey='tid', record=NOTE_BSKY)])

        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': '',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'embed': {
                '$type': 'app.bsky.embed.record',
                'record': {
                    'uri': 'at://did:plc:user/co.l.l/tid',
                    'cid': 'bafyreiccskuaccxa6zbaf7jeaiwyzg3pqtj3rg5qra653f5cmqilvgvejy',
                },
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'note',
            'attachments': [{
                'objectType': 'note',
                'url': 'fake:orig-post',
            }],
        })))

    def test_convert_actor_from_atproto_doesnt_add_self_label(self):
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
        }, ATProto.convert(Object(source_protocol='atproto', our_as1={
            'objectType': 'person',
            'displayName': 'Alice',
        })))

    def test_convert_non_atproto_actor_adds_self_label(self):
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed-fake'}],
            },
            'bridgyOriginalUrl': 'fake:alice',
        }, ATProto.convert(Object(source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:alice',
            'displayName': 'Alice',
        })))

    def test_convert_non_atproto_actor_adds_source_links(self):
        user = self.make_user_and_repo()

        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': '[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed-fake'}],
            },
            'bridgyOriginalUrl': 'fake:user',
        }, ATProto.convert(Object(source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Alice',
        }), from_user=user))

    def test_convert_web_actor_source_links_link_to_user_page(self):
        user = self.make_user(id='user.com', cls=Web, obj_id='user.com')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': '[bridged from https://user.com/ on the web: https://fed.brid.gy/web/user.com ]',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed-web'}],
            },
            'bridgyOriginalUrl': 'user.com',
        }, ATProto.convert(Object(source_protocol='web', our_as1={
            'objectType': 'person',
            'id': 'user.com',
            'displayName': 'Alice',
        }), from_user=user))

    def test_convert_non_atproto_update_actor_truncates_before_source_links(self):
        user = self.make_user_and_repo()

        summary = """\
<p>Mauris laoreet dolor eu ligula vulputate aliquam.</p>
Aenean vel augue at ipsum vestibulum ultricies.<br>
Nam quis tristique elit.<br>
<br>
Sed tortor neque, aliquet quis posuere aliquam, imperdiet sitamet odio. In molestie, mi tincidunt maximus congue, sem risus comod."""

        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': """\
Mauris laoreet dolor eu ligula vulputate aliquam.

Aenean vel augue at ipsum vestibulum ultricies.
Nam quis tristique elit.

Sed tortor neque, aliquet quis posuere aliquam […] 

[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]""",
            'bridgyOriginalDescription': summary,
            'bridgyOriginalUrl': 'fake:user',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed-fake'}],
            },
        }, ATProto.convert(Object(source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Alice',
            # 255 chars when converted to plain text. the app.bsky.actor.profile
            # description limit is 256 graphemes.
            'summary': summary,
        }), from_user=user))

    def test_convert_non_atproto_actor_link_in_summary(self):
        user = self.make_user_and_repo()

        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'bar\n\n[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val': 'bridged-from-bridgy-fed-fake'}],
            },
            'bridgyOriginalDescription': '<a href="http://foo">bar</a>',
            'bridgyOriginalUrl': 'fake:user',
        }, ATProto.convert(Object(source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Alice',
            'summary': '<a href="http://foo">bar</a>',
        }), from_user=user))

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_web_url(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('https://bsky.app/profile/did:plc:user', user.web_url())

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('https://bsky.app/profile/ha.nl', user.web_url())

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_or_id(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertIsNone(user.handle)
        self.assertEqual('did:plc:user', user.handle_or_id())

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('ha.nl', user.handle)
        self.assertEqual('ha.nl', user.handle_or_id())

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_as(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)

        # TODO? or remove?
        # self.assertEqual('@did:plc:user@bsky.brid.gy',
        #                  user.handle_as('activitypub'))

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('@ha.nl@bsky.brid.gy', user.handle_as('activitypub'))

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_profile_id(self, mock_get):
        self.assertEqual('at://did:plc:user/app.bsky.actor.profile/self',
                         self.make_user('did:plc:user', cls=ATProto).profile_id())

    @patch('atproto.DEBUG', new=False)
    @patch.object(atproto.dns_discovery_api, 'resourceRecordSets')
    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post', return_value=requests_response('OK'))  # create DID on PLC
    def test_create_for(self, mock_post, mock_create_task, mock_zone, mock_rrsets):
        mock_zone.return_value = zone = MagicMock()
        zone.resource_record_set = MagicMock()

        mock_rrsets.return_value = rrsets = MagicMock()
        rrsets.list.return_value = list_ = MagicMock()
        list_.execute.return_value = {'rrsets': []}

        Fake.fetchable = {'fake:profile:us_er': ACTOR_AS}
        user = Fake(id='fake:us_er')
        AtpRemoteBlob(id='https://alice.com/alice.jpg', mime_type='image/png',
                      cid=BLOB_CID.encode('base32'), size=8).put()

        ATProto.create_for(user)

        # check user, repo
        did = user.key.get().get_copy(ATProto)
        self.assertEqual([Target(uri=did, protocol='atproto')], user.copies)
        repo = arroba.server.storage.load_repo(did)

        # check DNS record
        zone.resource_record_set.assert_called_with(
            name='_atproto.fake-handle-us-er.fa.brid.gy.', record_type='TXT',
            ttl=atproto.DNS_TTL, rrdatas=[f'"did={did}"'])

        # check profile and chat declaration records
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there\n\n[bridged from web:fake:us_er on fake-phrase by https://fed.brid.gy/ ]',
            'bridgyOriginalDescription': 'hi there',
            'bridgyOriginalUrl': 'https://alice.com/',
            'avatar': {
                '$type': 'blob',
                'mimeType': 'image/png',
                'ref': BLOB_CID,
                'size': 8,
            },
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val' : 'bridged-from-bridgy-fed-fake'}],
            },
        }, repo.get_record('app.bsky.actor.profile', 'self'))

        self.assertEqual({
            "$type" : "chat.bsky.actor.declaration",
            "allowIncoming" : "none"
        }, repo.get_record('chat.bsky.actor.declaration', 'self'))

        uri = arroba.util.at_uri(did, 'app.bsky.actor.profile', 'self')
        self.assertEqual([Target(uri=uri, protocol='atproto')],
                         Object.get_by_id(id='fake:profile:us_er').copies)

        mock_create_task.assert_called()  # atproto-commit

    def test_create_for_bad_handle(self):
        # underscores gets translated to dashes, trailing/leading aren't allowed
        for bad in 'fake:user_', '_fake:user':
            with self.assertRaises(ValueError):
                ATProto.create_for(Fake(id=bad))

    @patch('atproto.DEBUG', new=False)
    @patch.object(google.cloud.dns.client.ManagedZone, 'changes')
    @patch.object(atproto.dns_discovery_api, 'resourceRecordSets')
    def test_set_dns_new(self, mock_rrsets, mock_changes):
        mock_changes.return_value = changes = MagicMock()
        mock_rrsets.return_value = rrsets = MagicMock()
        rrsets.list.return_value = list_ = MagicMock()
        list_.execute.return_value = {  # no existing record
            'rrsets': [],
            'kind': 'dns#resourceRecordSetsListResponse',
        }

        ATProto.set_dns('han.dull.fa.brid.gy', 'did:foo')

        # the call to see if this record already exists
        name = '_atproto.han.dull.fa.brid.gy.'
        rrsets.list.assert_called_with(
            project=DNS_GCP_PROJECT, managedZone=DNS_ZONE, type='TXT', name=name)

        # the changeset: add, no delete
        changes.delete_record_set.assert_not_called()
        changes.add_record_set.assert_called_once()
        rrset = changes.add_record_set.call_args[0][0]
        self.assertEqual(DNS_ZONE, rrset.zone.name)
        self.assertEqual(name, rrset.name)
        self.assertEqual('TXT', rrset.record_type)
        self.assertEqual(atproto.DNS_TTL, rrset.ttl)
        self.assertEqual(['"did=did:foo"'], rrset.rrdatas)

    @patch('atproto.DEBUG', new=False)
    @patch.object(google.cloud.dns.client.ManagedZone, 'changes')
    @patch.object(atproto.dns_discovery_api, 'resourceRecordSets')
    def test_set_dns_existing(self, mock_rrsets, mock_changes):
        name = '_atproto.han.dull.fa.brid.gy.'

        mock_changes.return_value = changes = MagicMock()
        mock_rrsets.return_value = rrsets = MagicMock()
        rrsets.list.return_value = list_ = MagicMock()
        list_.execute.return_value = {  # existing record
            'rrsets': [{
                'name': name,
                'type': 'TXT',
                'ttl': 300,
                'rrdatas': ['"did=did:abc:xyz"'],
                'kind': 'dns#resourceRecordSet',
            }],
            'kind': 'dns#resourceRecordSetsListResponse',
        }

        ATProto.set_dns('han.dull.fa.brid.gy', 'did:foo')

        # the call to see if this record already exists
        rrsets.list.assert_called_with(
            project=DNS_GCP_PROJECT, managedZone=DNS_ZONE, type='TXT', name=name)

        # the changeset: delete and add
        changes.delete_record_set.assert_called_once()
        rrset = changes.delete_record_set.call_args[0][0]
        self.assertEqual(DNS_ZONE, rrset.zone.name)
        self.assertEqual(name, rrset.name)
        self.assertEqual('TXT', rrset.record_type)
        self.assertEqual(300, rrset.ttl)
        self.assertEqual(['"did=did:abc:xyz"'], rrset.rrdatas)

        changes.add_record_set.assert_called_once()
        rrset = changes.add_record_set.call_args[0][0]
        self.assertEqual(DNS_ZONE, rrset.zone.name)
        self.assertEqual(name, rrset.name)
        self.assertEqual('TXT', rrset.record_type)
        self.assertEqual(atproto.DNS_TTL, rrset.ttl)
        self.assertEqual(['"did=did:foo"'], rrset.rrdatas)

    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post', return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo(self, mock_post, mock_create_task, _):
        user = self.make_user(id='fake:user', cls=Fake, enabled_protocols=['atproto'])
        obj = self.store_object(id='fake:post', source_protocol='fake',
                                our_as1=NOTE_AS)

        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy/'))

        # check DID doc
        user = user.key.get()
        did = user.get_copy(ATProto)
        assert did
        self.assertEqual([Target(uri=did, protocol='atproto')], user.copies)
        did_obj = ATProto.load(did, did_doc=True)
        self.assertEqual('http://localhost',
                         did_obj.raw['service'][0]['serviceEndpoint'])

        # check repo, record
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(NOTE_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        # check PLC directory call to create did:plc
        self.assertEqual((f'https://plc.local/{did}',), mock_post.call_args.args)
        genesis_op = mock_post.call_args.kwargs['json']
        self.assertEqual(did, genesis_op.pop('did'))
        genesis_op['sig'] = base64.urlsafe_b64decode(
            genesis_op['sig'] + '=' * (4 - len(genesis_op['sig']) % 4))  # padding
        assert arroba.util.verify_sig(genesis_op, repo.rotation_key.public_key())

        del genesis_op['sig']
        self.assertEqual({
                'type': 'plc_operation',
                'verificationMethods': {
                    'atproto': encode_did_key(repo.signing_key.public_key()),
                },
                'rotationKeys': [encode_did_key(repo.rotation_key.public_key())],
                'alsoKnownAs': [
                    'at://fake-handle-user.fa.brid.gy',
                ],
                'services': {
                    'atproto_pds': {
                        'type': 'AtprotoPersonalDataServer',
                        'endpoint': 'http://localhost',
                    }
                },
                'prev': None,
            }, genesis_op)

        # check atproto-commit task
        self.assertEqual(2, mock_create_task.call_count)
        self.assert_task(mock_create_task, 'atproto-commit')

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='image/png'))  # image blob fetch
    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post', return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo_includes_user_profile(self, mock_post, mock_create_task,
                                                 _, __):
        user = self.make_user(id='fake:user', cls=Fake, enabled_protocols=['atproto'],
                              obj_as1={})
        Fake.fetchable = {'fake:profile:user': ACTOR_AS}

        obj = self.store_object(id='fake:post', source_protocol='fake',
                                our_as1=NOTE_AS)
        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy/'))

        # check profile, record
        user = Fake.get_by_id('fake:user')
        did = user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there\n\n[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]',
            'bridgyOriginalDescription': 'hi there',
            'bridgyOriginalUrl': 'https://alice.com/',
            'avatar': {
                '$type': 'blob',
                'ref': BLOB_CID,
                'mimeType': 'image/png',
                'size': 13,
            },
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val' : 'bridged-from-bridgy-fed-fake'}],
            },
        }, profile)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(NOTE_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_note_existing_repo(self, mock_create_task):
        user = self.make_user_and_repo()
        obj = self.store_object(id='fake:post', source_protocol='fake',
                                our_as1=NOTE_AS)
        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy'))

        # check repo, record
        did = user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(NOTE_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_update_note(self, mock_create_task):
        self.test_send_note_existing_repo()
        mock_create_task.reset_mock()

        note = Object.get_by_id('fake:post')
        note.our_as1['content'] = 'something new'
        note.put()

        update = self.store_object(id='fake:update', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'object': note.our_as1,
        })
        self.assertTrue(ATProto.send(update, 'https://bsky.brid.gy'))

        # check repo, record
        did = self.user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual('something new', record['text'])

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_update_actor(self, mock_create_task):
        user = self.make_user_and_repo(obj_as1={'objectType': 'person', 'foo': 'bar'})

        # create profile object, set copy
        self.repo.apply_writes([
            Write(action=Action.CREATE, collection='app.bsky.actor.profile',
                  rkey='self', record=ACTOR_PROFILE_BSKY)])
        user.obj.copies = [Target(uri='at://did:plc:user/app.bsky.actor.profile/self',
                                  protocol='atproto')]
        user.obj.put()

        # update profile
        update = Object(id='fake:update', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': {
                'objectType': 'person',
                'id': 'fake:profile:user',
                'updated': '2024-06-24T01:02:03+00:00',
                'displayName': 'fooey',
            },
        })
        self.assertTrue(ATProto.send(update, 'https://bsky.brid.gy/', from_user=user))

        repo = self.storage.load_repo('did:plc:user')
        self.assert_equals({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'fooey',
            'description': '[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]',
        }, repo.get_record('app.bsky.actor.profile', 'self'),
        ignore=['bridgyOriginalUrl', 'labels'])

        mock_create_task.assert_called()  # atproto-commit

    def test_send_update_doesnt_exist(self):
        self.test_send_note_existing_repo()
        user = self.make_user_and_repo()

        update = Object(id='fake:update', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': {
                'id': 'fake:post',
                'foo': 'bar',
            },
        })
        self.assertFalse(ATProto.send(update, 'https://bsky.brid.gy'))

    def test_send_update_wrong_repo(self):
        self.test_send_note_existing_repo()

        orig = Object.get_by_id('fake:post')
        _, _, rkey = arroba.util.parse_at_uri(orig.copies[0].uri)
        orig.copies[0].uri = orig.copies[0].uri.replace('did:plc:user', 'did:plc:eve')
        orig.put()

        update = self.store_object(id='fake:update', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'object': {
                **NOTE_AS,
                'content': 'nope',
            },
        })
        self.assertFalse(ATProto.send(update, 'https://bsky.brid.gy'))

        # check repo, record
        did = self.user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        record = repo.get_record('app.bsky.feed.post', rkey)
        self.assertEqual(orig.as1['content'], record['text'])

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_delete_note(self, mock_create_task):
        self.test_send_note_existing_repo()
        mock_create_task.reset_mock()

        delete = self.store_object(id='fake:delete', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        })
        self.assertTrue(ATProto.send(delete, 'https://bsky.brid.gy/'))

        # check repo, record
        did = self.user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        self.assertIsNone(repo.get_record('app.bsky.feed.post', last_tid))

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task')
    def test_send_delete_no_original(self, mock_create_task):
        self.make_user_and_repo()

        obj = Object(id='fake:delete', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        })
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
        mock_create_task.assert_not_called()  # atproto-commit

    def test_send_delete_already_deleted(self):
        self.test_send_delete_note()

        delete = Object(id='fake:delete', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        })
        self.assertFalse(ATProto.send(delete, 'https://bsky.brid.gy/'))

    @patch.object(tasks_client, 'create_task')
    def test_send_delete_original_no_copy(self, mock_create_task):
        self.make_user_and_repo()
        obj = self.store_object(id='fake:post', source_protocol='fake',
                                our_as1=NOTE_AS)

        obj = Object(id='fake:delete', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        })
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
        mock_create_task.assert_not_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_like(self, mock_create_task):
        user = self.make_user_and_repo()
        self.store_object(id='did:plc:bob', raw={
            **DID_DOC,
            'id': 'did:plc:bob',
        })

        post_obj = self.store_object(id='at://did:plc:bob/app.bsky.feed.post/tid',
                                     source_protocol='atproto', bsky={
            '$type': 'app.bsky.feed.post',
            'cid': 'bafy+CID',
        })

        like_obj = self.store_object(id='fake:like', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'id': 'fake:like',
            'actor': 'fake:user',
            'object': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })
        self.assertTrue(ATProto.send(like_obj, 'https://bsky.brid.gy/'))

        # check repo, record
        did = user.get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.like', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                'cid': 'bafy+CID',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, record)

        at_uri = f'at://{did}/app.bsky.feed.like/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:like').copies)

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_undo_like(self, mock_create_task):
        self.test_send_like()
        mock_create_task.reset_mock()

        undo = self.store_object(id='fake:undo', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': Object.get_by_id('fake:like').as1,
        })
        self.assertTrue(ATProto.send(undo, 'https://bsky.brid.gy/'))

        # check repo, record
        did = self.user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        self.assertIsNone(repo.get_record('app.bsky.feed.post', last_tid))

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.get', return_value=requests_response({
        'uri': 'at://did:bo:b/app.bsky.feed.post/tid',
        'cid': 'my++sidd',
        'value': {
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
            'createdAt': '2022-01-02T03:04:05.000Z',
        },
    }))
    def test_send_repost(self, mock_get, mock_create_task):
        user = self.make_user_and_repo()
        obj = self.store_object(id='fake:repost', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:repost',
            'actor': 'fake:user',
            'object': 'at://did:bo:b/app.bsky.feed.post/tid',
        })
        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy'))

        # check repo, record
        did = user.get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.repost', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.repost',
            'subject': {
                'uri': 'at://did:bo:b/app.bsky.feed.post/tid',
                'cid': 'my++sidd',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, record)

        at_uri = f'at://{did}/app.bsky.feed.repost/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:repost').copies)

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Abo%3Ab&collection=app.bsky.feed.post&rkey=tid',
            json=None, data=None, headers=ANY)
        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_undo_repost(self, mock_create_task):
        self.test_send_repost()
        mock_create_task.reset_mock()

        undo = self.store_object(id='fake:undo', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': Object.get_by_id('fake:repost').as1,
        })
        self.assertTrue(ATProto.send(undo, 'https://bsky.brid.gy/'))

        # check repo, record
        did = self.user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        self.assertIsNone(repo.get_record('app.bsky.feed.post', last_tid))

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_follow(self, mock_create_task):
        user = self.make_user_and_repo()
        obj = self.store_object(id='fake:follow', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'fake:follow',
            'actor': 'fake:user',
            'object': 'did:plc:bob',
        })
        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy'))

        # check repo, record
        did = user.get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.graph.follow', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:bob',
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, record)

        at_uri = f'at://{did}/app.bsky.graph.follow/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:follow').copies)

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_unfollow(self, mock_create_task):
        user = self.make_user_and_repo()
        self.store_object(id='did:plc:bob', raw={
            **DID_DOC,
            'id': 'did:plc:bob',
        })
        bob = self.make_user('did:plc:bob', cls=ATProto)

        # store follow objects and Follower
        self.repo.apply_writes([Write(
            action=Action.CREATE,
            collection='app.bsky.graph.follow',
            rkey='123',
            record={
                '$type': 'app.bsky.graph.follow',
                'subject': 'did:plc:bob',
                'createdAt': '2022-01-02T03:04:05.000Z',
            })])
        self.assertIsNotNone(self.repo.get_record('app.bsky.graph.follow', '123'))

        copy = Target(uri='at://did:plc:user/app.bsky.graph.follow/123',
                      protocol='atproto')
        follow = self.store_object(id='fake:follow', source_protocol='fake',
                                   copies=[copy],
                                   our_as1={
                                       'objectType': 'activity',
                                       'verb': 'follow',
                                       'id': 'fake:follow',
                                       'actor': 'fake:user',
                                       'object': 'did:plc:bob',
                                   })
        follower = Follower.get_or_create(from_=user, to=bob, status='active',
                                          follow=follow.key)

        # send stop-following
        obj = Object(id='fake:unfollow', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'stop-following',
            'id': 'fake:unfollow',
            'actor': 'fake:user',
            'object': 'did:plc:bob',
        })
        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy', from_user=self.user))

        # follow record should be deleted, Follower deactivated
        repo = self.storage.load_repo('did:plc:user')
        self.assertIsNone(repo.get_record('app.bsky.graph.follow', '123'))
        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task')
    def test_send_not_our_repo(self, mock_create_task):
        self.assertFalse(ATProto.send(Object(id='fake:post'), 'http://other.pds/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_did_doc_not_our_repo(self, mock_create_task):
        self.store_object(id='did:plc:user', raw=DID_DOC)  # uses https://some.pds
        user = self.make_user(id='fake:user', cls=Fake,
                              copies=[Target(uri='did:plc:user', protocol='atproto')])
        obj = self.store_object(id='fake:post', source_protocol='fake',
                                our_as1=NOTE_AS)
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    @patch.object(ATProto, '_convert', return_value={})
    def test_send_skips_bad_convert(self, _, mock_create_task):
        self.make_user_and_repo()

        obj = Object(id='fake:bad', source_protocol='fake', our_as1={
            'actor': 'fake:user',
            'foo': 'bar',
        })
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_skips_question(self, mock_create_task):
        question = {
            'type': 'Question',
            'id': 'fake:q',
            'inReplyTo': 'user.com',
        }

        for input in (question, {'type': 'Update', 'object': question}):
            with self.subTest(input=input):
                obj = Object(id='fake:q', source_protocol='fake', as2=input)
                self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
                self.assertEqual(0, AtpBlock.query().count())
                self.assertEqual(0, AtpRepo.query().count())
                mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_skips_add_to_collection(self, mock_create_task):
        obj = Object(id='fake:add', source_protocol='fake', as2={
            'type': 'Add',
            'object': 'did:bo:b',
            'target': 'at://did:bo:b/li.s.t/foo',
        })
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_delete_actor(self, mock_create_task):
        user = self.make_user_and_repo()

        delete = self.store_object(id='fake:delete', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:user',
        })
        self.assertTrue(ATProto.send(delete, 'https://bsky.brid.gy/',
                                     from_user=user))

        did = self.user.key.get().get_copy(ATProto)
        with self.assertRaises(arroba.util.TombstonedRepo):
            self.storage.load_repo(did)

        seq = self.storage.last_seq(SUBSCRIBE_REPOS_NSID)
        self.assertEqual({
            '$type': 'com.atproto.sync.subscribeRepos#tombstone',
            'seq': seq,
            'did': did,
            'time': NOW.isoformat(),
        }, next(self.storage.read_events_by_seq(seq)))

        mock_create_task.assert_called()  # atproto-commit

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_from_deleted_actor(self, mock_create_task):
        self.make_user_and_repo()
        self.storage.tombstone_repo(self.repo)

        obj = Object(id='fake:post', source_protocol='fake', our_as1=NOTE_AS)
        self.assertFalse(ATProto.send(obj, 'https://bsky.brid.gy'))

        self.assertEqual({}, self.repo.get_contents()['app.bsky.feed.post'])
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_translates_ids(self, mock_create_task):
        user = self.make_user_and_repo()
        alice = self.make_user(id='fake:alice', cls=Fake,
                               copies=[Target(uri='did:al:ice', protocol='atproto')])
        self.store_object(id='at://did:bo:b/co.l.l/post', bsky={
            '$type': 'app.bsky.feed.post',
            'uri': 'at://did:bo:b/co.l.l/post',
            'cid': 'my++sidd',
        })
        self.store_object(
            id='fake:post', source_protocol='fake',
            copies=[Target(uri='at://did:bo:b/co.l.l/post', protocol='atproto')])

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:user',
            'content': 'foo',
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:alice',
            }, {
                'objectType': 'mention',
                'url': 'fake:bob',  # no ATProto user, should be dropped
            }],
        }
        reply = self.store_object(id='fake:reply', source_protocol='fake',
                                  our_as1=reply_as1)

        create_as1 = {
            'objectType': 'activity',
            'verb': 'post',
            'object': reply_as1,
        }
        create = self.store_object(id='fake:reply:post', source_protocol='fake',
                                   our_as1=create_as1)

        self.assertTrue(ATProto.send(create, 'https://bsky.brid.gy/'))

        repo = self.storage.load_repo(user.get_copy(ATProto))
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'text': 'foo',
            'bridgyOriginalText': 'foo',
            'bridgyOriginalUrl': 'fake:reply',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {
                    'uri': 'at://did:bo:b/co.l.l/post',
                    'cid': 'my++sidd',
                },
                'parent': {
                    'uri': 'at://did:bo:b/co.l.l/post',
                    'cid': 'my++sidd',
                },
            },
        }, record)

        at_uri = f'at://did:plc:user/app.bsky.feed.post/{last_tid}'
        self.assertEqual([], Object.get_by_id(id='fake:reply:post').copies)
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:reply').copies)

        mock_create_task.assert_called()  # atproto-commit

    # createReport
    @patch('requests.post', return_value=requests_response({
        'id': 3,
        'reasonType': 'com.atproto.moderation.defs#reasonSpam',
        'reason': '',
        'subject': {
            '$type': 'com.atproto.admin.defs#repoRef',
            'did': 'did:plc:eve',
        },
        'reportedBy': 'did:plc:bob',
        'createdAt': NOW.isoformat(),
    }))
    # did:plc:eve
    @patch('requests.get', return_value=requests_response({
            **DID_DOC,
            'id': 'did:plc:eve',
        }))
    def test_send_flag_createReport(self, _, mock_post):
        user = self.make_user_and_repo()

        uri = 'at://did:plc:eve/app.bsky.feed.post/123'
        obj = self.store_object(id='fake:flag', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'flag',
            'actor': 'fake:user',
            'object': uri,
            'content': 'foo bar',
        })
        self.store_object(id=uri, source_protocol='bsky', bsky={
            '$type': 'app.bsky.feed.post',
            'cid': 'bafyreigd',
        })

        self.assertTrue(ATProto.send(obj, 'https://bsky.brid.gy/'))

        repo = self.storage.load_repo(user.get_copy(ATProto))
        self.assertEqual({}, repo.get_contents())

        mock_post.assert_called_with(
            'https://mod.service.local/xrpc/com.atproto.moderation.createReport',
            json={
                '$type': 'com.atproto.moderation.createReport#input',
                'reasonType': 'com.atproto.moderation.defs#reasonOther',
                'reason': 'foo bar',
                'subject': {
                    '$type': 'com.atproto.repo.strongRef',
                    'uri': uri,
                    'cid': 'bafyreigd',
                },
            }, data=None, headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
                'Authorization': ANY,
            })

    @patch('requests.post', return_value=requests_response({  # sendMessage
        'id': 'chat456',
        'rev': '22222222tef2d',
        'sender': {'did': 'did:plc:user'},
        'text': 'hello world',
    }))
    @patch('requests.get', side_effect=[
        requests_response({  # getConvoForMembers
            'convo': {
                'id': 'convo123',
                'rev': '22222222fuozt',
                'members': [{
                    'did': 'did:plc:alice',
                    'handle': 'alice.bsky.social',
                }, {
                    'did': 'did:plc:user',
                    'handle': 'han.dull',
                }],
                'muted': False,
                'unreadCount': 0,
            },
        }),
        requests_response(DID_DOC),
    ])
    def test_send_dm_chat(self, mock_get, mock_post):
        user = self.make_user_and_repo()

        dm = Object(id='fake:dm', source_protocol='fake', our_as1={
            'objectType': 'note',
            'actor': user.key.id(),
            'content': 'hello world',
            'to': ['did:plc:alice'],
        })
        self.assertTrue(ATProto.send(dm, 'https://bsky.brid.gy/'))

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': common.USER_AGENT,
            'Authorization': ANY,
        }
        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getConvoForMembers?members=did%3Aplc%3Aalice',
            json=None, data=None, headers=headers)
        mock_post.assert_called_with(
            'https://chat.local/xrpc/chat.bsky.convo.sendMessage',
            json={
                'convoId': 'convo123',
                'message': {
                    '$type': 'chat.bsky.convo.defs#messageInput',
                    'text': 'hello world',
                    # unused
                    'createdAt': '2022-01-02T03:04:05.000Z',
                    'bridgyOriginalText': 'hello world',
                    'bridgyOriginalUrl': 'fake:dm',
                },
            }, data=None, headers=headers)

    # getConvoForMembers
    @patch('requests.get', return_value=requests_response({
        'error': 'InvalidRequest',
        'message': 'recipient has disabled incoming messages',
    }, status=400))
    def test_send_chat_recipient_disabled(self, mock_get):
        user = self.make_user_and_repo()

        dm = Object(id='fake:dm', source_protocol='fake', our_as1={
            'objectType': 'note',
            'actor': user.key.id(),
            'content': 'hello world',
            'to': ['did:plc:alice'],
        })
        self.assertFalse(ATProto.send(dm, 'https://bsky.brid.gy/'))

        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getConvoForMembers?members=did%3Aplc%3Aalice',
            json=None, data=None, headers=ANY)

    def test_datastore_client_get_record_datastore_object(self):
        self.make_user_and_repo()
        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
        }
        self.store_object(id='at://did:plc:user/co.l.l/post', bsky=post)

        client = DatastoreClient('https://appview.local')
        self.assertEqual({
            'uri': 'at://did:plc:user/co.l.l/post',
            'cid': 'bafyreigdjrzqmcj4i3zcj3fzcfgod52ty7lfvw57ienlu4yeet3dv6zdpy',
            'value': post,
        }, client.com.atproto.repo.getRecord(repo='did:plc:user',
                                             collection='co.l.l', rkey='post'))

    def test_datastore_client_get_record_datastore_repo(self):
        self.make_user_and_repo()
        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
            'createdAt': '2022-01-02T03:04:05.000Z',
        }
        self.repo.apply_writes([Write(action=Action.CREATE, collection='co.l.l',
                                      rkey='post', record=post)])

        client = DatastoreClient('https://appview.local')
        self.assertEqual({
            'uri': 'at://did:plc:user/co.l.l/post',
            'cid': 'bafyreiam6fisrctmj7uv6is5wkk4fqw6bxzlooepaapxntuv45j3mu34p4',
            'value': post,
        }, client.com.atproto.repo.getRecord(repo='did:plc:user',
                                             collection='co.l.l', rkey='post'))

    @patch('requests.get', return_value=requests_response({
        'uri': 'at://did:plc:user/co.l.l/tid',
        'cid': 'my++sidd',
        'value': {
            '$type': 'app.bsky.feed.post',
            'text': 'baz',
            'createdAt': NOW.isoformat(),
        },
    }))
    def test_datastore_client_get_record_pass_through(self, mock_get):
        self.make_user_and_repo()

        client = DatastoreClient('https://appview.local')
        self.assertEqual({
            'uri': 'at://did:plc:user/co.l.l/post',
            'cid': 'my++sidd',
            'value': {
                '$type': 'app.bsky.feed.post',
                'text': 'baz',
                'createdAt': NOW.isoformat(),
                'cid': 'my++sidd',
            },
        }, client.com.atproto.repo.getRecord(repo='did:plc:user',
                                             collection='co.l.l', rkey='post'))

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Auser&collection=co.l.l&rkey=post',
            json=None, data=None, headers=ANY)

    @patch('requests.get', side_effect=HTTPError(
        response=requests_response(status=500)))
    def test_datastore_client_get_record_pass_through_fails(self, mock_get):
        client = DatastoreClient('https://appview.local')
        self.assertEqual({}, client.com.atproto.repo.getRecord(
            repo='did:plc:user', collection='co.l.l', rkey='post'))

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Auser&collection=co.l.l&rkey=post',
            json=None, data=None, headers=ANY)

    def test_datastore_client_resolve_handle_datastore_user(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('did:plc:user', cls=ATProto)

        client = DatastoreClient('https://appview.local')
        self.assertEqual({'did': 'did:plc:user'},
                         client.com.atproto.identity.resolveHandle(handle='ha.nl'))

    def test_datastore_client_resolve_handle_datastore_repo(self):
        self.make_user_and_repo()

        client = DatastoreClient('https://appview.local')
        self.assertEqual({'did': 'did:plc:user'},
                         client.com.atproto.identity.resolveHandle(handle='han.dull'))

    @patch('requests.get', return_value=requests_response({'did': 'did:dy:d'}))
    def test_datastore_client_resolve_handle_pass_through(self, mock_get):
        client = DatastoreClient('https://appview.local')
        self.assertEqual({'did': 'did:dy:d'},
                         client.com.atproto.identity.resolveHandle(handle='han.dull'))

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.identity.resolveHandle?handle=han.dull',
            json=None, data=None, headers=ANY)

    @patch('requests.get')
    def test_datastore_client_other_call_pass_through(self, mock_get):
        output = {
            'handle': 'y.z',
            'did': 'did:y:z',
            'didDoc': '',
            'collections': [],
            'handleIsCorrect': True,
        }
        mock_get.return_value = requests_response(output)
        client = DatastoreClient('https://appview.local')
        self.assertEqual(output, client.com.atproto.repo.describeRepo(repo='y.z'))

        mock_get.assert_called_with(
            'https://appview.local/xrpc/com.atproto.repo.describeRepo?repo=y.z',
            json=None, data=None, headers=ANY)

    @patch.object(tasks_client, 'create_task')
    @patch('requests.get', side_effect=[
        requests_response({'logs': [], 'cursor': 'neckst'}),
    ])
    def test_poll_atproto_chat_empty(self, mock_get, mock_create_task):
        fa = self.make_user_and_repo(cls=Web, id='fa.brid.gy',
                                     atproto_last_chat_log_cursor='kursur')
        resp = self.get('/cron/atproto-poll-chat?proto=fake')
        self.assert_equals(200, resp.status_code)

        mock_get.assert_called_with(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=kursur',
            json=None, data=None, headers=ANY)
        self.assertEqual('neckst', fa.key.get().atproto_last_chat_log_cursor)
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    @patch('requests.get', side_effect=[
        requests_response({
            'cursor': 'neckst',
            'logs': [{
                '$type': 'chat.bsky.convo.defs#logBeginConvo',
                'convoId': 'abc',
                'rev': '123',
            }, {
                '$type': 'chat.bsky.convo.defs#logLeaveConvo',
                'convoId': 'def',
                'rev': '456',
            }, {
                '$type': 'chat.bsky.convo.defs#logDeleteMessage',
                'convoId': 'ghi',
                'message': {
                    '$type': 'chat.bsky.convo.defs#deletedMessageView',
                    'id': 'abc',
                    'rev': '000',
                    'sender': {'did': 'did:plc:user'},
                    'sentAt': NOW.isoformat(),
                },
                'rev': '789',
            }],
        }),
        requests_response({
            'cursor': 'dunn',
            'logs': [],
        }),
    ])
    def test_poll_atproto_chat_no_messages(self, mock_get, mock_create_task):
        fa = self.make_user_and_repo(cls=Web, id='fa.brid.gy',
                                     atproto_last_chat_log_cursor='kursur')
        resp = self.get('/cron/atproto-poll-chat?proto=fake')
        self.assert_equals(200, resp.status_code)

        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=kursur',
            json=None, data=None, headers=ANY)
        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=neckst',
            json=None, data=None, headers=ANY)
        self.assertEqual('dunn', fa.key.get().atproto_last_chat_log_cursor)
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    @patch('requests.get')
    def test_poll_atproto_chat_messages(self, mock_get, mock_create_task):
        msg_alice = {
            '$type': 'chat.bsky.convo.defs#messageView',
            'id': 'uvw',
            'text': 'foo bar',
            'sender': {'did': 'did:al:ice'},
            'rev': '123',
            'sentAt': NOW.isoformat(),
        }
        msg_bob = {
            '$type': 'chat.bsky.convo.defs#messageView',
            'id': 'xyz',
            'text': 'baz biff',
            'sender': {'did': 'did:bo:b'},
            'rev': '456',
            'sentAt': NOW.isoformat(),
        }
        msg_from_bot = {
            '$type': 'chat.bsky.convo.defs#messageView',
            'id': 'lmno',
            'text': 'beep boop this should not be received',
            'sender': {'did': 'did:plc:user'},
            'rev': '789',
            'sentAt': NOW.isoformat(),
        }
        msg_eve = {
            '$type': 'chat.bsky.convo.defs#messageView',
            'id': 'rst',
            'text': 'boff',
            'sender': {'did': 'did:ev:e'},
            'rev': '000',
            'sentAt': NOW.isoformat(),
        }

        mock_get.side_effect = [
            requests_response({
                'cursor': 'neckst',
                'logs': [{
                    '$type': 'chat.bsky.convo.defs#logCreateMessage',
                    'convoId': 'abc',
                    'message': msg_alice,
                    'rev': '123',
                }, {
                    '$type': 'chat.bsky.convo.defs#logCreateMessage',
                    'convoId': 'def',
                    'message': msg_bob,
                    'rev': '456',
                }],
                'cursor': 'neckst',
            }),
            requests_response({
                'cursor': 'moar',
                'logs': [{
                    '$type': 'chat.bsky.convo.defs#logCreateMessage',
                    'convoId': 'ghi',
                    'message': msg_from_bot,
                    'rev': '123',
                }, {
                    '$type': 'chat.bsky.convo.defs#logCreateMessage',
                    'convoId': 'jkl',
                    'message': msg_eve,
                    'rev': '456',
                }],
            }),
            requests_response({
                'cursor': 'dunn',
                'logs': [],
            }),
        ]

        fa = self.make_user_and_repo(cls=Web, id='fa.brid.gy',
                                     atproto_last_chat_log_cursor='kursur')
        resp = self.get('/cron/atproto-poll-chat?proto=fake')
        self.assert_equals(200, resp.status_code)

        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=kursur',
            json=None, data=None, headers=ANY)
        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=neckst',
            json=None, data=None, headers=ANY)
        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getLog?cursor=moar',
            json=None, data=None, headers=ANY)

        self.assertEqual(3, mock_create_task.call_count)

        id = 'at://did:al:ice/chat.bsky.convo.defs.messageView/uvw'
        self.assert_task(mock_create_task, 'receive', authed_as='did:al:ice',
                         obj=Object(id=id).key.urlsafe())
        self.assert_object(id, source_protocol='atproto', our_as1={
            'objectType': 'note',
            'id': 'at://did:al:ice/chat.bsky.convo.defs.messageView/uvw',
            'author': 'did:al:ice',
            'content': 'foo bar',
            'to': ['fa.brid.gy'],
            'published': NOW.isoformat(),
        })

        id = 'at://did:bo:b/chat.bsky.convo.defs.messageView/xyz'
        self.assert_task(mock_create_task, 'receive', authed_as='did:bo:b',
                         obj=Object(id=id).key.urlsafe())
        self.assert_object(id, source_protocol='atproto', our_as1={
            'objectType': 'note',
            'id': 'at://did:bo:b/chat.bsky.convo.defs.messageView/xyz',
            'author': 'did:bo:b',
            'content': 'baz biff',
            'to': ['fa.brid.gy'],
            'published': NOW.isoformat(),
        })

        id = 'at://did:plc:user/chat.bsky.convo.defs.messageView/lmno'
        self.assertIsNone(Object.get_by_id(id))

        id = 'at://did:ev:e/chat.bsky.convo.defs.messageView/rst'
        self.assert_task(mock_create_task, 'receive', authed_as='did:ev:e',
                         obj=Object(id=id).key.urlsafe())
        self.assert_object(id, source_protocol='atproto', our_as1={
            'objectType': 'note',
            'id': 'at://did:ev:e/chat.bsky.convo.defs.messageView/rst',
            'author': 'did:ev:e',
            'content': 'boff',
            'to': ['fa.brid.gy'],
            'published': NOW.isoformat(),
        })

        self.assertEqual('dunn', fa.key.get().atproto_last_chat_log_cursor)
