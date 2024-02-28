"""Unit tests for atproto.py."""
import base64
import copy
import logging
from unittest import skip
from unittest.mock import ANY, call, MagicMock, patch

from arroba.datastore_storage import AtpBlock, AtpRemoteBlob, AtpRepo, DatastoreStorage
from arroba.did import encode_did_key
from arroba.repo import Repo
import arroba.util
import dns.resolver
from dns.resolver import NXDOMAIN
from flask import g
from google.cloud.tasks_v2.types import Task
from granary.bluesky import NO_AUTHENTICATED_LABEL
from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_PROFILE_BSKY,
    POST_AS,
    POST_BSKY,
)
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads, trim_nulls
from werkzeug.exceptions import BadRequest

import atproto
from atproto import ATProto
import common
import hub
from models import Object, PROTOCOLS, Target
import protocol
from .testutil import ATPROTO_KEY, Fake, TestCase
from . import test_activitypub

DID_DOC = {
    'id': 'did:plc:user',
    'alsoKnownAs': ['at://han.dull'],
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


class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()
        self.storage = DatastoreStorage()
        common.RUN_TASKS_INLINE = False

    def make_user_and_repo(self):
        user = self.make_user(id='fake:user', cls=Fake,
                              copies=[Target(uri='did:plc:user', protocol='atproto')])

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = 'https://atproto.brid.gy/'
        self.store_object(id='did:plc:user', raw=did_doc)
        Repo.create(self.storage, 'did:plc:user', signing_key=ATPROTO_KEY)

        return user

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
        self.assertEqual('han.dull', ATProto(id='did:plc:user').handle)

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_get_or_create(self, _):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('han.dull', user.key.get().handle)

    def test_owns_id(self):
        self.assertEqual(False, ATProto.owns_id('http://foo'))
        self.assertEqual(False, ATProto.owns_id('https://bar.baz/biff'))
        self.assertEqual(False, ATProto.owns_id('e45fab982'))

        self.assertTrue(ATProto.owns_id('at://did:plc:user/bar/123'))
        self.assertTrue(ATProto.owns_id('did:plc:user'))
        self.assertTrue(ATProto.owns_id('did:web:bar.com'))
        self.assertTrue(ATProto.owns_id(
            'https://bsky.app/profile/snarfed.org/post/3k62u4ht77f2z'))

    def test_owns_handle(self):
        self.assertIsNone(ATProto.owns_handle('foo.com'))
        self.assertIsNone(ATProto.owns_handle('foo.bar.com'))

        self.assertEqual(False, ATProto.owns_handle('foo'))
        self.assertEqual(False, ATProto.owns_handle('@foo'))
        self.assertEqual(False, ATProto.owns_handle('@foo.com'))
        self.assertEqual(False, ATProto.owns_handle('@foo@bar.com'))
        self.assertEqual(False, ATProto.owns_handle('foo@bar.com'))
        self.assertEqual(False, ATProto.owns_handle('localhost'))
        # TODO: this should be False
        self.assertIsNone(ATProto.owns_handle('web.brid.gy'))

    def test_handle_to_id(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('did:plc:user', ATProto.handle_to_id('han.dull'))

    @patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    # resolving handle, HTTPS method, not found
    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_to_id_not_found(self, *_):
        self.assertIsNone(ATProto.handle_to_id('han.dull'))

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

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_pds_for_fetch_did(self, mock_get):
        got = ATProto.pds_for(Object(id='at://did:plc:user/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    def test_pds_for_user_with_stored_did(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user('fake:user', cls=Fake,
                       copies=[Target(uri='did:plc:user', protocol='atproto')])
        got = ATProto.pds_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        }))
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

    @patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
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
                                    'labels': [{
                                        'val' : NO_AUTHENTICATED_LABEL,
                                        'neg' : False,
                                    }],
                                })
        user = self.make_user('did:plc:user', cls=ATProto, obj_key=obj.key)

        self.assertEqual('opt-out', user.status)

    def test_target_for_user_no_stored_did(self):
        self.assertEqual('https://atproto.brid.gy/', ATProto.target_for(
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
        'cid': 'bafy...',
        'value': {'foo': 'bar'},
    }))
    def test_fetch_at_uri_record(self, mock_get):
        self.store_object(id='did:plc:abc', raw=DID_DOC)
        obj = Object(id='at://did:plc:abc/app.bsky.feed.post/123')
        self.assertTrue(ATProto.fetch(obj))
        self.assertEqual({
            'foo': 'bar',
            'cid': 'bafy...',
        }, obj.bsky)
        # eg https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        mock_get.assert_called_once_with(
            'https://some.pds/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc&collection=app.bsky.feed.post&rkey=123',
            json=None, data=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            },
        )

    def test_convert_bsky_pass_through(self):
        self.assertEqual({
            'foo': 'bar',
        }, ATProto.convert(Object(bsky={
            'foo': 'bar',
        })))

    def test_convert_populate_cid(self):
        self.store_object(id='did:plc:bob', raw={
            **DID_DOC,
            'id': 'did:plc:bob',
        })
        self.store_object(id='at://did:plc:bob/app.bsky.feed.post/tid', bsky={
            '$type': 'app.bsky.feed.post',
            'cid': 'my sidd',
        })

        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                'cid': 'my sidd',
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
                'cid': 'my sidd',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'object': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'text': 'foo',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                    'cid': 'my sidd',
                },
                'parent': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                    'cid': 'my sidd',
                },
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'comment',
            'content': 'foo',
            'inReplyTo': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })))

    def test_convert_blobs_false(self):
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        })))

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
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }), fetch_blobs=True))

        mock_get.assert_has_calls([self.req('http://my/pic')])

    def test_convert_fetch_blobs_true_existing_atp_remote_blob(self):
        cid = 'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq'
        AtpRemoteBlob(id='http://my/pic', cid=cid, size=8).put()

        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'avatar': {
                '$type': 'blob',
                'ref': CID.decode(cid),
                'mimeType': 'application/octet-stream',
                'size': 8,
            },
        }, ATProto.convert(Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }), fetch_blobs=True))

    def test_convert_protocols_not_enabled(self):
        obj = Object(our_as1={'foo': 'bar'}, source_protocol='activitypub')
        with self.assertRaises(BadRequest):
            ATProto.convert(obj)

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_web_url(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertEqual('https://bsky.app/profile/did:plc:user', user.web_url())

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('https://bsky.app/profile/han.dull', user.web_url())

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_or_id(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)
        self.assertIsNone(user.handle)
        self.assertEqual('did:plc:user', user.handle_or_id())

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('han.dull', user.handle)
        self.assertEqual('han.dull', user.handle_or_id())

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_as(self, mock_get):
        user = self.make_user('did:plc:user', cls=ATProto)

        # TODO? or remove?
        # self.assertEqual('@did:plc:user@atproto.brid.gy',
        #                  user.handle_as('activitypub'))

        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.assertEqual('@han.dull@atproto.brid.gy', user.handle_as('activitypub'))

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_profile_id(self, mock_get):
        self.assertEqual('at://did:plc:user/app.bsky.actor.profile/self',
                         self.make_user('did:plc:user', cls=ATProto).profile_id())

    @patch('atproto.DEBUG', new=False)
    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_create_for(self, mock_post, mock_create_task, mock_zone):
        mock_zone.return_value = zone = MagicMock()
        zone.resource_record_set = MagicMock()

        Fake.fetchable = {'fake:user': ACTOR_AS}
        user = Fake(id='fake:user')
        AtpRemoteBlob(id='https://alice.com/alice.jpg',
                      cid=BLOB_CID.encode('base32'), size=8).put()

        ATProto.create_for(user)

        # check user, repo
        did = user.key.get().get_copy(ATProto)
        self.assertEqual([Target(uri=did, protocol='atproto')], user.copies)
        repo = arroba.server.storage.load_repo(did)

        # check DNS record
        zone.resource_record_set.assert_called_with(
            name='_atproto.fake:handle:user.fa.brid.gy.', record_type='TXT',
            ttl=atproto.DNS_TTL, rrdatas=[f'"did={did}"'])

        # check profile record
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there',
            'avatar': {
                '$type': 'blob',
                'mimeType': 'application/octet-stream',
                'ref': BLOB_CID,
                'size': 8,
            },
        }, profile)

        uri = arroba.util.at_uri(did, 'app.bsky.actor.profile', 'self')
        self.assertEqual([Target(uri=uri, protocol='atproto')],
                         Object.get_by_id(id='fake:user').copies)

        mock_create_task.assert_called()

    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo(self, mock_post, mock_create_task, _):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })

        self.assertTrue(ATProto.send(obj, 'https://atproto.brid.gy/'))

        # check DID doc
        user = user.key.get()
        did = user.get_copy(ATProto)
        assert did
        self.assertEqual([Target(uri=did, protocol='atproto')], user.copies)
        did_obj = ATProto.load(did)
        self.assertEqual('https://atproto.brid.gy/',
                         did_obj.raw['service'][0]['serviceEndpoint'])

        # check repo, record
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        # check PLC directory call to create did:plc
        self.assertEqual((f'https://plc.local/{did}',), mock_post.call_args.args)
        genesis_op = mock_post.call_args.kwargs['json']
        self.assertEqual(did, genesis_op.pop('did'))
        genesis_op['sig'] = base64.urlsafe_b64decode(genesis_op['sig'])
        assert arroba.util.verify_sig(genesis_op, repo.rotation_key.public_key())

        del genesis_op['sig']
        self.assertEqual({
                'type': 'plc_operation',
                'verificationMethods': {
                    'atproto': encode_did_key(repo.signing_key.public_key()),
                },
                'rotationKeys': [encode_did_key(repo.rotation_key.public_key())],
                'alsoKnownAs': [
                    'at://fake:handle:user.fa.brid.gy',
                ],
                'services': {
                    'atproto_pds': {
                        'type': 'AtprotoPersonalDataServer',
                        'endpoint': 'https://atproto.brid.gy/',
                    }
                },
                'prev': None,
            }, genesis_op)

        # check atproto-commit task
        self.assertEqual(2, mock_create_task.call_count)
        self.assert_task(mock_create_task, 'atproto-commit',
                         '/queue/atproto-commit')

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='image/png'))  # image blob fetch
    @patch('google.cloud.dns.client.ManagedZone', autospec=True)
    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo_includes_user_profile(self, mock_post, mock_create_task,
                                                 _, __):
        Fake.fetchable = {'fake:user': ACTOR_AS}

        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'https://atproto.brid.gy/'))

        # check profile, record
        user = Fake.get_by_id('fake:user')
        did = user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there',
            'avatar': {
                '$type': 'blob',
                'ref': BLOB_CID,
                'mimeType': 'image/png',
                'size': 13,
            },
        }, profile)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_note_existing_repo(self, mock_create_task):
        user = self.make_user_and_repo()
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'https://atproto.brid.gy/'))

        # check repo, record
        did = user.key.get().get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()

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
            'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
            'cid': 'bafyCID',
        })

        like_obj = self.store_object(id='fake:like', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'id': 'fake:like',
            'actor': 'fake:user',
            'object': 'at://did:plc:bob/app.bsky.feed.post/tid',
        })
        self.assertTrue(ATProto.send(like_obj, 'https://atproto.brid.gy/'))

        # check repo, record
        did = user.get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.like', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:bob/app.bsky.feed.post/tid',
                'cid': 'bafyCID',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, record)

        at_uri = f'at://{did}/app.bsky.feed.like/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:like').copies)

        mock_create_task.assert_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_repost(self, mock_create_task):
        user = self.make_user_and_repo()
        obj = self.store_object(id='fake:repost', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:repost',
            'actor': 'fake:user',
            'object': 'at://did/app.bsky.feed.post/tid',
        })
        self.assertTrue(ATProto.send(obj, 'https://atproto.brid.gy/'))

        # check repo, record
        did = user.get_copy(ATProto)
        repo = self.storage.load_repo(did)
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.repost', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.repost',
            'subject': {
                'uri': 'at://did/app.bsky.feed.post/tid',
                'cid': '',
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }, record)

        at_uri = f'at://{did}/app.bsky.feed.repost/{last_tid}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:repost').copies)

        mock_create_task.assert_called()

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
        self.assertTrue(ATProto.send(obj, 'https://atproto.brid.gy/'))

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

        mock_create_task.assert_called()

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
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'foo',
            'actor': 'fake:user',
        })
        self.assertFalse(ATProto.send(obj, 'https://atproto.brid.gy/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_ignore_accept(self, mock_create_task):
        obj = Object(id='fake:accept', as2=test_activitypub.ACCEPT)
        self.assertFalse(ATProto.send(obj, 'https://atproto.brid.gy/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_translates_ids(self, mock_create_task):
        user = self.make_user_and_repo()
        alice = self.make_user(id='fake:alice', cls=Fake,
                               copies=[Target(uri='did:alice', protocol='atproto')])
        post = self.store_object(
            id='fake:post', source_protocol='fake',
            copies=[Target(uri='at://did/coll/post', protocol='atproto')])

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

        self.assertTrue(ATProto.send(create, 'https://atproto.brid.gy/'))

        repo = self.storage.load_repo(user.get_copy(ATProto))
        last_tid = arroba.util.int_to_tid(arroba.util._tid_ts_last)
        record = repo.get_record('app.bsky.feed.post', last_tid)
        self.assertEqual({
            '$type': 'app.bsky.feed.post',
            'createdAt': '2022-01-02T03:04:05.000Z',
            'text': 'foo',
            'reply': {
                '$type': 'app.bsky.feed.post#replyRef',
                'root': {
                    'uri': 'at://did/coll/post',
                    'cid': '',
                },
                'parent': {
                    'uri': 'at://did/coll/post',
                    'cid': '',
                },
            },
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:alice',
                }],
            }],
        }, record)

        at_uri = f'at://did:plc:user/app.bsky.feed.post/{last_tid}'
        self.assertEqual([], Object.get_by_id(id='fake:reply:post').copies)
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:reply').copies)

        mock_create_task.assert_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.get')
    def test_poll_notifications(self, mock_get, mock_create_task):
        user_a = self.make_user(id='fake:user-a', cls=Fake,
                                copies=[Target(uri='did:plc:a', protocol='atproto')])
        user_b = self.make_user(id='fake:user-b', cls=Fake,
                                copies=[Target(uri='did:plc:b', protocol='atproto')])
        user_c = self.make_user(id='fake:user-c', cls=Fake,
                                copies=[Target(uri='did:plc:c', protocol='atproto')])

        Repo.create(self.storage, 'did:plc:a', signing_key=ATPROTO_KEY)
        Repo.create(self.storage, 'did:plc:c', signing_key=ATPROTO_KEY)

        like = {
            '$type': 'app.bsky.feed.like',
            'subject': {
                'cid': '...',
                'uri': 'at://did:plc:a/app.bsky.feed.post/999',
            },
        }
        reply = {
            '$type': 'app.bsky.feed.post',
            'text': 'I hereby reply',
            'reply': {
                'root': {
                    'cid': '...',
                    'uri': 'at://did:plc:a/app.bsky.feed.post/987',
                },
                'parent': {
                    'cid': '...',
                    'uri': 'at://did:plc:a/app.bsky.feed.post/987',
                }
            },
        }
        follow = {
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:c',
        }
        eve = {
            '$type': 'app.bsky.actor.defs#profileView',
            'did': 'did:plc:eve',
            'handle': 'eve.com',
        }
        alice = {
            '$type': 'app.bsky.actor.defs#profileView',
            'did': 'did:plc:a',
            'handle': 'alice',
        }

        mock_get.side_effect = [
            requests_response({
                'cursor': '...',
                'notifications': [{
                    'uri': 'at://did:plc:d/app.bsky.feed.like/123',
                    'cid': '...',
                    'author': eve,
                    'record': like,
                    'reason': 'like',
                }, {
                    'uri': 'at://did:plc:d/app.bsky.feed.post/456',
                    'cid': '...',
                    'author': eve,
                    'record': reply,
                    'reason': 'reply',
                }],
            }),
            requests_response(DID_DOC),
            requests_response({
                'cursor': '...',
                'notifications': [{
                    'uri': 'at://did:plc:d/app.bsky.graph.follow/789',
                    'cid': '...',
                    'author': alice,
                    'record': follow,
                    'reason': 'follow',
                }],
            }),
        ]

        resp = self.post('/queue/atproto-poll-notifs', client=hub.app.test_client())
        self.assertEqual(200, resp.status_code)

        expected_list_notifs = call(
            'https://api.bsky-sandbox.dev/xrpc/app.bsky.notification.listNotifications',
            json=None, data=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            },
        )
        # just check that access token was set, then remove it before comparing
        # for call in mock_get.call_args_list:
        assert mock_get.call_args_list[0].kwargs['headers'].pop('Authorization')
        self.assertEqual(expected_list_notifs, mock_get.call_args_list[0])

        assert mock_get.call_args_list[2].kwargs['headers'].pop('Authorization')
        self.assertEqual(expected_list_notifs, mock_get.call_args_list[2])

        like_obj = Object.get_by_id('at://did:plc:d/app.bsky.feed.like/123')
        self.assertEqual(like, like_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=like_obj.key.urlsafe(), authed_as='did:plc:eve')

        reply_obj = Object.get_by_id('at://did:plc:d/app.bsky.feed.post/456')
        self.assertEqual(reply, reply_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=reply_obj.key.urlsafe(), authed_as='did:plc:eve')

        follow_obj = Object.get_by_id('at://did:plc:d/app.bsky.graph.follow/789')
        self.assertEqual(follow, follow_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=follow_obj.key.urlsafe(), authed_as='did:plc:a')

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.get')
    def test_poll_posts(self, mock_get, mock_create_task):
        user_a = self.make_user(id='fake:user-a', cls=Fake,
                                copies=[Target(uri='did:plc:a', protocol='atproto')])
        user_b = self.make_user(id='fake:user-b', cls=Fake,
                                copies=[Target(uri='did:plc:b', protocol='atproto')])
        user_c = self.make_user(id='fake:user-c', cls=Fake,
                                copies=[Target(uri='did:plc:c', protocol='atproto')])
        Repo.create(self.storage, 'did:plc:a', signing_key=ATPROTO_KEY)
        Repo.create(self.storage, 'did:plc:b', signing_key=ATPROTO_KEY)
        Repo.create(self.storage, 'did:plc:c', signing_key=ATPROTO_KEY)

        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'My original post',
            'createdAt': '2007-07-07T03:04:05',
        }
        post_view = {
            '$type': 'app.bsky.feed.defs#postView',
            'uri': 'at://did:web:alice.com/app.bsky.feed.post/123',
            'cid': '',
            'record': post,
            'author': {
                '$type': 'app.bsky.actor.defs#profileViewBasic',
                'did': 'did:web:alice.com',
                'handle': 'alice.com',
            },
        }

        mock_get.side_effect = [
            requests_response({
                'cursor': '...',
                'feed': [{
                    '$type': 'app.bsky.feed.defs#feedViewPost',
                    'post': post_view,
                }],
            }),
            requests_response({
                **DID_DOC,
                'id': 'did:plc:alice.com',
            }),
            requests_response({
                'cursor': '...',
                'feed': [],
            }),
            requests_response({
                'cursor': '...',
                'feed': [{
                    '$type': 'app.bsky.feed.defs#feedViewPost',
                    'post': post_view,
                    'reason': {
                        '$type': 'app.bsky.feed.defs#reasonRepost',
                        'by': {
                            '$type': 'app.bsky.actor.defs#profileViewBasic',
                            'did': 'did:web:bob.com',
                            'handle': 'bob.com',
                        },
                        'indexedAt': '2022-01-02T03:04:05.000Z',
                    },
                }],
            }),
        ]

        resp = self.post('/queue/atproto-poll-posts', client=hub.app.test_client())
        self.assertEqual(200, resp.status_code)

        get_timeline = call(
            'https://api.bsky-sandbox.dev/xrpc/app.bsky.feed.getTimeline',
            json=None, data=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
                'Authorization': ANY,
            })
        self.assertEqual([
            get_timeline,
            self.req('https://alice.com/.well-known/did.json'),
            get_timeline,
            get_timeline,
        ], mock_get.call_args_list)

        post_obj = Object.get_by_id('at://did:web:alice.com/app.bsky.feed.post/123')
        self.assertEqual(post, post_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/queue/receive',
                         obj=post_obj.key.urlsafe(), authed_as='did:plc:a')

        # TODO: https://github.com/snarfed/bridgy-fed/issues/728
        # repost_obj = Object.get_by_id('at://did:plc:d/app.bsky.feed.post/456')
        # self.assertEqual(repost, repost_obj.bsky)
        # self.assert_task(mock_create_task, 'receive', '/queue/receive',
        #                  obj=repost_obj.key.urlsafe(), authed_as='did:plc:eve')
