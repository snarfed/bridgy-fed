"""Unit tests for atproto.py."""
import base64
import copy
from google.cloud.tasks_v2.types import Task
import logging
from unittest import skip
from unittest.mock import call, patch

from arroba.datastore_storage import AtpBlock, AtpRepo, DatastoreStorage
from arroba.did import encode_did_key
from arroba.repo import Repo
import arroba.util
import dns.resolver
from dns.resolver import NXDOMAIN
from flask import g
from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_PROFILE_VIEW_BSKY,
    POST_AS,
    POST_BSKY,
)
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads

import atproto
from atproto import ATProto
import common
from models import Object, Target
import protocol
from .testutil import Fake, TestCase
from . import test_activitypub

from hub import app

DID_DOC = {
    'id': 'did:plc:foo',
    'alsoKnownAs': ['at://han.dull'],
    'verificationMethod': [{
        'id': 'did:plc:foo#atproto',
        'type': 'Multikey',
        'controller': 'did:plc:foo',
        'publicKeyMultibase': 'did:key:xyz',
    }],
    'service': [{
        'id': '#atproto_pds',
        'type': 'AtprotoPersonalDataServer',
        'serviceEndpoint': 'https://some.pds',
    }],
}

KEY = arroba.util.new_key(2349823483510)  # deterministic seed


class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()
        self.storage = DatastoreStorage()

    def test_put_validates_id(self):
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
        ATProto(id='did:plc:foo').put()

    def test_put_blocks_atproto_did(self):
        with self.assertRaises(AssertionError):
            ATProto(id='did:plc:123', atproto_did='did:plc:456').put()

    def test_owns_id(self):
        self.assertFalse(ATProto.owns_id('http://foo'))
        self.assertFalse(ATProto.owns_id('https://bar.baz/biff'))
        self.assertFalse(ATProto.owns_id('e45fab982'))

        self.assertTrue(ATProto.owns_id('at://did:plc:foo/bar/123'))
        self.assertTrue(ATProto.owns_id('did:plc:foo'))
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

    def test_handle_to_id(self, *_):
        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('did:plc:foo', ATProto.handle_to_id('han.dull'))

    @patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    # resolving handle, HTTPS method, not founud
    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_to_id_not_found(self, *_):
        self.assertIsNone(ATProto.handle_to_id('han.dull'))

    def test_target_for_did_doc(self):
        self.assertIsNone(ATProto.target_for(Object(id='did:plc:foo')))

    def test_target_for_stored_did(self):
        self.store_object(id='did:plc:foo', raw=DID_DOC)
        got = ATProto.target_for(Object(id='at://did:plc:foo/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_target_for_fetch_did(self, mock_get):
        got = ATProto.target_for(Object(id='at://did:plc:foo/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    def test_target_for_user_with_stored_did(self):
        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.make_user('fake:user', cls=Fake, atproto_did='did:plc:foo')
        got = ATProto.target_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        }))
        self.assertEqual('https://some.pds', got)

    def test_target_for_user_no_stored_did(self):
        self.make_user('fake:user', cls=Fake)
        got = ATProto.target_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        }))
        self.assertEqual('http://localhost/', got)

    def test_target_for_bsky_app_url_did_stored(self):
        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.make_user('fake:user', cls=Fake, atproto_did='did:plc:foo')

        got = ATProto.target_for(Object(
            id='https://bsky.app/profile/did:plc:foo/post/123'))
        self.assertEqual('https://some.pds', got)

    @patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    @patch('requests.get', side_effect=[
        # resolving handle, HTTPS method
        requests_response('did:plc:foo', content_type='text/plain'),
        # fetching DID doc
        requests_response(DID_DOC),
    ])
    def test_target_for_bsky_app_url_resolve_handle(self, mock_get, _):
        got = ATProto.target_for(Object(
            id='https://bsky.app/profile/baz.com/post/123'))
        self.assertEqual('https://some.pds', got)

        mock_get.assert_has_calls((
            self.req('https://baz.com/.well-known/atproto-did'),
            self.req('https://plc.local/did:plc:foo'),
        ))

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
        self.assertEqual({'foo': 'bar'}, obj.bsky)
        # eg https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        mock_get.assert_called_once_with(
            'https://some.pds/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc&collection=app.bsky.feed.post&rkey=123',
            json=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': common.USER_AGENT,
            },
        )

    def test_serve(self):
        obj = self.store_object(id='http://orig', our_as1=ACTOR_AS)
        self.assertEqual(
            (ACTOR_PROFILE_VIEW_BSKY, {'Content-Type': 'application/json'}),
            ATProto.serve(obj))

    def test_web_url(self):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('https://bsky.app/profile/did:plc:foo', user.web_url())

        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.assertEqual('https://bsky.app/profile/han.dull', user.web_url())

    @patch('requests.get', return_value=requests_response('', status=404))
    def test_handle_or_id(self, mock_get):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertIsNone(user.handle)
        self.assertEqual('did:plc:foo', user.handle_or_id())

        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.assertEqual('han.dull', user.handle)
        self.assertEqual('han.dull', user.handle_or_id())

    def test_ap_address(self):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('@did:plc:foo@atproto.brid.gy', user.ap_address())

        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.assertEqual('@han.dull@atproto.brid.gy', user.ap_address())

    def test_profile_id(self):
        self.assertEqual('at://did:plc:foo/app.bsky.actor.profile/self',
                         self.make_user('did:plc:foo', cls=ATProto).profile_id())

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo(self, mock_post, mock_create_task):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check DID doc
        user = user.key.get()
        assert user.atproto_did
        self.assertEqual([Target(uri=user.atproto_did, protocol='atproto')],
                         user.copies)
        did_obj = ATProto.load(user.atproto_did)
        self.assertEqual('http://localhost/',
                         did_obj.raw['service'][0]['serviceEndpoint'])

        # check repo, record
        repo = self.storage.load_repo(user.atproto_did)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{user.atproto_did}/app.bsky.feed.post/{arroba.util._tid_last}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        # check PLC directory call to create did:plc
        self.assertEqual((f'https://plc.local/{user.atproto_did}',),
                         mock_post.call_args.args)
        genesis_op = mock_post.call_args.kwargs['json']
        self.assertEqual(user.atproto_did, genesis_op.pop('did'))
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
                        'endpoint': 'http://localhost/',
                    }
                },
                'prev': None,
            }, genesis_op)

        # check atproto-commit task
        self.assertEqual(2, mock_create_task.call_count)
        self.assert_task(mock_create_task, 'atproto-commit',
                         '/_ah/queue/atproto-commit')

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo_includes_user_profile(self, mock_post, mock_create_task):
        user = self.make_user(id='fake:user', cls=Fake, obj_as1=ACTOR_AS)
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check profile, record
        did = user.key.get().atproto_did
        repo = self.storage.load_repo(did)
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual(ACTOR_PROFILE_VIEW_BSKY, profile)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{did}/app.bsky.feed.post/{arroba.util._tid_last}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_send_existing_repo(self, mock_create_task):
        user = self.make_user(id='fake:user', cls=Fake, atproto_did='did:plc:foo')

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = 'http://localhost/'
        self.store_object(id='did:plc:foo', raw=did_doc)
        Repo.create(self.storage, 'did:plc:foo', signing_key=KEY)

        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check repo, record
        repo = self.storage.load_repo(user.atproto_did)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

        at_uri = f'at://{user.atproto_did}/app.bsky.feed.post/{arroba.util._tid_last}'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:post').copies)

        mock_create_task.assert_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_not_our_repo(self, mock_create_task):
        self.assertFalse(ATProto.send(Object(id='fake:post'), 'http://other.pds/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_did_doc_not_our_repo(self, mock_create_task):
        self.store_object(id='did:plc:foo', raw=DID_DOC)  # uses https://some.pds
        user = self.make_user(id='fake:user', cls=Fake, atproto_did='did:plc:foo')
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'foo',
            'actor': 'fake:user',
        })
        self.assertFalse(ATProto.send(obj, 'http://localhost/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task')
    def test_send_ignore_accept(self, mock_create_task):
        obj = Object(id='fake:accept', as2=test_activitypub.ACCEPT)
        self.assertFalse(ATProto.send(obj, 'http://localhost/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())
        mock_create_task.assert_not_called()

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.get')
    def test_poll_notifications(self, mock_get, mock_create_task):
        user_a = self.make_user(id='fake:user-a', cls=Fake, atproto_did=f'did:plc:a')
        user_b = self.make_user(id='fake:user-c', cls=Fake, atproto_did=f'did:plc:b')
        user_c = self.make_user(id='fake:user-b', cls=Fake, atproto_did=f'did:plc:c')

        Repo.create(self.storage, 'did:plc:a', signing_key=KEY)
        Repo.create(self.storage, 'did:plc:c', signing_key=KEY)

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

        client = app.test_client()
        resp = client.get('/_ah/queue/atproto-poll-notifs')
        self.assertEqual(200, resp.status_code)

        expected_list_notifs = call(
            'https://api.bsky-sandbox.dev/xrpc/app.bsky.notification.listNotifications',
            json=None,
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

        # TODO: to convert like back to AS1, we need some mapping from the
        # original post's URI/CID to its original non-ATP URL, right? add a new
        # AS1 field? store it in datastore?
        # ANSWER: add `copies` repeated Target property to Object to map
        #
        like_obj = Object.get_by_id('at://did:plc:d/app.bsky.feed.like/123')
        self.assertEqual(like, like_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/_ah/queue/receive',
                         obj=like_obj.key.urlsafe(), user=user_a.key.urlsafe())

        reply_obj = Object.get_by_id('at://did:plc:d/app.bsky.feed.post/456')
        self.assertEqual(reply, reply_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/_ah/queue/receive',
                         obj=reply_obj.key.urlsafe(), user=user_a.key.urlsafe())

        follow_obj = Object.get_by_id('at://did:plc:d/app.bsky.graph.follow/789')
        self.assertEqual(follow, follow_obj.bsky)
        self.assert_task(mock_create_task, 'receive', '/_ah/queue/receive',
                         obj=follow_obj.key.urlsafe(), user=user_c.key.urlsafe())
