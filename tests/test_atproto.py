"""Unit tests for atproto.py."""
import copy
import logging
from unittest import skip
from unittest.mock import patch

from arroba.datastore_storage import AtpBlock, AtpRepo, DatastoreStorage
from arroba.repo import Repo
import arroba.util
from flask import g
from granary.tests.test_bluesky import (
    ACTOR_AS,
    ACTOR_PROFILE_VIEW_BSKY,
    POST_AS,
    POST_BSKY,
)
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

from atproto import ATProto
from common import USER_AGENT
from models import Object
import protocol
from .testutil import Fake, TestCase

DID_DOC = {
  'type': 'plc_operation',
  'rotationKeys': ['did:key:xyz'],
  'verificationMethods': {'atproto': 'did:key:xyz'},
  'alsoKnownAs': ['at://han.dull'],
    'services': {
        'atproto_pds': {
            'type': 'AtprotoPersonalDataServer',
            'endpoint': 'https://some.pds',
        }
    },
  'prev': None,
  'sig': '...'
}

class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()

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

    def test_target_for_did_doc(self):
        self.assertIsNone(ATProto.target_for(Object(id='did:plc:foo')))

    def test_target_for_stored_did(self):
        did_obj = self.store_object(id='did:plc:foo', raw=DID_DOC)
        got = ATProto.target_for(Object(id='at://did:plc:foo/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_target_for_fetch_did(self, mock_get):
        got = ATProto.target_for(Object(id='at://did:plc:foo/co.ll/123'))
        self.assertEqual('https://some.pds', got)

    def test_target_for_user_with_stored_did(self):
        did_obj = self.store_object(id='did:plc:foo', raw=DID_DOC)
        user = self.make_user('fake:user', cls=Fake, atproto_did='did:plc:foo')
        got = ATProto.target_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        }))
        self.assertEqual('https://some.pds', got)

    def test_target_for_user_no_stored_did(self):
        user = self.make_user('fake:user', cls=Fake)
        got = ATProto.target_for(Object(id='fake:post', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        }))
        self.assertEqual('http://localhost/', got)

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

    @patch('requests.get', return_value=requests_response({'foo': 'bar'}))
    def test_fetch_at_uri_record(self, mock_get):
        self.store_object(id='did:plc:abc', raw=DID_DOC)
        obj = Object(id='at://did:plc:abc/app.bsky.feed.post/123')
        self.assertTrue(ATProto.fetch(obj))
        self.assertEqual({'foo': 'bar'}, obj.bsky)
        # eg https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        mock_get.assert_called_with(
            'https://some.pds/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc&collection=app.bsky.feed.post&rkey=123',
            json=None,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT,
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
    def test_readable_id(self, mock_get):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('did:plc:foo', user.readable_id)

        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.assertEqual('han.dull', user.readable_id)

    def test_ap_address(self):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('@did:plc:foo@atproto.brid.gy', user.ap_address())

        self.store_object(id='did:plc:foo', raw=DID_DOC)
        self.assertEqual('@han.dull@atproto.brid.gy', user.ap_address())

    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo(self, mock_post):
        user = self.make_user(id='fake:user', cls=Fake)
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check DID doc
        user = user.key.get()
        assert user.atproto_did
        did_obj = ATProto.load(user.atproto_did)
        self.assertEqual('https://localhost',
                         did_obj.raw['services']['atproto_pds']['endpoint'])
        mock_post.assert_has_calls(
            [self.req(f'https://plc.local/{user.atproto_did}', json=did_obj.raw)])

        # check repo, record
        repo = DatastoreStorage().load_repo(did=user.atproto_did)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_send_new_repo_includes_user_profile(self, mock_post):
        user = self.make_user(id='fake:user', cls=Fake, obj_as1=ACTOR_AS)
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check profile, record
        repo = DatastoreStorage().load_repo(did=user.key.get().atproto_did)
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual(ACTOR_PROFILE_VIEW_BSKY, profile)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

    def test_send_existing_repo(self):
        user = self.make_user(id='fake:user', cls=Fake, atproto_did='did:plc:foo')

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['services']['atproto_pds']['endpoint'] = 'http://localhost/'
        self.store_object(id='did:plc:foo', raw=did_doc)

        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            **POST_AS,
            'actor': 'fake:user',
        })
        self.assertTrue(ATProto.send(obj, 'http://localhost/'))

        # check repo, record
        repo = DatastoreStorage().load_repo(did=user.atproto_did)
        record = repo.get_record('app.bsky.feed.post', arroba.util._tid_last)
        self.assertEqual(POST_BSKY, record)

    def test_send_not_our_repo(self):
        self.assertFalse(ATProto.send(Object(id='fake:post'), 'http://other.pds/'))
        self.assertEqual(0, AtpBlock.query().count())
        self.assertEqual(0, AtpRepo.query().count())

    def test_send_did_doc_not_our_repo(self):
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
