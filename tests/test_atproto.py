"""Unit tests for atproto.py."""
import copy
import logging
from unittest import skip
from unittest.mock import patch

from flask import g
from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_VIEW_BSKY
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

from atproto import ATProto
import common
from models import Object
import protocol
from .testutil import Fake, TestCase

class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()
        # self.request_context.push()

        # self.user = self.make_user('user.com', has_hcard=True, has_redirects=True,
        #                            obj_as2={**ACTOR, 'id': 'https://user.com/'})

    def test_put_validates_id(self, *_):
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

    def test_owns_id(self):
        self.assertFalse(ATProto.owns_id('http://foo'))
        self.assertFalse(ATProto.owns_id('https://bar.baz/biff'))
        self.assertFalse(ATProto.owns_id('e45fab982'))

        self.assertTrue(ATProto.owns_id('at://did:plc:foo/bar/123'))
        self.assertTrue(ATProto.owns_id('did:plc:foo'))
        self.assertTrue(ATProto.owns_id('did:web:bar.com'))

    @patch('requests.get', return_value=requests_response({'foo': 'bar'}))
    def test_fetch_did_plc(self, mock_get):
        obj = Object(id='did:plc:123')
        ATProto.fetch(obj)
        self.assertEqual({'foo': 'bar'}, obj.raw)

        mock_get.assert_has_calls((
            self.req('https://plc.local/did:plc:123'),
        ))

    @patch('requests.get', return_value=requests_response({'foo': 'bar'}))
    def test_fetch_did_web(self, mock_get):
        obj = Object(id='did:web:user.com')
        ATProto.fetch(obj)
        self.assertEqual({'foo': 'bar'}, obj.raw)

        mock_get.assert_has_calls((
            self.req('https://user.com/.well-known/did.json'),
        ))

    # @patch('requests.get')
    # def test_fetch_not_json(self, mock_get):
    #     mock_get.return_value = self.as2_resp('XYZ not JSON')

    #     with self.assertRaises(BadGateway):
    #         ATProto.fetch(Object(id='http://the/id'))

    #     mock_get.assert_has_calls([self.as2_req('http://the/id')])

    def test_serve(self):
        obj = self.store_object(id='http://orig', our_as1=ACTOR_AS)
        self.assertEqual(
            (ACTOR_PROFILE_VIEW_BSKY, {'Content-Type': 'application/json'}),
            ATProto.serve(obj))

    # def test_ap_address(self):
    #     user = ATProto(obj=Object(id='a', as2={**ACTOR, 'preferredUsername': 'me'}))
    #     self.assertEqual('@me@mas.to', user.ap_address())
    #     self.assertEqual('@me@mas.to', user.readable_id)

    #     user.obj.as2 = ACTOR
    #     self.assertEqual('@swentel@mas.to', user.ap_address())
    #     self.assertEqual('@swentel@mas.to', user.readable_id)

    #     user = ATProto(id='https://mas.to/users/alice')
    #     self.assertEqual('@alice@mas.to', user.ap_address())
    #     self.assertEqual('@alice@mas.to', user.readable_id)

    # def test_ap_actor(self):
    #     user = self.make_user('http://foo/actor', cls=ATProto)
    #     self.assertEqual('http://foo/actor', user.ap_actor())

    def test_web_url(self):
        user = self.make_user('did:plc:foo', cls=ATProto)
        self.assertEqual('https://bsky.app/profile/did:plc:foo', user.web_url())
        # TODO test that handle overrides

    # def test_readable_id(self):
    #     user = self.make_user('http://foo', cls=ATProto)
    #     self.assertIsNone(user.readable_id)
    #     self.assertEqual('http://foo', user.readable_or_key_id())

    #     user.obj = Object(id='a', as2=ACTOR)
    #     self.assertEqual('@swentel@mas.to', user.readable_id)
    #     self.assertEqual('@swentel@mas.to', user.readable_or_key_id())

    # @skip
    # def test_target_for_not_atproto(self):
    #     with self.assertRaises(AssertionError):
    #         ATProto.target_for(Object(source_protocol='web'))

    # def test_target_for_actor(self):
    #     self.assertEqual(ACTOR['inbox'], ATProto.target_for(
    #         Object(source_protocol='ap', as2=ACTOR)))

    #     actor = copy.deepcopy(ACTOR)
    #     del actor['inbox']
    #     self.assertIsNone(ATProto.target_for(
    #         Object(source_protocol='ap', as2=actor)))

    #     actor['publicInbox'] = 'so-public'
    #     self.assertEqual('so-public', ATProto.target_for(
    #         Object(source_protocol='ap', as2=actor)))

    #     # sharedInbox
    #     self.assertEqual('so-public', ATProto.target_for(
    #         Object(source_protocol='ap', as2=actor), shared=True))
    #     actor['endpoints'] = {
    #         'sharedInbox': 'so-shared',
    #     }
    #     self.assertEqual('so-public', ATProto.target_for(
    #         Object(source_protocol='ap', as2=actor)))
    #     self.assertEqual('so-shared', ATProto.target_for(
    #         Object(source_protocol='ap', as2=actor), shared=True))

    # def test_target_for_object(self):
    #     obj = Object(as2=NOTE_OBJECT, source_protocol='ap')
    #     self.assertIsNone(ATProto.target_for(obj))

    #     Object(id=ACTOR['id'], as2=ACTOR).put()
    #     obj.as2 = {
    #         **NOTE_OBJECT,
    #         'author': ACTOR['id'],
    #     }
    #     self.assertEqual('http://mas.to/inbox', ATProto.target_for(obj))

    #     del obj.as2['author']
    #     obj.as2['actor'] = copy.deepcopy(ACTOR)
    #     obj.as2['actor']['url'] = [obj.as2['actor'].pop('id')]
    #     self.assertEqual('http://mas.to/inbox', ATProto.target_for(obj))

    # @patch('requests.get')
    # def test_target_for_object_fetch(self, mock_get):
    #     mock_get.return_value = self.as2_resp(ACTOR)

    #     obj = Object(as2={
    #         **NOTE_OBJECT,
    #         'author': 'http://the/author',
    #     }, source_protocol='ap')
    #     self.assertEqual('http://mas.to/inbox', ATProto.target_for(obj))
    #     mock_get.assert_has_calls([self.as2_req('http://the/author')])

    # @patch('requests.get')
    # def test_target_for_author_is_object_id(self, mock_get):
    #     obj = self.store_object(id='http://the/author', our_as1={
    #         'author': 'http://the/author',
    #     })
    #     # test is that we short circuit out instead of infinite recursion
    #     self.assertIsNone(ATProto.target_for(obj))
