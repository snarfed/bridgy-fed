"""Unit tests for atproto.py."""
import copy
import logging
from unittest import skip
from unittest.mock import patch

from flask import g
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

from atproto import ATProto
import common
import protocol
from .testutil import Fake, TestCase


class ATProtoTest(TestCase):

    def setUp(self):
        super().setUp()
        # self.request_context.push()

        # self.user = self.make_user('user.com', has_hcard=True, has_redirects=True,
        #                            obj_as2={**ACTOR, 'id': 'https://user.com/'})

    # def test_put_validates_id(self, *_):
    #     for bad in (
    #         '',
    #         'not a url',
    #         'ftp://not.web/url',
    #         'https:///no/domain',
    #         'https://fed.brid.gy/foo',
    #         'https://ap.brid.gy/foo',
    #         'http://localhost/foo',
    #     ):
    #         with self.assertRaises(AssertionError):
    #             ATProto(id=bad).put()

    def test_owns_id(self):
        self.assertFalse(ATProto.owns_id('http://foo'))
        self.assertFalse(ATProto.owns_id('https://bar.baz/biff'))
        self.assertFalse(ATProto.owns_id('e45fab982'))

        self.assertTrue(ATProto.owns_id('at://did:plc:foo/bar/123'))
        self.assertTrue(ATProto.owns_id('did:plc:foo'))
        self.assertTrue(ATProto.owns_id('did:web:bar.com'))

    # # TODO: make these generic and use Fake
    # @patch('requests.get')
    # def test_load_http(self, mock_get):
    #     mock_get.return_value = AS2

    #     id = 'http://the/id'
    #     self.assertIsNone(Object.get_by_id(id))

    #     # first time fetches over HTTP
    #     got = ATProto.load(id)
    #     self.assert_equals(id, got.key.id())
    #     self.assert_equals(AS2_OBJ, got.as2)
    #     mock_get.assert_has_calls([self.as2_req(id)])

    #     # second time is in cache
    #     got.key.delete()
    #     mock_get.reset_mock()

    #     got = ATProto.load(id)
    #     self.assert_equals(id, got.key.id())
    #     self.assert_equals(AS2_OBJ, got.as2)
    #     mock_get.assert_not_called()

    # @patch('requests.get')
    # def test_load_datastore(self, mock_get):
    #     id = 'http://the/id'
    #     stored = Object(id=id, as2=AS2_OBJ)
    #     stored.put()
    #     protocol.objects_cache.clear()

    #     # first time loads from datastore
    #     got = ATProto.load(id)
    #     self.assert_entities_equal(stored, got)
    #     mock_get.assert_not_called()

    #     # second time is in cache
    #     stored.key.delete()
    #     got = ATProto.load(id)
    #     self.assert_entities_equal(stored, got)
    #     mock_get.assert_not_called()

    # @patch('requests.get')
    # def test_load_preserves_fragment(self, mock_get):
    #     stored = Object(id='http://the/id#frag', as2=AS2_OBJ)
    #     stored.put()
    #     protocol.objects_cache.clear()

    #     got = ATProto.load('http://the/id#frag')
    #     self.assert_entities_equal(stored, got)
    #     mock_get.assert_not_called()

    # @patch('requests.get')
    # def test_load_datastore_no_as2(self, mock_get):
    #     """If the stored Object has no as2, we should fall back to HTTP."""
    #     id = 'http://the/id'
    #     stored = Object(id=id, as2={}, status='in progress')
    #     stored.put()
    #     protocol.objects_cache.clear()

    #     mock_get.return_value = AS2
    #     got = ATProto.load(id)
    #     mock_get.assert_has_calls([self.as2_req(id)])

    #     self.assert_equals(id, got.key.id())
    #     self.assert_equals(AS2_OBJ, got.as2)
    #     mock_get.assert_has_calls([self.as2_req(id)])

    #     self.assert_object(id,
    #                        as2=AS2_OBJ,
    #                        as1={**AS2_OBJ, 'id': id},
    #                        source_protocol='atproto',
    #                        # check that it reused our original Object
    #                        status='in progress')

    # @patch('requests.get')
    # def test_fetch_direct(self, mock_get):
    #     mock_get.return_value = AS2
    #     obj = Object(id='http://orig')
    #     ATProto.fetch(obj)
    #     self.assertEqual(AS2_OBJ, obj.as2)

    #     mock_get.assert_has_calls((
    #         self.as2_req('http://orig'),
    #     ))

    # @patch('requests.get')
    # def test_fetch_direct_ld_content_type(self, mock_get):
    #     mock_get.return_value = requests_response(AS2_OBJ, headers={
    #         'Content-Type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
    #     })
    #     obj = Object(id='http://orig')
    #     ATProto.fetch(obj)
    #     self.assertEqual(AS2_OBJ, obj.as2)

    #     mock_get.assert_has_calls((
    #         self.as2_req('http://orig'),
    #     ))

    # @patch('requests.get')
    # def test_fetch_via_html(self, mock_get):
    #     mock_get.side_effect = [HTML_WITH_AS2, AS2]
    #     obj = Object(id='http://orig')
    #     ATProto.fetch(obj)
    #     self.assertEqual(AS2_OBJ, obj.as2)

    #     mock_get.assert_has_calls((
    #         self.as2_req('http://orig'),
    #         self.as2_req('http://as2', headers=as2.CONNEG_HEADERS),
    #     ))

    # @patch('requests.get')
    # def test_fetch_only_html(self, mock_get):
    #     mock_get.return_value = HTML

    #     obj = Object(id='http://orig')
    #     self.assertFalse(ATProto.fetch(obj))
    #     self.assertIsNone(obj.as1)

    # @patch('requests.get')
    # def test_fetch_not_acceptable(self, mock_get):
    #     mock_get.return_value = NOT_ACCEPTABLE

    #     obj = Object(id='http://orig')
    #     self.assertFalse(ATProto.fetch(obj))
    #     self.assertIsNone(obj.as1)

    # @patch('requests.get')
    # def test_fetch_ssl_error(self, mock_get):
    #     mock_get.side_effect = requests.exceptions.SSLError
    #     with self.assertRaises(BadGateway):
    #         ATProto.fetch(Object(id='http://orig'))

    # @patch('requests.get')
    # def test_fetch_no_content(self, mock_get):
    #     mock_get.return_value = self.as2_resp('')

    #     with self.assertRaises(BadGateway):
    #         ATProto.fetch(Object(id='http://the/id'))

    #     mock_get.assert_has_calls([self.as2_req('http://the/id')])

    # @patch('requests.get')
    # def test_fetch_not_json(self, mock_get):
    #     mock_get.return_value = self.as2_resp('XYZ not JSON')

    #     with self.assertRaises(BadGateway):
    #         ATProto.fetch(Object(id='http://the/id'))

    #     mock_get.assert_has_calls([self.as2_req('http://the/id')])

    # def test_fetch_non_url(self):
    #     obj = Object(id='x y z')
    #     self.assertFalse(ATProto.fetch(obj))
    #     self.assertIsNone(obj.as1)

    # def test_serve(self):
    #     obj = Object(id='http://orig', as2=LIKE)
    #     self.assertEqual((LIKE_WRAPPED, {'Content-Type': 'application/activity+json'}),
    #                      ATProto.serve(obj))

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

    # def test_web_url(self):
    #     user = self.make_user('http://foo/actor', cls=ATProto)
    #     self.assertEqual('http://foo/actor', user.web_url())

    #     user.obj = Object(id='a', as2=copy.deepcopy(ACTOR))  # no url
    #     self.assertEqual('http://foo/actor', user.web_url())

    #     user.obj.as2['url'] = ['http://my/url']
    #     self.assertEqual('http://my/url', user.web_url())

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
