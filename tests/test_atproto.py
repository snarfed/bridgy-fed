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

    def test_target_for_stored_did(self):
        self.assertIsNone(ATProto.target_for(Object(id='did:plc:foo')))

        did_obj = self.store_object(id='did:plc:foo', raw=DID_DOC)
        got = ATProto.target_for(Object(id='at://did:plc:foo/co.ll/123'))
        self.assertEqual('https://some.pds', got)

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
        # TODO test that handle overrides

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
