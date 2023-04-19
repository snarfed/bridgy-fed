"""Unit tests for protocol.py."""
from unittest.mock import patch

from flask import g
from oauth_dropins.webutil.testutil import requests_response
import requests

from protocol import Protocol
from flask_app import app
from models import Follower, Object, User

from .test_activitypub import ACTOR, REPLY
from . import testutil
from .testutil import FakeProtocol

REPLY = {
    **REPLY,
    'actor': ACTOR,
    'object': {
        **REPLY['object'],
        'author': ACTOR,
    },
}


class ProtocolTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('foo.com', has_hcard=True)
        self.app_context = app.test_request_context('/')
        self.app_context.__enter__()
        g.user = None

    def tearDown(self):
        self.app_context.__exit__(None, None, None)
        super().tearDown()

    @patch('requests.get')
    def test_receive_reply_not_feed_not_notification(self, mock_get):
        Follower.get_or_create(ACTOR['id'], 'foo.com')

        # user.com webmention discovery
        mock_get.return_value = requests_response('<html></html>')

        Protocol.receive(REPLY['id'], as2=REPLY)

        self.assert_object(REPLY['id'],
                           as2=REPLY,
                           type='post',
                           domains=['user.com'],
                           # not feed since it's a reply
                           # not notification since it doesn't involve the user
                           labels=['activity'],
                           status='complete',
                           )
        self.assert_object(REPLY['object']['id'],
                           as2=REPLY['object'],
                           type='comment',
                           )

    def test_load(self):
        FakeProtocol.objects['foo'] = {'x': 'y'}

        loaded = FakeProtocol.load('foo')
        self.assert_equals({'x': 'y'}, loaded.our_as1)
        self.assertFalse(loaded.changed)
        self.assertTrue(loaded.new)

        self.assertIsNotNone(Object.get_by_id('foo'))
        self.assertEqual(['foo'], FakeProtocol.fetched)

    def test_load_already_stored(self):
        stored = Object(id='foo', our_as1={'x': 'y'})
        stored.put()

        loaded = FakeProtocol.load('foo')
        self.assert_equals({'x': 'y'}, loaded.our_as1)
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)

        self.assertEqual([], FakeProtocol.fetched)

    @patch('requests.get')
    def test_load_empty_deleted(self, mock_get):
        stored = Object(id='foo', deleted=True)
        stored.put()

        loaded = FakeProtocol.load('foo')
        self.assert_entities_equal(stored, loaded)
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)

        self.assertEqual([], FakeProtocol.fetched)

    @patch('requests.get')
    def test_load_refresh_unchanged(self, mock_get):
        obj = Object(id='foo', our_as1={'x': 'stored'})
        obj.put()
        FakeProtocol.objects['foo'] = {'x': 'stored'}

        loaded = FakeProtocol.load('foo', refresh=True)
        self.assert_entities_equal(obj, loaded)
        self.assertFalse(obj.changed)
        self.assertFalse(obj.new)
        self.assertEqual(['foo'], FakeProtocol.fetched)

    @patch('requests.get')
    def test_load_refresh_changed(self, mock_get):
        Object(id='foo', our_as1={'content': 'stored'}).put()
        FakeProtocol.objects['foo'] = {'content': 'new'}

        loaded = FakeProtocol.load('foo', refresh=True)
        self.assert_equals({'content': 'new'}, loaded.our_as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['foo'], FakeProtocol.fetched)
