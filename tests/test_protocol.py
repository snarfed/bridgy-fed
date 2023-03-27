"""Unit tests for protocol.py."""
from unittest.mock import patch

from flask import g
from oauth_dropins.webutil.testutil import requests_response
import requests

from protocol import Protocol
from app import app
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

    def test_get_object(self):
        obj = Object(id='foo', our_as1={'x': 'y'})
        FakeProtocol.objects = {'foo': obj}
        self.assert_entities_equal(obj, FakeProtocol.get_object('foo'))
        self.assertIsNotNone(Object.get_by_id('foo'))
        self.assertEqual(['foo'], FakeProtocol.fetched)

    def test_get_object_already_stored(self):
        stored = Object(id='foo', our_as1={'x': 'y'})
        stored.put()
        self.assert_entities_equal(stored, FakeProtocol.get_object('foo'))
        self.assertEqual([], FakeProtocol.fetched)
