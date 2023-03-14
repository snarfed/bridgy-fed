"""Unit tests for protocol.py."""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import requests_response
import requests

from protocol import Protocol
from app import app
from models import Follower, Object, User

from .test_activitypub import ACTOR, REPLY
from . import testutil


class ProtocolTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('foo.com', has_hcard=True)
        self.app_context = app.test_request_context('/')
        self.app_context.__enter__()

    def tearDown(self):
        self.app_context.__exit__(None, None, None)
        super().tearDown()

    @patch('requests.get')
    def test_receive_reply_dont_deliver_to_followers(self, mock_get):
        Follower.get_or_create('or.ig', ACTOR['id'])

        # or.ig webmention discovery
        mock_get.return_value = requests_response('<html></html>')

        reply = {
            **REPLY,
            'actor': ACTOR,
            'object': {
                **REPLY['object'],
                'author': ACTOR,
            },
        }
        Protocol.receive(reply['id'], user=self.user, as2=reply)

        self.assert_object(reply['id'],
                           as2=reply,
                           type='post',
                           domains=['or.ig'],
                           labels=['notification', 'activity'],
                           status='complete',
                           )
        self.assert_object(reply['object']['id'],
                           as2=reply['object'],
                           type='comment',
                           )
