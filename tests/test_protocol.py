"""Unit tests for protocol.py."""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import requests_response
import requests

from protocol import Protocol
from app import app
from models import Follower, Object, User

from .test_activitypub import ACTOR, REPLY
from . import testutil

REPLY = {
    **REPLY,
    'actor': ACTOR,
    'object': {
        **REPLY['object'],
        'author': ACTOR,
        # 'inReplyTo': 'http://th.is/orig/post',
    },
}


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
    def test_receive_reply_not_feed_not_notification(self, mock_get):
        Follower.get_or_create(ACTOR['id'], 'foo.com')

        # or.ig webmention discovery
        mock_get.return_value = requests_response('<html></html>')

        Protocol.receive(REPLY['id'], user=self.user, as2=REPLY)

        self.assert_object(REPLY['id'],
                           as2=REPLY,
                           type='post',
                           domains=['or.ig'],
                           # not feed since it's a reply
                           # not notification since it doesn't involve the user
                           labels=['activity'],
                           status='complete',
                           )
        self.assert_object(REPLY['object']['id'],
                           as2=REPLY['object'],
                           type='comment',
                           )
