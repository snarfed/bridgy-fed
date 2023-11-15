"""Integration tests."""
from unittest.mock import patch

from arroba.datastore_storage import DatastoreStorage
from arroba.repo import Repo
from flask import g
from oauth_dropins.webutil.testutil import requests_response

from activitypub import ActivityPub
import app
from atproto import ATProto
import hub
from models import Target

from .testutil import ATPROTO_KEY, TestCase
from . import test_atproto
from . import test_web

DID_DOC = {
    **test_atproto.DID_DOC,
    'id': 'did:plc:alice',
}


class IntegrationTests(TestCase):

    @patch('requests.post')
    @patch('requests.get')
    def test_atproto_notify_reply_to_activitypub(self, mock_get, mock_post):
        """ATProto poll notifications, deliver reply to ActivityPub.

        ActivityPub original post http://inst/post by bob
        ATProto reply 123 by alice

        https://github.com/snarfed/bridgy-fed/issues/720
        """
        # setup
        self.store_object(id='did:plc:alice', raw=DID_DOC)
        alice = self.make_user(id='did:plc:alice', cls=ATProto)

        storage = DatastoreStorage()
        Repo.create(storage, 'did:plc:bob', signing_key=ATPROTO_KEY)
        bob = self.make_user(id='http://inst/bob', cls=ActivityPub,
                             atproto_did='did:plc:bob', obj_as2={
                                 'id': 'http://inst/bob',
                                 'inbox': 'http://inst/bob/inbox',
                             })

        self.store_object(id='http://inst/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'http://inst/bob',
                          },
                          copies=[
            Target(uri='at://did:plc:bob/app.bsky.feed.post/123', protocol='atproto'),
        ])

        # ATProto listNotifications => receive
        mock_get.side_effect = [
            requests_response({
                'cursor': '...',
                'notifications': [{
                    'uri': 'at://did:plc:alice/app.bsky.feed.post/456',
                    'cid': '...',
                    'author': {
                        '$type': 'app.bsky.actor.defs#profileView',
                        'did': 'did:plc:alice',
                        'handle': 'alice',
                    },
                    'reason': 'reply',
                    'record': {
                        '$type': 'app.bsky.feed.post',
                        'text': 'I hereby reply',
                        'reply': {
                            'root': {
                                'cid': '...',
                                'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                            },
                            'parent': {
                                'cid': '...',
                                'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                            }
                        },
                    },
                }],
            }),
        ]

        resp = self.post('/queue/atproto-poll-notifs', client=hub.app.test_client())
        self.assertEqual(200, resp.status_code)

        g.user = alice
        test_web.WebTest().assert_deliveries(mock_post, ['http://inst/bob/inbox'], data={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'https://atproto.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/456#bridgy-fed-create',
            'actor': 'https://atproto.brid.gy/ap/did:plc:alice',
            'published': '2022-01-02T03:04:05+00:00',
            'object': {
                'type': 'Note',
                'id': 'https://atproto.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/456',
                'url': 'http://localhost/r/https://bsky.app/profile/did:plc:alice/post/456',
                'attributedTo': 'https://atproto.brid.gy/ap/did:plc:alice',
                'content': 'I hereby reply',
                'contentMap': {'en': 'I hereby reply'},
                'inReplyTo': 'http://inst/post',
                'tag': [{'type': 'Mention', 'href': 'http://inst/bob'}],
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
                'cc': ['http://inst/bob'],
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        })
