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
from web import Web

from .testutil import ATPROTO_KEY, TestCase
from . import test_atproto
from . import test_web

DID_DOC = {
    **test_atproto.DID_DOC,
    'id': 'did:plc:alice',
    'alsoKnownAs': ['at://alice.com'],
}


class IntegrationTests(TestCase):

    @patch('requests.post')
    @patch('requests.get')
    @patch('common.ENABLED_BRIDGES', new=[('activitypub', 'atproto')])
    def test_atproto_notify_reply_to_activitypub(self, mock_get, mock_post):
        """ATProto poll notifications, deliver reply to ActivityPub.

        ActivityPub original post http://inst/post by bob
        ATProto reply 123 by alice.com (did:plc:alice)

        https://github.com/snarfed/bridgy-fed/issues/720
        """
        # setup
        self.store_object(id='did:plc:alice', raw=DID_DOC)
        alice = self.make_user(id='did:plc:alice', cls=ATProto)

        storage = DatastoreStorage()
        Repo.create(storage, 'did:plc:bob', signing_key=ATPROTO_KEY)
        bob = self.make_user(
            id='http://inst/bob',
            cls=ActivityPub,
            copies=[Target(uri='did:plc:bob', protocol='atproto')],
            obj_as2={
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
                        'handle': 'alice.com',
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

        web_test = test_web.WebTest()
        web_test.user = alice
        web_test.assert_deliveries(mock_post, ['http://inst/bob/inbox'], data={
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

    @patch('requests.post', return_value=requests_response(''))
    @patch('requests.get')
    def test_atproto_follow_to_web(self, mock_get, mock_post):
        """ATProto poll notifications, deliver follow to Web.

        ATProto user alice.com (did:plc:alice)
        ATProto follow at://did:plc:alice/app.bsky.graph.follow/123
        Web user bob.com
        """
        # setup
        self.store_object(id='did:plc:alice', raw=DID_DOC)
        alice = self.make_user(id='did:plc:alice', cls=ATProto)

        storage = DatastoreStorage()
        Repo.create(storage, 'did:plc:bob', signing_key=ATPROTO_KEY)
        bob = self.make_user(id='bob.com', cls=Web,
                             copies=[Target(uri='did:plc:bob', protocol='atproto')])

        # ATProto listNotifications => receive
        mock_get.side_effect = [
            # ATProto listNotifications
            requests_response({
                'cursor': '...',
                'notifications': [{
                    'uri': 'at://did:plc:alice/app.bsky.graph.follow/123',
                    'cid': '...',
                    'author': {
                        '$type': 'app.bsky.actor.defs#profileView',
                        'did': 'did:plc:alice',
                        'handle': 'alice.com',
                    },
                    'reason': 'follow',
                    'record': {
                        '$type': 'app.bsky.graph.follow',
                        'subject': 'did:plc:bob',
                        'createdAt': '2022-01-02T03:04:05.000Z',
                    },
                }],
            }),
            # webmention discovery
            test_web.WEBMENTION_REL_LINK,
        ]

        resp = self.post('/queue/atproto-poll-notifs', client=hub.app.test_client())
        self.assertEqual(200, resp.status_code)

        self.assert_req(mock_get, 'https://bob.com/')
        self.assert_req(mock_post, 'https://bob.com/webmention', data={
            'source': 'https://atproto.brid.gy/convert/web/at://did:plc:alice/app.bsky.graph.follow/123',
            'target': 'https://bob.com/',
        }, allow_redirects=False, headers={'Accept': '*/*'})
