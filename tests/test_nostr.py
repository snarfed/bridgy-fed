"""Unit tests for nostr.py."""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from flask_app import app
import ids
from ids import translate_handle, translate_object_id, translate_user_id
from models import Object, Target
from nostr import Nostr
from .testutil import Fake, TestCase

from granary.tests.test_nostr import NOW_TS, NPUB_URI, PUBKEY


class NostrTest(TestCase):

    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

    def test_id_uri(self):
        self.assertEqual('nostr:npub123', Nostr(id='npub123').id_uri())

    def test_web_url(self):
        self.assertIsNone(Nostr().web_url())
        self.assertEqual('https://coracle.social/people/nprofile123',
                         Nostr(obj_key=Object(id='nostr:nprofile123').key).web_url())

    def test_bridged_web_url_for(self):
        self.assertIsNone(Nostr.bridged_web_url_for(Nostr()))
        self.assertIsNone(Nostr.bridged_web_url_for(Fake()))

        obj = self.store_object(
            id='fake:profile',
            copies=[Target(uri='nostr:nprofile123', protocol='nostr')])
        self.assertEqual('https://coracle.social/people/nprofile123',
                         Nostr.bridged_web_url_for(Fake(obj=obj)))

    def test_owns_id(self):
        for id in ('npub23', 'nevent123', 'note123', 'nprofile123', 'naddr123',
                   'nostr:nevent123'):
            with self.subTest(id=id):
                self.assertTrue(Nostr.owns_id(id))

        for id in ('abc', 'did:abc', 'foo.com', 'https://foo.com/',
                   'https://foo.com/bar', 'at://did:abc/x.y.z/123'):
            with self.subTest(id=id):
                self.assertFalse(Nostr.owns_id(id))

    def test_owns_handle(self):
        for handle in ('user@domain', 'user@domain.com', 'user.com@domain.com',
                       'user@domain', 'user@sub.do.main', '_@domain'):
            with self.subTest(handle=handle):
                self.assertTrue(Nostr.owns_handle(handle))

        for handle in ('domain', 'domain.com', '@user', '@user.com',
                       'http://user.com', '@user@web.brid.gy', '@user@domain',
                       '@user@sub.dom.ain', '_@'):
            with self.subTest(handle=handle):
                self.assertEqual(False, Nostr.owns_handle(handle))

    @patch('requests.get', return_value=requests_response({
        'names': {'alice': 'b0635d'},
    }))
    def test_handle_to_id(self, _):
        self.assertEqual('npub1kp346yk70h6', Nostr.handle_to_id('alice@example.com'))

    def test_convert_actor(self):
        self.assert_equals({
            'kind': 0,
            'id': 'b5194395b42eebb7c3dfb9c45be1859d20daf33a95dd05e409c68597689b7a19',
            'pubkey': PUBKEY,
            'content': json_dumps({
                'name': 'Alice',
                'about': 'It me',
                'picture': 'http://alice/pic',
                'nip05': '_@alice',  # TODO
            }, sort_keys=True),
            'tags': [],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'person',
            'id': NPUB_URI,
            'displayName': 'Alice',
            'description': 'It me',
            'image': 'http://alice/pic',
            'username': 'alice',
        })))

    def test_convert_note(self):
        self.assert_equals({
            'kind': 1,
            'id': '4a57c7a1dde3bfe13076db485c4f09756e54447f6389dbf6864d4139bc40a214',
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': NOW_TS,
            'tags': [],
        }, Nostr._convert(Object(our_as1={
            'objectType': 'note',
            'id': 'nostr:note1z24swknlsf',
            'author': NPUB_URI,
            'content': 'Something to say',
            'published': '2022-01-02T03:04:05+00:00',
        })))

    def test_convert_follow(self):
        self.assert_equals({
            'kind': 3,
            'id': 'e65338c8d5529524ba28618367baf052573d57d7646fabb213bf7575bf19cd5f',
            'pubkey': PUBKEY,
            'content': 'not important',
            'tags': [
                ['p', '34cd', 'TODO relay', ''],
                ['p', '98fe', 'TODO relay', 'bob'],
            ],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'nostr:nevent1z24spd6d40',
            'actor': NPUB_URI,
            'published': '2022-01-02T03:04:05+00:00',
            'object': [
                'nostr:npub1xnxsce33j3',
                {'id': 'nostr:npub1nrlqrdny0w', 'displayName': 'bob'},
            ],
            'content': 'not important',
        })))
