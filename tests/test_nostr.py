"""Unit tests for nostr.py."""
from unittest import skip
from unittest.mock import patch

from google.cloud import ndb
import granary.nostr
from granary.nostr import (
    KIND_AUTH,
    KIND_CONTACTS,
    KIND_DELETE,
    KIND_NOTE,
    KIND_PROFILE,
    KIND_RELAYS,
)
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
from secp256k1 import PrivateKey, PublicKey
from websockets.exceptions import ConnectionClosedOK, WebSocketException

import common
from flask_app import app
import ids
from ids import translate_handle, translate_object_id, translate_user_id
from models import Object, Target
import nostr
from nostr import Nostr
from web import Web

from granary.tests.test_nostr import (
    FakeConnection,
    ID,
    NOTE_NOSTR,
    NOW_TS,
    NPUB_URI,
    PRIVKEY,
    PUBKEY,
    URI,
)
from .testutil import Fake, TestCase


class NostrTest(TestCase):

    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

        self.key = PrivateKey(bytes.fromhex(PRIVKEY))
        self.user = self.make_user(
            'fake:user', cls=Fake, nostr_key_bytes=self.key.private_key,
            enabled_protocols=['nostr'],
            copies=[Target(uri=NPUB_URI, protocol='nostr')])

    def test_pre_put_hook(self):
        Nostr(id='nostr:npub123').put()

        with self.assertRaises(AssertionError):
            Nostr(id='foo').put()

    def test_hex_pubkey(self):
        self.assertEqual(PUBKEY, Nostr(id=NPUB_URI).hex_pubkey())

    def test_npub(self):
        self.assertEqual(NPUB_URI, Nostr(id=NPUB_URI).npub())

    def test_id_uri(self):
        self.assertEqual('nostr:npub123', Nostr(id='npub123').id_uri())

    def test_web_url(self):
        self.assertIsNone(Nostr().web_url())
        self.assertEqual('https://coracle.social/people/nprofile123',
                         Nostr(obj_key=Object(id='nostr:nprofile123').key).web_url())

    def test_handle(self):
        self.assertIsNone(Nostr().handle)

        for expected, event in (
                (None, {'kind': KIND_NOTE}),
                (None, {'kind': KIND_NOTE, 'content': 'foo'}),
                (None, {'kind': KIND_NOTE, 'content': '{"nip05":"foo"}'}),
                (None, {'kind': KIND_PROFILE, 'content': '{"name":"Alice"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"foo"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"_@foo"}'}),
        ):
            with self.subTest(event=event):
                obj = Object(id='x', nostr={**event, 'pubkey': PUBKEY})
                self.assertEqual(expected, Nostr(obj_key=obj.put()).handle)

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
            'kind': KIND_PROFILE,
            'id': 'ad2022ba75a10fb2963005f14ce69ef66b466ebd4a13100d86200dcb818bcb2e',
            'pubkey': PUBKEY,
            'content': json_dumps({
                'name': 'Alice',
                'about': 'It me',
                'picture': 'http://alice/pic',
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
            'kind': KIND_NOTE,
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
            'kind': KIND_CONTACTS,
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

    def test_convert_note_from_user_sign(self):
        got = Nostr._convert(Object(our_as1={
            'objectType': 'note',
            'id': 'fake:post',
            'author': NPUB_URI,
            'content': 'Something to say',
            'published': '2022-01-02T03:04:05+00:00',
        }), from_user=self.user)
        self.assert_equals({
            'kind': KIND_NOTE,
            'id': '4a57c7a1dde3bfe13076db485c4f09756e54447f6389dbf6864d4139bc40a214',
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': NOW_TS,
            'tags': [],
            'sig': '65b42db33486f669fa4dff3dba2ed914dcda886d47177a747e5e574e1a87cd4da23b54350dba758ecd91d48625f5345c8516458c76bebf60b0de89d12fa76a11',
        }, got)
        self.assertTrue(granary.nostr.verify(got))

    def test_send_note(self):
        obj = Object(id='fake:note', our_as1={
            'objectType': 'note',
            'author': 'fake:user',
            'content': 'Something to say',
            'published': '2019-12-02T03:04:05+00:00',
        })

        id = '941a6c6fe92768bc9935ad2fe8f29df4934d551b63f4e7c6038df758c0a5602f'
        expected = {
            'kind': KIND_NOTE,
            'id': id,
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': 1575255845,
            'tags': [],
            'sig': '43bfafe0b0b6911ee0246906e23fb7eb857be1daa8cafdd521ad9eb33d0da981435f9b0adda92917881de5373baa64a5c2db11ab9c29b2ef2edfa94463261a14',
        }
        FakeConnection.to_receive = [
            ['OK', id, True],
        ]

        self.assertTrue(Nostr.send(obj, 'TODO relay', from_user=self.user))
        self.assert_equals([['EVENT', expected]], FakeConnection.sent)
        self.assertTrue(granary.nostr.verify(expected))
        self.assertEqual(granary.nostr.id_to_uri('note', id), obj.get_copy(Nostr))

    @patch('secp256k1._gen_private_key', return_value=bytes.fromhex(PRIVKEY))
    def test_create_for(self, _):
        alice = self.make_user(
            'fake:alice', cls=Fake,
            obj_as1={'objectType': 'person', 'displayName': 'Alice'})
        self.assertIsNone(alice.nostr_key_bytes)

        profile_id = '8be34ca85471dcb2306ca005182d4468eede8e3a979f84b80f1a9616e84f4c74'
        FakeConnection.to_receive = [
            ['OK', profile_id, True],
        ]

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertEqual(PRIVKEY, alice.nostr_key_bytes.hex())
        self.assertEqual(NPUB_URI, alice.get_copy(Nostr))
        self.assertEqual(granary.nostr.id_to_uri('nprofile', profile_id),
                         alice.obj.get_copy(Nostr))

        self.assertEqual([['EVENT', {
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'id': profile_id,
            'sig': '54173e03ea1608c1c99b40532a68c824c3e2558628286d13271277f8811d08823484d4708a299182310c2a5480aa3966772c99214531937437fc900a361288f0',
            'content': json_dumps({'name':'Alice'}),
            'created_at': NOW_TS,
            'tags': [],
        }]], FakeConnection.sent)

    def test_create_for_already_has_nostr_copy(self):
        alice = self.make_user('fake:user3', cls=Fake,
                                   copies=[Target(uri='nostr:npub123', protocol='nostr')])

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertIsNone(alice.nostr_key_bytes)
        self.assertEqual(0, len(FakeConnection.sent))

    def test_create_for_existing_key_no_copy(self):
        alice = self.make_user('fake:user4', cls=Fake,
                                   nostr_key_bytes=self.key.private_key,
                                   obj_as1={'objectType': 'person', 'displayName': 'Charlie'})

        FakeConnection.to_receive = [
            ['OK', 'fakeid', True],
        ]

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertEqual(self.key.private_key, alice.nostr_key_bytes)

        self.assertEqual(1, len(FakeConnection.sent))
        event_type, event = FakeConnection.sent[0]
        self.assertEqual('EVENT', event_type)
        self.assertEqual(PUBKEY, event['pubkey'])

    def test_create_for_profile_already_copied(self):
        alice = self.make_user('fake:user5', cls=Fake,
                                   obj_as1={'objectType': 'person', 'displayName': 'David'})
        alice.obj.copies = [Target(uri='nostr:nevent123', protocol='nostr')]
        alice.obj.put()

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertIsNotNone(alice.nostr_key_bytes)
        self.assertEqual(1, len([c for c in alice.copies if c.protocol == 'nostr']))
        self.assertEqual(0, len(FakeConnection.sent))

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_fetch_note(self, _):
        FakeConnection.to_receive = [
            ['EVENT', 'towkin', NOTE_NOSTR],
            ['EOSE', 'towkin'],
        ]

        obj = Object(id=URI)
        self.assertTrue(Nostr.fetch(obj))
        self.assertEqual(NOTE_NOSTR, obj.nostr)
        self.assertEqual([
            ['REQ', 'towkin', {'ids': [ID], 'limit': 20}],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_fetch_npub(self, _):
        FakeConnection.to_receive = [
            ['EVENT', 'towkin', NOTE_NOSTR],
            ['EOSE', 'towkin'],
        ]

        obj = Object(id=NPUB_URI)
        self.assertTrue(Nostr.fetch(obj))
        self.assertEqual(NOTE_NOSTR, obj.nostr)
        self.assertEqual([
            ['REQ', 'towkin', {'authors': [PUBKEY], 'kinds': [0], 'limit': 20}],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_fetch_not_found(self, _):
        FakeConnection.to_receive = [
            ['EOSE', 'towkin'],
        ]

        obj = Object(id=URI)
        self.assertFalse(Nostr.fetch(obj))
        self.assertIsNone(obj.nostr)
        self.assertEqual([
            ['REQ', 'towkin', {'ids': [ID], 'limit': 20}],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

    def test_fetch_error(self):
        FakeConnection.send_err = WebSocketException('Failed to connect')

        obj = Object(id=URI)
        with self.assertRaises(WebSocketException):
            Nostr.fetch(obj)

        self.assertIsNone(obj.nostr)

    def test_fetch_invalid_id(self):
        for id in '', 'not-a-nostr-id', 'https://example.com':
            with self.subTest(id=id):
                self.assertFalse(Nostr.fetch(Object(id=id)))

    def test_nip_05_fake_user(self):
        user = self.make_user('fake:alice', cls=Fake, enabled_protocols=['nostr'],
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=fake:alice',
                        base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'fake:alice': PUBKEY},
        }, resp.json)

    def test_nip_05_web_user(self):
        user = self.make_user('user.com', cls=Web, enabled_protocols=['nostr'],
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=user.com',
                        base_url='https://web.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'user.com': PUBKEY},
        }, resp.json)

    def test_nip_05_fake_user_by_handle(self):
        user = self.make_user('fake:bob', cls=Fake, enabled_protocols=['nostr'],
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=fake:handle:bob',
                        base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'fake:handle:bob': PUBKEY},
        }, resp.json)

    def test_nip_05_user_nostr_not_enabled(self):
        user = self.make_user('fake:disabled', cls=Fake,
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=fake:disabled',
                        base_url='https://fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_nip_05_no_nostr_copy(self):
        user = self.make_user('fake:charlie', cls=Fake, enabled_protocols=['nostr'])

        resp = self.get('/.well-known/nostr.json?name=fake:charlie',
                        base_url='https://fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_nip_05_user_not_found(self):
        resp = self.get('/.well-known/nostr.json?name=fake:nonexistent',
                        base_url='https://fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_nip_05_missing_name_param(self):
        resp = self.get('/.well-known/nostr.json', base_url='https://fa.brid.gy')
        self.assertEqual(400, resp.status_code)

    def test_nip_05_native_nostr_user_ignored(self):
        nostr_user = self.make_user('nostr:npub123', cls=Nostr)

        for name in ('npub123', 'nostr:npub123'):
            with self.subTest(name=name):
                resp = self.get(f'/.well-known/nostr.json?name={name}',
                                base_url='https://nostr.brid.gy')
                self.assertEqual(404, resp.status_code)

    def test_target_for_existing_user(self):
        relay_list = Object(id='nostr:nevent123', nostr={
            'kind': 10002,
            'tags': [
                ['r', 'wss://a', 'read'],
                ['r', 'wss://b'],
            ],
        })
        relay_list.put()
        self.make_user(NPUB_URI, cls=Nostr, relay_list=relay_list.key)

        self.assertEqual('wss://b', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

        relay_list.nostr['tags'] = [
            ['r', 'wss://a', 'read'],
            ['r', 'wss://c', 'write'],
            ['r', 'wss://b'],
        ]
        relay_list.put()
        self.assertEqual('wss://c', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    @skip  # TODO
    def test_target_for_fetch_user(self):
        self.assertEqual('wss://a', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    def test_target_for_no_relay_list_object(self):
        self.make_user(NPUB_URI, cls=Nostr)
        self.assertIsNone(Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    def test_target_for_no_author(self):
        self.assertIsNone(Nostr.target_for(Object(our_as1={
            'objectType': 'note',
            'content': 'Hello world',
        })))

    def test_target_for_no_as1(self):
        self.assertIsNone(Nostr.target_for(Object()))
