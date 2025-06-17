"""Unit tests for nostr.py."""
import copy
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
    KIND_REPOST,
    id_and_sign,
)
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil import util
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
    NOTE_AS1,
    NOTE_NOSTR,
    NOW_TS,
    NPUB_URI,
    NSEC_URI,
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
        self.assertEqual('npub123', Nostr(id='nostr:npub123').npub())

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
                (None, {'kind': KIND_PROFILE}),
                (None, {'kind': KIND_NOTE, 'content': 'foo'}),
                (None, {'kind': KIND_NOTE, 'content': '{"nip05":"foo"}'}),
                (None, {'kind': KIND_PROFILE, 'content': '{"name":"Alice"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"foo"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"_@foo"}'}),
        ):
            with self.subTest(event=event):
                obj = Object(id='x', nostr={**event, 'pubkey': PUBKEY})
                user = Nostr(obj_key=obj.put())
                self.assertEqual(expected, user.handle)
                if expected is None:
                    user.key = ndb.Key(Nostr, 'nostr:npub123')
                    self.assertEqual('npub123', user.handle)

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

    def test_handle_as_domain(self):
        self.assertEqual('npub789', Nostr(id='nostr:npub789').handle_as_domain)

        profile = Object(id='x', nostr={
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({'nip05': '_@x.y'}),
        })
        user = Nostr(id='nostr:npub789', obj_key=profile.put())
        self.assertEqual('x.y', user.handle_as_domain)

        profile.nostr['content'] = json_dumps({'nip05': 'a@x.y'})
        self.assertEqual('a.x.y', user.handle_as_domain)

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
            'summary': 'It me',
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

    def test_convert_reply(self):
        Object(id=URI, nostr={
            'kind': KIND_NOTE,
            'pubkey': 'abc123',  # npub140qjxm63yry
        }).put()
        relays = Object(id='nostr:nevent123', nostr={
            'kind': KIND_RELAYS,
            'tags': [['r', 'reelaay']],
        }).put()
        Nostr(id='nostr:npub140qjxm63yry', relays=relays).put()

        self.assert_equals({
            'kind': KIND_NOTE,
            'id': 'ddaa744f04433c978af112e5b9d1affb514a745e4734c267bcd54492b02ba908',
            'pubkey': PUBKEY,
            'content': 'I hereby reply',
            'tags': [
                ['e', ID, 'reelaay', 'reply'],
            ],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'note',
            'id': 'http://foo/bar',
            'author': NPUB_URI,
            'content': 'I hereby reply',
            'inReplyTo': URI,
        })))

    def test_convert_repost(self):
        Object(id=NOTE_AS1['id'], nostr=NOTE_NOSTR).put()
        relays = Object(id='nostr:nevent123', nostr={
            'kind': KIND_RELAYS,
            'tags': [['r', 'reelaay']],
        }).put()
        Nostr(id=NPUB_URI, relays=relays).put()

        note_event = copy.copy(NOTE_NOSTR)
        del note_event['sig']
        self.assert_equals({
            'kind': KIND_REPOST,
            'id': 'ac3f207afeb7687fe71522fb350dd983ac388d6bf5e85079b9edb2a7cd4f956c',
            'pubkey': 'abc123',  # npub140qjxm63yry,
            'content': json_dumps(note_event, sort_keys=True),
            'tags': [
                # id for Nostr version of original post object, below
                ['e', NOTE_NOSTR['id'], 'reelaay', 'mention'],
                ['p', PUBKEY],
            ],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'http://foo/bar',
            'author': 'nostr:npub140qjxm63yry',
            'content': 'I hereby reply',
            'object': NOTE_AS1,
        })))

    def test_convert_follow(self):
        relays = Object(id='nostr:nevent123', nostr={
            'kind': KIND_RELAYS,
            'tags': [['r', 'reelaay']],
        }).put()
        Nostr(id='nostr:npub1xnxsce33j3', relays=relays).put()

        self.assert_equals({
            'kind': KIND_CONTACTS,
            'id': 'b772f7125a61bdce7cbce6925dd73d66914a3451655a7c3469cbac0626da9d82',
            'pubkey': PUBKEY,
            'content': 'not important',
            'tags': [
                ['p', '34cd', 'reelaay', ''],
                ['p', '98fe', 'reelaay', 'bob'],
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

        self.assertTrue(Nostr.send(obj, 'reeelaaay', from_user=self.user))
        self.assert_equals(['reeelaaay'], FakeConnection.relays)
        self.assert_equals([['EVENT', expected]], FakeConnection.sent)
        self.assertTrue(granary.nostr.verify(expected))
        self.assertEqual(
            [Target(uri=granary.nostr.id_to_uri('note', id), protocol='nostr')],
            obj.key.get().copies)

    def test_send_profile_has_existing_copy(self):
        obj = Object(id='fake:note',
                     copies=[Target(uri='nostr:nprofile123', protocol='nostr')],
                     our_as1={
                         'objectType': 'person',
                         'displayName': 'alice',
                     })
        obj.put()

        id = '8ad830634299733997c828ba094b995a1a1aad8ca7607ff44e268afb83a29da9'
        expected = {
            'kind': KIND_PROFILE,
            'id': id,
            'pubkey': PUBKEY,
            'content': json_dumps({
                'about': '🌉 bridged from fake:note by https://fed.brid.gy/',
                'name': 'alice',
            }, ensure_ascii=False),
            'created_at': 1641092645,
            'tags': [],
        }
        FakeConnection.to_receive = [
            ['OK', id, True],
        ]

        self.assertTrue(Nostr.send(obj, 'reeelaaay', from_user=self.user))
        self.assert_equals(['reeelaaay'], FakeConnection.relays)
        self.assert_equals([['EVENT', expected]], FakeConnection.sent,
                           ignore=['sig'])
        self.assertEqual(
            [Target(uri=granary.nostr.id_to_uri('nprofile', id), protocol='nostr')],
            obj.key.get().copies)

    @patch('secp256k1._gen_private_key', return_value=bytes.fromhex(PRIVKEY))
    def test_create_for(self, _):
        alice = self.make_user('fake:alice', cls=Fake, obj_as1={
            'objectType': 'person',
            'displayName': 'Alice',
            'summary': 'foo bar'
        })
        self.assertIsNone(alice.nostr_key_bytes)

        profile_id = 'c3f5ade6dc03c6d802bb3188567ee2f9c6424c7552d58ed7c4551c1c7e356c2d'
        FakeConnection.to_receive = [
            ['OK', profile_id, True],
        ]

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertEqual(PRIVKEY, alice.nostr_key_bytes.hex())
        self.assertEqual(NPUB_URI, alice.get_copy(Nostr))
        # self.assertEqual(granary.nostr.id_to_uri('nprofile', profile_id),
        #                  alice.obj.get_copy(Nostr))

        self.assert_equals([['EVENT', {
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'id': profile_id,
            'content': json_dumps({
                'about': 'foo bar\n\n🌉 bridged from web:fake:alice on fake-phrase by https://fed.brid.gy/',
                'name':'Alice',
            }, ensure_ascii=False),
            'created_at': NOW_TS,
            'tags': [],
        }]], FakeConnection.sent, ignore=['id', 'sig'])

    def test_create_for_already_has_nostr_copy(self):
        alice = self.make_user('fake:user3', cls=Fake,
                                   copies=[Target(uri='nostr:npub123', protocol='nostr')])

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertIsNone(alice.nostr_key_bytes)
        self.assertEqual(0, len(FakeConnection.sent))

    def test_create_for_existing_key_no_copy(self):
        alice = self.make_user('fake:user4', cls=Fake,
                               nostr_key_bytes=self.key.private_key, obj_as1={
                                   'objectType': 'person',
                                   'displayName': 'Charlie',
                               })

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
        alice = self.make_user('fake:user5', cls=Fake, obj_as1={
            'objectType': 'person',
            'displayName': 'David',
        })
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

    def test_nip_05_fake_user_by_handle(self):
        user = self.make_user('fake:alice', cls=Fake, enabled_protocols=['nostr'],
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])
        self.assertEqual('fake-handle-alice', user.handle_as_domain)

        resp = self.get('/.well-known/nostr.json?name=fake-handle-alice',
                        base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'fake-handle-alice': PUBKEY},
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

    def test_nip_05_user_nostr_not_enabled(self):
        user = self.make_user('fake:disabled', cls=Fake,
                             copies=[Target(uri=NPUB_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=fake:disabled',
                        base_url='https://fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_nip_05_no_nostr_copy(self):
        user = self.make_user('fake:charlie', cls=Fake, enabled_protocols=['nostr'])

        resp = self.get('/.well-known/nostr.json?name=fake-handle-charlie',
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

        for name in ('npub123', 'nostr:npub123', 'nostr-npub123'):
            with self.subTest(name=name):
                resp = self.get(f'/.well-known/nostr.json?name={name}',
                                base_url='https://nostr.brid.gy')
                self.assertEqual(404, resp.status_code)

    def test_target_for_existing_user(self):
        relays = Object(id='nostr:nevent123', nostr={
            'kind': KIND_RELAYS,
            'tags': [
                ['r', 'wss://a', 'read'],
                ['r', 'wss://b'],
            ],
        })
        relays.put()
        self.make_user(NPUB_URI, cls=Nostr, relays=relays.key)

        self.assertEqual('wss://b', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

        relays.nostr['tags'] = [
            ['r', 'wss://a', 'read'],
            ['r', 'wss://c', 'write'],
            ['r', 'wss://b'],
        ]
        relays.put()
        self.assertEqual('wss://c', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    def test_target_for_no_relays_object(self):
        self.make_user(NPUB_URI, cls=Nostr)
        self.assertIsNone(Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    def test_target_for_no_author(self):
        self.assertIsNone(Nostr.target_for(Object(our_as1={
            'objectType': 'note',
            'content': 'Hello world',
        })))

    def test_target_for_no_as1(self):
        self.assertIsNone(Nostr.target_for(Object()))

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_reload_profile(self, _):
        profile = id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({
                'name': 'Alice',
                'about': 'Test user',
                'picture': 'http://alice/pic',
            }),
            'created_at': NOW_TS,
            'tags': [],
        }, privkey=NSEC_URI)
        relays = id_and_sign({
            'kind': KIND_RELAYS,
            'pubkey': PUBKEY,
            'content': '',
            'created_at': NOW_TS,
            'tags': [
                ['r', 'wss://a', 'read'],
                ['r', 'wss://b'],
            ],
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'towkin', profile],
            ['EVENT', 'towkin', relays],
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=NPUB_URI)
        user.reload_profile()

        self.assertEqual([
            ['REQ', 'towkin', {
                'authors': [PUBKEY],
                'kinds': [KIND_PROFILE, KIND_RELAYS],
                'limit': 20,
            }],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

        self.assertEqual(profile, user.obj_key.get().nostr)
        self.assertEqual(relays, user.relays.get().nostr)
        self.assertEqual('wss://b', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_reload_profile_no_events(self, _):
        FakeConnection.to_receive = [
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=NPUB_URI)
        user.reload_profile()

        self.assertIsNone(user.obj_key)
        self.assertIsNone(user.relays)
        self.assertIsNone(Nostr.target_for(Object(nostr=NOTE_NOSTR)))
