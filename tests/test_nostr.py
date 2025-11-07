"""Unit tests for nostr.py."""
import copy
from unittest import skip
from unittest.mock import patch

from google.cloud import ndb
import granary.nostr
from granary.nostr import (
    KIND_ARTICLE,
    KIND_AUTH,
    KIND_CONTACTS,
    KIND_DELETE,
    KIND_NOTE,
    KIND_PROFILE,
    KIND_RELAYS,
    KIND_REPOST,
    id_and_sign,
)
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
from secp256k1 import PrivateKey, PublicKey
from websockets.exceptions import ConnectionClosedOK, WebSocketException

from activitypub import ActivityPub
from atproto import ATProto
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
    NPUB,
    NPUB_URI,
    NPUB_URI_2,
    NSEC_URI,
    NSEC_URI_2,
    PRIVKEY,
    PRIVKEY_2,
    PUBKEY,
    PUBKEY_2,
    PUBKEY_URI,
    PUBKEY_URI_2,
)
from .testutil import ExplicitFake, Fake, TestCase
from .test_atproto import DID_DOC

ID_URI = 'nostr:' + ID


class NostrTest(TestCase):

    def setUp(self):
        super().setUp()
        common.RUN_TASKS_INLINE = False

        self.key = PrivateKey(bytes.fromhex(PRIVKEY))
        self.user = self.make_user(
            'fake:user', cls=Fake, nostr_key_bytes=self.key.private_key,
            enabled_protocols=['nostr'],
            copies=[Target(uri=PUBKEY_URI, protocol='nostr')])

    def test_pre_put_hook(self):
        Nostr(id=ID_URI).put()

        with self.assertRaises(AssertionError):
            Nostr(id='foo').put()

        with self.assertRaises(AssertionError):
            Nostr(id=ID_URI, nostr_key_bytes=b'x').put()

    def test_hex_pubkey(self):
        self.assertEqual(PUBKEY, Nostr(id=PUBKEY_URI).hex_pubkey())

    def test_npub(self):
        self.assertEqual(NPUB, Nostr(id=PUBKEY_URI).npub())

    def test_id_uri(self):
        self.assertEqual(PUBKEY_URI, Nostr(id=PUBKEY_URI).id_uri())

    def test_web_url(self):
        self.assertIsNone(Nostr().web_url())

        user = Nostr(id=PUBKEY_URI, obj_key=Object(id=ID_URI).key)
        self.assertEqual(f'https://coracle.social/people/{NPUB}', user.web_url())

    def test_is_profile(self):
        user = Nostr(id=PUBKEY_URI)

        self.assertFalse(user.is_profile(Object(id='x')))
        self.assertFalse(user.is_profile(Object(id=PUBKEY_URI_2)))

        self.assertTrue(user.is_profile(Object(id=PUBKEY_URI)))

        user.obj_key = Object(id=ID_URI).key
        self.assertTrue(user.is_profile(Object(id=ID_URI)))

        self.assertTrue(user.is_profile(Object(id='unused', nostr={
            'pubkey': user.hex_pubkey(),
            'kind': KIND_PROFILE,
        })))

    def test_nip_05(self):
        self.assertIsNone(Nostr().nip_05())

        for expected, event in (
                (None, {'kind': KIND_PROFILE}),
                (None, {'kind': KIND_PROFILE, 'content': '{"name":"Alice"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"foo"}'}),
                ('_@foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"_@foo"}'}),
                ('a@foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"a@foo"}'}),
        ):
            with self.subTest(event=event):
                obj = Object(id='x', nostr={**event, 'pubkey': PUBKEY})
                self.assertEqual(expected, Nostr(obj_key=obj.put()).nip_05())

        user = Nostr(obj=Object(id='unused', our_as1={'username': 'a@foo'}))
        self.assertEqual('a@foo', user.nip_05())

        user.obj.our_as1['username'] = 'foo'
        self.assertEqual('_@foo', user.nip_05())

    def test_handle(self):
        self.assertIsNone(Nostr().handle)

        for expected, event in (
                (None, {'kind': KIND_PROFILE}),
                (None, {'kind': KIND_PROFILE, 'content': '{"name":"Alice"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"foo"}'}),
                ('foo', {'kind': KIND_PROFILE, 'content': '{"nip05":"_@foo"}'}),
        ):
            with self.subTest(event=event):
                obj = Object(id='x', nostr={**event, 'pubkey': PUBKEY})
                user = Nostr(obj_key=obj.put())
                self.assertEqual(expected, user.handle)
                if expected is None:
                    user.key = ndb.Key(Nostr, PUBKEY_URI)
                    self.assertEqual(NPUB, user.handle)

    def test_bridged_web_url_for(self):
        self.assertIsNone(Nostr.bridged_web_url_for(Nostr()))
        self.assertIsNone(Nostr.bridged_web_url_for(Fake()))

        user = Fake(id='fake:user')
        self.assertIsNone(Nostr.bridged_web_url_for(Fake()))

        user.copies=[Target(uri=PUBKEY_URI, protocol='nostr')]
        self.assertEqual(f'https://coracle.social/people/{NPUB}',
                         Nostr.bridged_web_url_for(user))

    def test_owns_id(self):
        self.assertTrue(Nostr.owns_id(PUBKEY_URI))
        self.assertTrue(Nostr.owns_id(NPUB_URI))

        self.assertIsNone(Nostr.owns_id(PUBKEY))
        self.assertIsNone(Nostr.owns_id(NPUB))

        for id in ('abc', 'did:abc', 'foo.com', 'https://foo.com/',
                   'https://foo.com/bar', 'at://did:abc/x.y.z/123'):
            with self.subTest(id=id):
                self.assertEqual(False, Nostr.owns_id(id))

    def test_owns_handle(self):
        for handle in ('user@domain', 'user@domain.com', 'user.com@domain.com',
                       'user@domain', 'user@sub.do.main', '_@domain'):
            with self.subTest(handle=handle):
                self.assertTrue(Nostr.owns_handle(handle))

        for handle in 'domain.com', 'foo.domain.com':
            with self.subTest(handle=handle):
                self.assertIsNone(Nostr.owns_handle(handle))

        for handle in ('domain', '@user', '@user.com', 'http://user.com',
                       '@user@web.brid.gy', '@user@domain', '@user@sub.dom.ain', '_@'):
            with self.subTest(handle=handle):
                self.assertEqual(False, Nostr.owns_handle(handle))

    @patch('requests.get', return_value=requests_response({
        'names': {'alice': PUBKEY},
        'relays': {PUBKEY: ['wss://nos.lol']},
    }))
    def test_handle_to_id(self, _):
        self.assertEqual(PUBKEY_URI, Nostr.handle_to_id('alice@example.com'))

    def test_handle_as_domain(self):
        self.assertEqual(NPUB, Nostr(id=PUBKEY_URI).handle_as_domain)

        profile = Object(id='x', nostr={
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({'nip05': '_@x.y'}),
        })
        user = Nostr(id=PUBKEY_URI, obj_key=profile.put())
        self.assertEqual('x.y', user.handle_as_domain)

        profile.nostr['content'] = json_dumps({'nip05': 'a@x.y'})
        self.assertEqual('a.x.y', user.handle_as_domain)

    def test_profile_id(self):
        user = Nostr(id=PUBKEY_URI, obj_key=Object(id=ID_URI).key)
        user.put()
        self.assertEqual(ID_URI, user.profile_id())

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
            'id': PUBKEY_URI,
            'displayName': 'Alice',
            'summary': 'It me',
            'image': 'http://alice/pic',
            'username': 'alice',
        })))

    def test_convert_web_user_actor(self):
        user = self.make_user('alice.com', cls=Web, obj_as1={
            'objectType': 'person',
            'displayName': 'Ms Alice',
            'summary': 'It me',
        })

        self.assert_equals({
            'kind': KIND_PROFILE,
            'pubkey': user.hex_pubkey(),
            'content': json_dumps({
                'name': 'Ms Alice',
                'about': 'It me',
                'nip05': 'alice.com@web.brid.gy',
            }, sort_keys=True),
            'tags': [],
            'created_at': NOW_TS,
        }, Nostr.convert(user.obj, from_user=user), ignore=['id', 'sig'])

    def test_convert_activitypub_user_actor(self):
        user = self.make_user('http://in.st/alice', cls=ActivityPub, obj_as2={
            'type': 'Person',
            'id': 'http://in.st/alice',
            'name': 'Ms Alice',
            'summary': 'It me',
            'preferredUsername': 'alice',
        })

        self.assert_equals({
            'kind': KIND_PROFILE,
            'pubkey': user.hex_pubkey(),
            'content': json_dumps({
                'name': 'Ms Alice',
                'about': 'It me\n\n🌉 bridged from ⁂ http://in.st/alice by https://fed.brid.gy/',
                'nip05': 'alice.in.st@ap.brid.gy',
            }, sort_keys=True, ensure_ascii=False),
            'tags': [],
            'created_at': NOW_TS,
        }, Nostr.convert(user.obj, from_user=user), ignore=['id', 'sig'])

    def test_convert_activitypub_instance_actor(self):
        user = self.make_user('http://in.st/actor', cls=ActivityPub, obj_as2={
            'type': 'Person',
            'id': 'http://in.st/actor',
            'name': 'Ms Alice',
            'summary': 'It me',
            'preferredUsername': 'instance-actor',
        })

        self.assert_equals({
            'kind': KIND_PROFILE,
            'pubkey': user.hex_pubkey(),
            'content': json_dumps({
                'name': 'Ms Alice',
                'about': 'It me\n\n🌉 bridged from ⁂ http://in.st/actor by https://fed.brid.gy/',
                'nip05': 'instance-actor.in.st@ap.brid.gy',
            }, sort_keys=True, ensure_ascii=False),
            'tags': [],
            'created_at': NOW_TS,
        }, Nostr.convert(user.obj, from_user=user), ignore=['id', 'sig'])

    def test_convert_atproto_actor(self):
        self.store_object(id='did:plc:alice', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://han.dull'],
        })
        user = self.make_user('did:plc:alice', cls=ATProto, obj_bsky={
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there',
        })

        self.assert_equals({
            'kind': KIND_PROFILE,
            'pubkey': user.hex_pubkey(),
            'content': json_dumps({
                'name': 'Alice',
                'about': 'hi there\n\n🌉 bridged from 🦋 https://bsky.app/profile/han.dull by https://fed.brid.gy/',
                'nip05': 'han.dull@bsky.brid.gy',
                'website':'https://bsky.app/profile/han.dull',
            }, sort_keys=True, ensure_ascii=False),
            'tags': [],
            'created_at': NOW_TS,
        }, Nostr.convert(user.obj, from_user=user), ignore=['id', 'sig'])

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
            'id': ID_URI,
            'author': PUBKEY_URI,
            'content': 'Something to say',
            'published': '2022-01-02T03:04:05+00:00',
        })))

    def test_convert_reply(self):
        note_obj = Object(id=f'nostr:{ID}', nostr={
            'kind': KIND_NOTE,
            'id': ID,
            'pubkey': PUBKEY,
            'content': 'original note',
            'created_at': NOW_TS,
            'tags': [],
        }, source_protocol='nostr')
        note_obj.put()
        relays_obj = Object(id=ID_URI, nostr={
            'kind': KIND_RELAYS,
            'pubkey': PUBKEY,
            'tags': [['r', 'reelaay']],
        }, source_protocol='nostr')
        user = Nostr(id=PUBKEY_URI, relays=relays_obj.put())
        user.put()

        self.assert_equals({
            'kind': KIND_NOTE,
            'id': '2ecd824add055bcb36b9babf479e0f822888cc733215ade8021fedf38730b73c',
            'pubkey': PUBKEY,
            'content': 'I hereby reply',
            'tags': [['e', ID, 'reelaay']],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'note',
            'id': 'http://foo/bar',
            'author': PUBKEY_URI,
            'content': 'I hereby reply',
            'inReplyTo': f'nostr:{ID}',
        })))

    def test_convert_repost(self):
        Object(id=NOTE_AS1['id'], nostr=NOTE_NOSTR).put()
        relays = Object(id=ID_URI, nostr={
            'kind': KIND_RELAYS,
            'pubkey': PUBKEY,
            'tags': [['r', 'reelaay']],
        }).put()
        Nostr(id=PUBKEY_URI, relays=relays).put()

        note_event = copy.copy(NOTE_NOSTR)
        del note_event['sig']
        self.assert_equals({
            'kind': KIND_REPOST,
            'pubkey': PUBKEY_2,
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
            'author': PUBKEY_URI_2,
            'content': 'I hereby reply',
            'object': NOTE_AS1,
        })), ignore=['id'])

    def test_convert_follow(self):
        relays = Object(id=ID_URI, nostr={
            'kind': KIND_RELAYS,
            'pubkey': PUBKEY,
            'tags': [['r', 'reelaay']],
        }).put()
        Nostr(id=ID_URI, relays=relays).put()

        test_pubkey_1 = '34cd' + '0' * 60
        test_pubkey_2 = '98fe' + '0' * 60
        self.assert_equals({
            'kind': KIND_CONTACTS,
            'id': 'ae3426a4b8ceb0201769b5ddecc9415a9c11ac6a25b66367f6695b6b253380b1',
            'pubkey': PUBKEY,
            'content': 'not important',
            'tags': [
                ['p', test_pubkey_1, None, ''],
                ['p', test_pubkey_2, None, 'bob'],
            ],
            'created_at': NOW_TS,
        }, Nostr._convert(Object(our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'id': ID_URI,
            'actor': PUBKEY_URI,
            'published': '2022-01-02T03:04:05+00:00',
            'object': [
                f'nostr:{test_pubkey_1}',
                {'id': f'nostr:{test_pubkey_2}', 'displayName': 'bob'},
            ],
            'content': 'not important',
        })))

    def test_convert_note_from_user_sign(self):
        got = Nostr._convert(Object(id='fake:post', our_as1={
            'objectType': 'note',
            'id': 'fake:post',
            'author': PUBKEY_URI,
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

    def test_convert_article(self):
        obj = Object(id='fake:post', our_as1={
            'objectType': 'article',
            'id': 'fake:post',
            'author': PUBKEY_URI,
            'content': 'Something to say',
            'published': '2022-01-02T03:04:05+00:00',
        })

        event = {
            'kind': KIND_ARTICLE,
            'id': '288da70e240bc54d34c657d49312597b867ad33a6db50e6ec8a27e4b44ff1d0d',
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': NOW_TS,
            'tags': [
                ['d', 'fake:post'],
                ['published_at', str(NOW_TS)],
            ],
            'sig': '1365f0f26f403bf8e979061dcd658a41267012e66241744cad2af9e278097a70acffb4276ecfa358e740e1c656db206a4f97bbd90798df03720e4507248d40c9',
        }

        self.assert_equals(event, Nostr.convert(obj, from_user=self.user))

        # should still use the object id in the d tag even if we have
        # a mapping to Nostr event id
        obj.copies = [Target(uri='nostr:' + ID, protocol='nostr')]
        obj.put()
        self.assert_equals(event, Nostr.convert(obj, from_user=self.user))

    def test_send_bare_note(self):
        obj = Object(id='fake:note', our_as1={
            'objectType': 'note',
            'author': 'fake:user',
            'content': 'Something to say',
            'published': '2019-12-02T03:04:05+00:00',
        })

        id = '4a57c7a1dde3bfe13076db485c4f09756e54447f6389dbf6864d4139bc40a214'
        expected = {
            'kind': KIND_NOTE,
            'id': id,
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': NOW_TS,
            'tags': [],
            'sig': '65b42db33486f669fa4dff3dba2ed914dcda886d47177a747e5e574e1a87cd4da23b54350dba758ecd91d48625f5345c8516458c76bebf60b0de89d12fa76a11',
        }
        FakeConnection.to_receive = [
            ['OK', id, True, ''],
        ]

        self.assertTrue(Nostr.send(obj, 'reeelaaay', from_user=self.user))
        self.assert_equals(['reeelaaay'], FakeConnection.relays)
        self.assert_equals([['EVENT', expected]], FakeConnection.sent)
        self.assertTrue(granary.nostr.verify(expected))
        expected_copy = [Target(uri='nostr:' + id, protocol='nostr')]
        self.assertEqual(expected_copy, obj.key.get().copies)

        # send again should reuse the same event
        FakeConnection.sent = []
        FakeConnection.relays = []

        FakeConnection.to_receive = [
            ['OK', id, True, ''],
        ]

        # we shouldn't call now()
        with patch('granary.nostr.util.now') as mock_now:
            self.assertTrue(Nostr.send(obj, 'other-relay', from_user=self.user))

        mock_now.assert_not_called()
        self.assert_equals(['other-relay'], FakeConnection.relays)
        self.assert_equals([['EVENT', expected]], FakeConnection.sent)
        self.assertTrue(granary.nostr.verify(expected))
        self.assertEqual(expected_copy, obj.key.get().copies)

    def test_send_note_create(self):
        note = self.store_object(id='fake:note', our_as1={
            'objectType': 'note',
            'author': 'fake:user',
            'content': 'Something to say',
            'published': '2019-12-02T03:04:05+00:00',
        })
        create = Object(id='fake:create', our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'author': 'fake:user',
            'object': note.as1,
        })

        id = '4a57c7a1dde3bfe13076db485c4f09756e54447f6389dbf6864d4139bc40a214'
        expected = {
            'kind': KIND_NOTE,
            'id': id,
            'pubkey': PUBKEY,
            'content': 'Something to say',
            'created_at': NOW_TS,
            'tags': [],
            'sig': '65b42db33486f669fa4dff3dba2ed914dcda886d47177a747e5e574e1a87cd4da23b54350dba758ecd91d48625f5345c8516458c76bebf60b0de89d12fa76a11',
        }
        FakeConnection.to_receive = [
            ['OK', id, True, ''],
        ]

        self.assertTrue(Nostr.send(create, 'reeelaaay', from_user=self.user))
        self.assert_equals(['reeelaaay'], FakeConnection.relays)
        self.assert_equals([['EVENT', expected]], FakeConnection.sent)
        self.assertTrue(granary.nostr.verify(expected))
        self.assertEqual([Target(uri='nostr:' + id, protocol='nostr')],
                         note.key.get().copies)
        self.assertIsNone(create.key.get())

    def test_send_rejected_by_relay(self):
        obj = Object(id='fake:note', our_as1={
            'objectType': 'note',
            'author': 'fake:user',
            'content': 'Something to say',
            'published': '2019-12-02T03:04:05+00:00',
        })

        FakeConnection.to_receive = [
            ['OK', 'id', False, 'blocked: reason here'],
        ]

        self.assertFalse(Nostr.send(obj, 'reeelaaay', from_user=self.user))

    def test_send_profile_has_existing_copy(self):
        obj = Object(id='fake:alice',
                     copies=[Target(uri=ID_URI, protocol='nostr')],
                     our_as1={
                         'objectType': 'person',
                         'displayName': 'alice',
                     })
        obj.put()

        profile_id = '37e4ed37a09bbb2e0b68cb3b175c14edeb14021e830f436fe2c816e4b7654588'
        relays_id = 'b644499566c9940eaa54de876ebebfcc0a0edbd029faa693aa0e1ab489a99ddf'
        expected = [
            ['EVENT', {
                'kind': KIND_PROFILE,
                'id': profile_id,
                'pubkey': PUBKEY,
                'content': json_dumps({
                    'about': '🌉 bridged from 🤡 fake:alice by https://fed.brid.gy/',
                    'name': 'alice',
                }, ensure_ascii=False),
                'created_at': NOW_TS,
                'tags': [],
            }],
            ['EVENT', {
                'kind': KIND_RELAYS,
                'pubkey': PUBKEY,
                'id': relays_id,
                'created_at': NOW_TS,
                'tags': [['r', 'wss://nos.lol']],
                'content': '',
            }],
        ]
        FakeConnection.to_receive = [
            ['OK', profile_id, True, ''],
            ['OK', relays_id, True, ''],
        ]

        self.assertTrue(Nostr.send(obj, 'reeelaaay', from_user=self.user))
        self.assert_equals(['reeelaaay'], FakeConnection.relays)
        self.assert_equals(expected, FakeConnection.sent, ignore=['sig'])
        self.assertEqual([Target(uri='nostr:' + profile_id, protocol='nostr')],
                         obj.key.get().copies)

    @patch('secp256k1._gen_private_key', return_value=bytes.fromhex(PRIVKEY))
    def test_create_for(self, _):
        self.make_user(cls=Web, id='efake.brid.gy',
                       copies=[Target(protocol='nostr', uri=PUBKEY_URI)])
        alice = self.make_user('efake:alice', cls=ExplicitFake, obj_as1={
            'objectType': 'person',
            'displayName': 'Alice',
            'summary': 'foo bar'
        })

        profile_id = 'e9fb90a5bc5732be166ad28e8b61c1864190a309db1333291516d43f0c273826'
        relays_id = 'b644499566c9940eaa54de876ebebfcc0a0edbd029faa693aa0e1ab489a99ddf'
        FakeConnection.to_receive = [
            ['OK', profile_id, True, ''],
            ['OK', relays_id, True, ''],
        ]

        Nostr.create_for(alice)

        self.assert_equals([
            ['EVENT', {
                'kind': KIND_PROFILE,
                'pubkey': PUBKEY,
                'id': profile_id,
                'content': json_dumps({
                    # no @-mentions in Nostr profiles 🤷
                    'about': 'foo bar\n\n🌉 bridged from 📣 web:efake:alice, follow @efake.brid.gy to interact',
                    'name':'Alice',
                    'nip05': 'efake-handle-alice@efake.brid.gy',
                }, ensure_ascii=False),
                'created_at': NOW_TS,
                'tags': [],
            }],
            ['EVENT', {
                'kind': KIND_RELAYS,
                'pubkey': PUBKEY,
                'id': relays_id,
                'created_at': NOW_TS,
                'tags': [['r', 'wss://nos.lol']],
                'content': '',
            }],
        ], FakeConnection.sent, ignore=['sig'])

    def test_create_for_already_has_nostr_copy(self):
        Nostr.create_for(self.user)

        got = self.user.key.get()
        self.assertEqual([Target(uri=PUBKEY_URI, protocol='nostr')], got.copies)

        self.assertEqual(0, len(FakeConnection.sent))

    def test_create_for_no_copy(self):
        alice = self.make_user('fake:alice', cls=Fake,
                               nostr_key_bytes=self.key.private_key, obj_as1={
                                   'objectType': 'person',
                                   'displayName': 'Alice',
                               })

        FakeConnection.to_receive = [
            ['OK', 'fakeid', True, ''],
        ]

        Nostr.create_for(alice)

        got = alice.key.get()
        self.assertEqual([Target(uri=PUBKEY_URI, protocol='nostr')], got.copies)

        self.assertEqual(1, len(FakeConnection.sent))
        event_type, event = FakeConnection.sent[0]
        self.assertEqual('EVENT', event_type)
        self.assertEqual(PUBKEY, event['pubkey'])

    def test_create_for_profile_already_copied(self):
        alice = self.make_user('fake:user', cls=Fake, obj_as1={
            'objectType': 'person',
            'displayName': 'Alice',
        })
        alice.obj.copies = [Target(uri=ID_URI, protocol='nostr')]
        alice.obj.put()

        Nostr.create_for(alice)

        alice = alice.key.get()
        self.assertEqual(1, len([c for c in alice.copies if c.protocol == 'nostr']))
        self.assertEqual(0, len(FakeConnection.sent))

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_fetch_note(self, _):
        FakeConnection.to_receive = [
            ['EVENT', 'towkin', NOTE_NOSTR],
            ['EOSE', 'towkin'],
        ]

        obj = Object(id=ID_URI)
        self.assertTrue(Nostr.fetch(obj))
        self.assertEqual(NOTE_NOSTR, obj.nostr)
        self.assertEqual([Nostr.DEFAULT_TARGET], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'towkin', {'ids': [ID], 'limit': 20}],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_fetch_not_found(self, _):
        FakeConnection.to_receive = [
            ['EOSE', 'towkin'],
        ]

        obj = Object(id=ID_URI)
        self.assertFalse(Nostr.fetch(obj))
        self.assertIsNone(obj.nostr)
        self.assertEqual([Nostr.DEFAULT_TARGET], FakeConnection.relays)
        self.assertEqual([
            ['REQ', 'towkin', {'ids': [ID], 'limit': 20}],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)

    def test_fetch_error(self):
        FakeConnection.send_err = WebSocketException('Failed to connect')

        obj = Object(id=ID_URI)
        with self.assertRaises(WebSocketException):
            Nostr.fetch(obj)

        self.assertIsNone(obj.nostr)
        self.assertEqual([Nostr.DEFAULT_TARGET], FakeConnection.relays)

    def test_fetch_invalid_id(self):
        for id in '', 'not-a-nostr-id', 'https://example.com':
            with self.subTest(id=id):
                self.assertFalse(Nostr.fetch(Object(id=id)))

    def test_nip_05_fake_user_by_handle(self):
        user = self.make_user('fake:alice', cls=Fake, enabled_protocols=['nostr'],
                             copies=[Target(uri=PUBKEY_URI, protocol='nostr')])
        self.assertEqual('fake-handle-alice', user.handle_as_domain)

        resp = self.get('/.well-known/nostr.json?name=fake-handle-alice',
                        base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'fake-handle-alice': PUBKEY},
            'relays': {PUBKEY: ['wss://nos.lol']},
        }, resp.json)

    def test_nip_05_web_user(self):
        user = self.make_user('user.com', cls=Web, enabled_protocols=['nostr'],
                             copies=[Target(uri=PUBKEY_URI, protocol='nostr')])

        resp = self.get('/.well-known/nostr.json?name=user.com',
                        base_url='https://web.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/json', resp.headers['Content-Type'])
        self.assert_equals({
            'names': {'user.com': PUBKEY},
            'relays': {PUBKEY: ['wss://nos.lol']},
        }, resp.json)

    def test_nip_05_user_nostr_not_enabled(self):
        user = self.make_user('fake:disabled', cls=Fake,
                             copies=[Target(uri=PUBKEY_URI, protocol='nostr')])

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
        nostr_user = self.make_user(PUBKEY_URI, cls=Nostr)

        for name in (NPUB, PUBKEY_URI, f'nostr-{PUBKEY}'):
            with self.subTest(name=name):
                resp = self.get(f'/.well-known/nostr.json?name={name}',
                                base_url='https://nostr.brid.gy')
                self.assertEqual(404, resp.status_code)

    def test_target_for_existing_user(self):
        relays = Object(id=ID_URI, nostr={
            'kind': KIND_RELAYS,
            'pubkey': PUBKEY,
            'tags': [
                ['r', 'wss://a', 'read'],
                ['r', 'wss://b'],
            ],
        })
        relays.put()
        user = self.make_user(PUBKEY_URI, cls=Nostr, relays=relays.key)

        self.assertEqual('wss://b', Nostr.target_for(Object(nostr=NOTE_NOSTR)))

        actor = {'objectType': 'person', 'id': user.key.id()}
        self.assertEqual('wss://b', Nostr.target_for(Object(our_as1=actor)))

        relays.nostr['tags'] = [
            ['r', 'wss://a', 'read'],
            ['r', 'wss://c', 'write'],
            ['r', 'wss://b'],
        ]
        relays.put()
        self.assertEqual('wss://c', Nostr.target_for(Object(nostr=NOTE_NOSTR)))
        self.assertEqual('wss://c', Nostr.target_for(Object(our_as1=actor)))

    def test_target_for_no_relays_object(self):
        self.make_user(PUBKEY_URI, cls=Nostr)
        self.assertIsNone(Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    def test_target_for_no_author(self):
        self.assertIsNone(Nostr.target_for(Object(our_as1={
            'objectType': 'note',
            'content': 'Hello world',
        })))

    def test_target_for_no_as1(self):
        self.assertIsNone(Nostr.target_for(Object()))

    @patch('secrets.token_urlsafe', return_value='towkin')
    @patch('requests.get', return_value=requests_response({'names': {'a': PUBKEY}}))
    def test_reload_profile(self, mock_get, _):
        profile = id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({
                'name': 'Alice',
                'about': 'Test user',
                'picture': 'http://alice/pic',
                'nip05': 'a@example.com',
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

        user = Nostr(id=PUBKEY_URI)
        user.reload_profile()

        self.assertEqual([
            ['REQ', 'towkin', {
                'authors': [PUBKEY],
                'kinds': [KIND_PROFILE, KIND_RELAYS],
                'limit': 20,
            }],
            ['CLOSE', 'towkin'],
        ], FakeConnection.sent)
        self.assert_req(mock_get, 'https://example.com/.well-known/nostr.json?name=a')

        self.assertEqual(profile, user.obj_key.get().nostr)
        self.assertEqual(relays, user.relays.get().nostr)
        self.assertEqual('wss://b', Nostr.target_for(Object(nostr=NOTE_NOSTR)))
        self.assertEqual('a@example.com', user.valid_nip05)

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_reload_profile_no_events(self, _):
        FakeConnection.to_receive = [
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=PUBKEY_URI, valid_nip05='old')
        user.reload_profile()

        self.assertIsNone(user.obj_key)
        self.assertIsNone(user.relays)
        self.assertEqual('old', user.valid_nip05)
        self.assertIsNone(Nostr.target_for(Object(nostr=NOTE_NOSTR)))

    @patch('secrets.token_urlsafe', return_value='towkin')
    def test_reload_profile_no_nip05(self, _):
        profile = id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({'name': 'Alice'}),
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'towkin', profile],
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=PUBKEY_URI, valid_nip05='old')
        user.reload_profile()
        self.assertIsNone(user.valid_nip05)

    @patch('secrets.token_urlsafe', return_value='towkin')
    @patch('requests.get', return_value=requests_response({'names': {'a': 'cba321'}}))
    def test_reload_profile_nip05_wrong_pubkey(self, mock_get, _):
        profile = id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({'nip05': 'a@example.com'}),
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'towkin', profile],
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=PUBKEY_URI, valid_nip05='old')
        user.reload_profile()

        self.assert_req(mock_get, 'https://example.com/.well-known/nostr.json?name=a')
        self.assertIsNone(user.valid_nip05)

    @patch('secrets.token_urlsafe', return_value='towkin')
    @patch('requests.get', side_effect=OSError('nope'))
    def test_reload_profile_nip05_fetch_error(self, mock_get, _):
        profile = id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({'nip05': 'a@example.com'}),
        }, privkey=NSEC_URI)

        FakeConnection.to_receive = [
            ['EVENT', 'towkin', profile],
            ['EOSE', 'towkin'],
        ]

        user = Nostr(id=PUBKEY_URI, valid_nip05='old')
        user.reload_profile()

        self.assert_req(mock_get, 'https://example.com/.well-known/nostr.json?name=a')
        self.assertIsNone(user.valid_nip05)

    @patch('requests.get', return_value=requests_response(''))  # NIP-05 checks
    def test_status(self, _):
        self.assertEqual('no-profile', Nostr().status)
        self.assertEqual('no-profile', Nostr(valid_nip05='a@example.com').status)

        profile = Object(id=ID_URI, nostr=id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY,
            'content': json_dumps({
                'name': 'Alice',
                'picture': 'http://alice/pic',
                'nip05': 'a@example.com',
            }),
        }, privkey=NSEC_URI))
        user = Nostr(id=PUBKEY_URI, obj_key=profile.put())
        self.assertEqual('no-nip05', user.status)

        user.valid_nip05 = 'nope@example.com'
        self.assertEqual('no-nip05', user.status)

        user.valid_nip05 = 'a@example.com'
        self.assertIsNone(user.status)

    @patch('requests.get', return_value=requests_response({'names': {'a': PUBKEY_2}}))
    def test_status_unsets_valid_nip05_on_other_users(self, mock_get):
        user1 = self.make_user(id=PUBKEY_URI, cls=Nostr, valid_nip05='a@example.com')
        user1.put()
        self.assertEqual('a@example.com', user1.valid_nip05)

        profile = Object(id=ID, nostr=id_and_sign({
            'kind': KIND_PROFILE,
            'pubkey': PUBKEY_2,
            'content': json_dumps({
                'name': 'Bob',
                'picture': 'http://bob/pic',
                'nip05': 'a@example.com',
            }),
        }, privkey=NSEC_URI_2))
        user2 = self.make_user(id=PUBKEY_URI_2, cls=Nostr, obj_key=profile.put())
        user2.put()

        self.assertEqual('a@example.com', user2.valid_nip05)
        self.assert_req(mock_get, 'https://example.com/.well-known/nostr.json?name=a')

        self.assertIsNone(user1.key.get().valid_nip05)

    def test_check_supported(self):
        Nostr.check_supported(Object(our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'object': {'objectType': 'person'},
        }), 'send')

        Nostr.check_supported(Object(our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'object': {
                'objectType': 'article',
                'content': 'foo',
            },
        }), 'send')

        with self.assertRaises(NoContent) as e:
            Nostr.check_supported(Object(our_as1={
                'objectType': 'activity',
                'verb': 'update',
                'object': {'objectType': 'note'},
            }), 'send')
