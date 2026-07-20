"""Unit tests for ids.py."""
import hashlib
from unittest.mock import patch

from granary.generated.farcaster.username_proof_pb2 import UserNameProof
from granary.nostr import KIND_PROFILE
from granary.tests.test_farcaster import user_data_message
from granary.tests.test_nostr import ID, NPUB, NPUB_URI, PUBKEY, PUBKEY_URI
from webutil import util
from webutil.util import json_dumps

from activitypub import ActivityPub
from atproto import ATProto
import farcaster
from farcaster import Farcaster
from flask_app import app
from google.cloud.ndb.key import _MAX_KEYPART_BYTES
import ids
from ids import translate_handle, translate_object_id, translate_user_id
from models import Object, Target
from nostr import Nostr
from .testutil import Fake, TestCase
from web import Web

NOSTR_ID_0 = 'nostr:0' + 'a' * 63
NOSTR_ID_1 = 'nostr:1' + 'a' * 63
NOSTR_ID_2 = 'nostr:2' + 'a' * 63
NOSTR_ID_3 = 'nostr:3' + 'a' * 63
ID_URI = 'nostr:' + ID


class IdsTest(TestCase):
    def setUp(self):
        super().setUp()
        Web(id='bsky.brid.gy', ap_subdomain='bsky', has_redirects=True).put()
        Web(id='fed.brid.gy', ap_subdomain='fed', has_redirects=True).put()
        Web(id='nostr.brid.gy', ap_subdomain='nostr', has_redirects=True).put()

    def test_translate_user_id(self):
        Web(id='user.com', copies=[
            Target(uri='did:plc:123', protocol='atproto'),
            Target(uri='farcaster://123', protocol='farcaster'),
            Target(uri='nostr:123', protocol='nostr'),
        ]).put()
        ActivityPub(id='https://inst/user', copies=[
            Target(uri='did:plc:456', protocol='atproto'),
            Target(uri='farcaster://456', protocol='farcaster'),
            Target(uri='nostr:456', protocol='nostr'),
        ]).put()
        fake_user = Fake(id='fake:user', copies=[
            Target(uri='did:plc:789', protocol='atproto'),
            Target(uri='farcaster://789', protocol='farcaster'),
            Target(uri='nostr:789', protocol='nostr'),
        ])
        fake_user.put()

        # ATProto with DID docs, used to resolve handle in bsky.app URL
        did = self.store_object(id='did:plc:123', raw={
            'id': 'did:plc:123',
            'alsoKnownAs': ['at://user.com'],
        })
        ATProto(id='did:plc:123', obj_key=did.key).put()

        did = self.store_object(id='did:plc:000', raw={
            'id': 'did:plc:000',
            'alsoKnownAs': ['at://zero.com'],
        })
        ATProto(id='did:plc:000').put()

        for from_, id, to, expected in [
            (ActivityPub, 'https://inst/user', ActivityPub, 'https://inst/user'),
            (ActivityPub, 'https://inst/user', ATProto, 'did:plc:456'),
            (ActivityPub, 'https://inst/user', Fake, 'fake:u:https://inst/user'),
            (ActivityPub, 'https://inst/user', Web, 'https://inst/user'),
            (ActivityPub, 'https://bsky.brid.gy/ap/did:plc:456',
             ATProto, 'did:plc:456'),
            (ActivityPub, 'https://bsky.brid.gy/ap/did:plc:456',
             Fake, 'fake:u:did:plc:456'),
            (ATProto, 'did:plc:456', ATProto, 'did:plc:456'),
            (ATProto, 'https://bsky.app/profile/did:plc:456', ATProto, 'did:plc:456'),
            (Nostr, PUBKEY, Nostr, PUBKEY_URI),
            (Nostr, PUBKEY_URI, Nostr, PUBKEY_URI),
            (Nostr, NPUB, Nostr, PUBKEY_URI),
            (Nostr, NPUB_URI, Nostr, PUBKEY_URI),

            # copies
            (ATProto, 'did:plc:123', Web, 'user.com'),
            (ATProto, 'did:plc:456', ActivityPub, 'https://inst/user'),
            (ATProto, 'did:plc:789', Fake, 'fake:user'),
            (Farcaster, 'farcaster://123', Web, 'user.com'),
            (Farcaster, 'farcaster://456', ActivityPub, 'https://inst/user'),
            (Farcaster, 'farcaster://789', Fake, 'fake:user'),
            (Nostr, 'nostr:123', Web, 'user.com'),
            (Nostr, 'nostr:456', ActivityPub, 'https://inst/user'),
            (Nostr, 'nostr:789', Fake, 'fake:user'),

            # no copies
            (ActivityPub, 'https://web.brid.gy/ap/alice.com', Fake, 'fake:u:alice.com'),
            (ActivityPub, 'https://inst/alice', Farcaster, None),
            (ActivityPub, 'https://inst/alice', Nostr, None),
            (ActivityPub, 'https://web.brid.gy/ap/alice.com', Web, 'alice.com'),

            (ATProto, 'did:plc:x', Web, 'https://bsky.brid.gy/web/did:plc:x'),
            (ATProto, 'did:plc:x', ActivityPub, 'https://bsky.brid.gy/ap/did:plc:x'),
            (ATProto, 'did:plc:x', Fake, 'fake:u:did:plc:x'),
            (ATProto, 'did:plc:456', Nostr, None),
            (ATProto, 'https://bsky.app/profile/user.com', ATProto, 'did:plc:123'),
            (ATProto, 'https://bsky.app/profile/did:plc:123', ATProto, 'did:plc:123'),

            (Farcaster, 'farcaster://555', Web, 'https://fc.brid.gy/web/farcaster:555'),
            (Farcaster, 'farcaster://555', ActivityPub, 'https://fc.brid.gy/ap/farcaster:555'),
            (Farcaster, 'farcaster://555', ATProto, None),
            (Farcaster, 'farcaster://555', Nostr, None),

            (Nostr, ID, Web, f'https://nostr.brid.gy/web/{ID_URI}'),
            (Nostr, ID_URI, Web, f'https://nostr.brid.gy/web/{ID_URI}'),
            (Nostr, ID, ActivityPub, f'https://nostr.brid.gy/ap/{ID_URI}'),
            (Nostr, ID_URI, ActivityPub, f'https://nostr.brid.gy/ap/{ID_URI}'),
            (Nostr, ID, ATProto, None),
            (Nostr, ID_URI, ATProto, None),
            (Nostr, ID, Fake, f'fake:u:{ID_URI}'),
            (Nostr, ID_URI, Fake, f'fake:u:{ID_URI}'),

            # not enabled for target protocol, shouldn't matter
            (Fake, 'fake:user', ActivityPub, 'https://fa.brid.gy/ap/fake:user'),
            (Fake, 'fake:user', Fake, 'fake:user'),
            (Fake, 'fake:user', Web, 'https://fa.brid.gy/web/fake:user'),
            (Fake, 'fake:user', ATProto, 'did:plc:789'),
            # ...except when we don't have a copy
            (Fake, 'fake:alice', ATProto, None),
            (Fake, 'fake:alice', Farcaster, None),
            (Fake, 'fake:alice', Nostr, None),

            (Web, 'user.com', ActivityPub, 'http://localhost/user.com'),
            (Web, 'https://user.com/', ActivityPub, 'http://localhost/user.com'),
            (Web, 'user.com', ATProto, 'did:plc:123'),
            (Web, 'https://user.com', ATProto, 'did:plc:123'),
            (Web, 'user.com', Fake, 'fake:u:user.com'),
            (Web, 'alice.com', Farcaster, None),
            (Web, 'alice.com', Nostr, None),
            (Web, 'user.com', Web, 'user.com'),
            (Web, 'https://user.com/', Web, 'user.com'),

            # instance actor / protocol bot users
            (Web, 'fed.brid.gy', ActivityPub, 'https://fed.brid.gy/fed.brid.gy'),
            (Web, 'bsky.brid.gy', ActivityPub, 'https://bsky.brid.gy/bsky.brid.gy'),
            (Web, 'nostr.brid.gy', ActivityPub, 'https://nostr.brid.gy/nostr.brid.gy'),
        ]:
            with self.subTest(id=id, from_=from_.LABEL, to=to.LABEL):
                self.assertEqual(expected, translate_user_id(
                    id=id, from_=from_, to=to))

        fake_user.enabled_protocols = ['activitypub', 'web']
        fake_user.put()
        self.assertEqual(
            'https://fa.brid.gy/ap/fake:user',
            translate_user_id(id='fake:user', from_=Fake, to=ActivityPub))
        self.assertEqual(
            'https://fa.brid.gy/web/fake:user',
            translate_user_id(id='fake:user', from_=Fake, to=Web))

    def test_translate_user_id_no_copy_did_stored(self):
        for proto, id in [
            (Web, 'user.com'),
            (ActivityPub, 'https://instance/user'),
            (Fake, 'fake:user'),
        ]:
            with self.subTest(proto=proto.LABEL, id=id):
                self.assertIsNone(translate_user_id(id=id, from_=proto, to=ATProto))

    def test_translate_user_id_use_instead(self):
        did = Target(uri='did:plc:123', protocol='atproto')
        user = self.make_user('user.com', cls=Web, copies=[did])
        self.make_user('www.user.com', cls=Web, use_instead=user.key)

        for proto, expected in [
            (ATProto, 'did:plc:123'),
            (ActivityPub, 'http://localhost/user.com'),
            (Fake, 'fake:u:user.com'),
        ]:
            with self.subTest(proto=proto.LABEL):
                self.assertEqual(expected, translate_user_id(
                    id='www.user.com', from_=Web, to=proto))
                self.assertEqual(expected, translate_user_id(
                    id='https://www.user.com/', from_=Web, to=proto))

    def test_translate_user_id_web_ap_subdomain_fed(self):
        self.make_user('on-fed.com', cls=Web, ap_subdomain='fed')
        self.make_user('on-bsky.com', cls=Web, ap_subdomain='bsky')

        for base_url in ['https://web.brid.gy/', 'https://fed.brid.gy/']:
            with app.test_request_context('/', base_url=base_url):
                self.assertEqual('https://web.brid.gy/on-web.com', translate_user_id(
                    id='on-web.com', from_=Web, to=ActivityPub))
                self.assertEqual('https://fed.brid.gy/on-fed.com', translate_user_id(
                    id='on-fed.com', from_=Web, to=ActivityPub))
                self.assertEqual('https://bsky.brid.gy/on-bsky.com', translate_user_id(
                    id='on-bsky.com', from_=Web, to=ActivityPub))

    def test_translate_user_id_not_user_id(self):
        for proto, id in [
            (ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/lists/abc'),
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                got = ids.translate_user_id(id=id, from_=proto, to=proto)
                self.assertEqual(id, got)

    def test_normalize_user_id(self):
        for proto, id, expected in [
            (ActivityPub, 'https://inst/user', 'https://inst/user'),
            (ATProto, 'did:plc:456', 'did:plc:456'),
            (ATProto, 'https://bsky.app/profile/did:plc:123', 'did:plc:123'),
            # TODO
            # (ATProto, 'https://bsky.app/profile/han.dull', 'did:plc:123'),
            (ATProto, 'at://did:plc:123', 'did:plc:123'),
            (ATProto, 'at://did:plc:123/app.bsky.actor.profile/self', 'did:plc:123'),
            (ATProto, 'https://bsky.app/profile/did:plc:123/post/456',
             'https://bsky.app/profile/did:plc:123/post/456'),
            (ATProto, 'at://did:plc:123/app.bsky.feed.post/456',
             'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/post/456',
             'https://bsky.app/profile/han.dull/post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/lists/abc',
             'https://bsky.app/profile/han.dull/lists/abc'),
            (Fake, 'fake:user', 'fake:user'),
            (Fake, 'fake:profile:user', 'fake:user'),
            (Farcaster, '123', 'farcaster://123'),
            (Farcaster, 'farcaster://123', 'farcaster://123'),
            (Farcaster, 'farcaster:123', 'farcaster://123'),
            (Web, 'user.com', 'user.com'),
            (Web, 'https://user.com/', 'user.com'),
            (Web, 'https://www.user.com/', 'user.com'),
            (Web, 'm.user.com', 'user.com'),
            (Nostr, PUBKEY, PUBKEY_URI),
            (Nostr, PUBKEY_URI, PUBKEY_URI),
            (Nostr, NPUB, PUBKEY_URI),
            (Nostr, NPUB_URI, PUBKEY_URI),
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                self.assertEqual(expected, ids.normalize_user_id(id=id, proto=proto))

    @patch('granary.farcaster.rpc_pb2_grpc.HubServiceStub')
    def test_normalize_user_id_farcaster_username(self, mock_stub):
        farcaster._client = None
        mock_stub.return_value.GetUsernameProof.return_value = \
            UserNameProof(fid=123, name=b'user')
        self.assertEqual('farcaster://123', ids.normalize_user_id(
            id='farcaster://@user', proto=Farcaster))

    def test_normalize_user_id_not_user_id(self):
        for proto, id in [
            (ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/lists/abc'),
            (Farcaster, 'farcaster://123/0x456')
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                self.assertEqual(id, ids.normalize_user_id(id=id, proto=proto))

    def test_normalize_object_id(self):
        for proto, id, expected in [
            (ActivityPub, 'https://inst/obj', 'https://inst/obj'),
            (ATProto, 'https://bsky.app/profile/did:plc:123/post/abc',
             'at://did:plc:123/app.bsky.feed.post/abc'),
            (Fake, 'fake:obj', 'fake:obj'),
            (Fake, 'fake:alice', 'fake:profile:alice'),
            # TODO? would need user id though
            # (Farcaster, b'Eg', 'farcaster://123/0x4567'),
            # (Farcaster, '0x456', 'farcaster://123/0x456'),
            (Farcaster, 'farcaster://123/0x456', 'farcaster://123/0x456'),
            (Web, 'user.com', 'https://user.com/'),
            (Web, 'https://user.com/', 'https://user.com/'),
            (Web, 'https://user.com/foo', 'https://user.com/foo'),
            (Web, 'https://user.com/foo\nbar', 'https://user.com/foo'),
            (Web, 'https://user.com/' + 'x' * _MAX_KEYPART_BYTES,
             'https://user.com/' + 'x' * (_MAX_KEYPART_BYTES - 17)),
            (Nostr, PUBKEY, PUBKEY_URI),
            (Nostr, PUBKEY_URI, PUBKEY_URI),
            (Nostr, NPUB, PUBKEY_URI),
            (Nostr, NPUB_URI, PUBKEY_URI),
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                self.assertEqual(expected, ids.normalize_object_id(id=id, proto=proto))

    def test_profile_id(self):
        for proto, id, expected in [
            (ActivityPub, 'https://inst/user', 'https://inst/user'),
            (ATProto, 'did:plc:123', 'at://did:plc:123/app.bsky.actor.profile/self'),
            (ATProto, 'at://did:plc:123/app.bsky.actor.profile/self',
             'at://did:plc:123/app.bsky.actor.profile/self'),
            (Fake, 'fake:user', 'fake:profile:user'),
            (Web, 'user.com', 'https://user.com/'),
            (Nostr, NPUB, None),
            (Nostr, NPUB_URI, None),
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                self.assertEqual(expected, ids.profile_id(id=id, proto=proto))

        user = Nostr(id=PUBKEY_URI, obj_key=Object(id=NOSTR_ID_0).key)
        user.put()
        self.assertEqual(NOSTR_ID_0, ids.profile_id(id=PUBKEY_URI, proto=Nostr))
        self.assertEqual(NOSTR_ID_0, ids.profile_id(
            id=PUBKEY_URI.removeprefix('nostr:'), proto=Nostr))
        self.assertEqual(NOSTR_ID_0, user.profile_id())

    @patch.object(util.session, 'get', autospec=True)
    def test_translate_handle(self, _):
        # ATProto handles come from a DID doc's alsoKnownAs, keyed by DID
        self.store_object(id='did:plc:user', raw={
            'id': 'did:plc:user', 'alsoKnownAs': ['at://user.com']})
        self.store_object(id='did:plc:u-se-r', raw={
            'id': 'did:plc:u-se-r', 'alsoKnownAs': ['at://u-se-r.com']})

        def ap_user(addr):
            return ActivityPub(webfinger_addr=addr)

        id = 0
        def fc_user(username):
            nonlocal id
            id += 1
            return self.make_user(cls=Farcaster, id=f'farcaster://{id}', objs_fc=[
                user_data_message(123, 'USER_DATA_TYPE_USERNAME', username)
            ])

        def nostr_user(nip05):
            nonlocal id
            id += 1
            return self.make_user(cls=Nostr, id=PUBKEY_URI, obj_nostr={
                'id': hashlib.sha256(bytes(id)).hexdigest(),
                'kind': KIND_PROFILE,
                'pubkey': PUBKEY,
                'content': json_dumps({'nip05': nip05}),
            })

        for from_user, to, expected in [
            # basic
            (Web(id='user.com'), ActivityPub, '@user.com@web.brid.gy'),
            (Web(id='user.com'), ATProto, 'user.com.web.brid.gy'),
            (Web(id='user.com'), Fake, 'fake:handle:user.com'),
            (Web(id='u_se-r.com'), Fake, 'fake:handle:u_se-r.com'),
            (Web(id='user.com'), Farcaster, 'user-com'),
            (Web(id='user.com'), Nostr, 'user.com@web.brid.gy'),
            (Web(id='user.com'), Web, 'user.com'),

            (ap_user('@user@instance'), ActivityPub, '@user@instance'),
            (ap_user('@user@instance'), ATProto, 'user.instance.ap.brid.gy'),
            (ap_user('@u_se~r@instance'), ATProto, 'u-se-r.instance.ap.brid.gy'),
            (ap_user('@user@instance'), Fake, 'fake:handle:@user@instance'),
            (ap_user('@user@instance'), Farcaster, 'user-instance'),
            (ap_user('@user@instance'), Nostr, 'user.instance@ap.brid.gy'),
            (ap_user('@user@instance'), Web, 'https://instance/@user'),

            (ATProto(id='did:plc:user'), ActivityPub, '@user.com@bsky.brid.gy'),
            (ATProto(id='did:plc:u-se-r'), ActivityPub, '@u-se-r.com@bsky.brid.gy'),
            (ATProto(id='did:plc:user'), ATProto, 'user.com'),
            (ATProto(id='did:plc:user'), Fake, 'fake:handle:user.com'),
            (ATProto(id='did:plc:user'), Farcaster, 'user-com'),
            (ATProto(id='did:plc:user'), Nostr, 'user.com@bsky.brid.gy'),
            (ATProto(id='did:plc:user'), Web, 'user.com'),

            (Fake(id='fake:user'), ActivityPub, '@fake-handle-user@fa.brid.gy'),
            (Fake(id='fake:user'), ATProto, 'fake-handle-user.fa.brid.gy'),
            (Fake(id='fake:user'), Fake, 'fake:handle:user'),
            (Fake(id='fake:user'), Nostr, 'fake-handle-user@fa.brid.gy'),
            (Fake(id='fake:user'), Web, 'fake:handle:user'),

            (fc_user('me'), ActivityPub, '@me@fc.brid.gy'),
            (fc_user('me.eth'), ActivityPub, '@me.eth@fc.brid.gy'),
            (fc_user('me'), ATProto, 'me.fc.brid.gy'),
            (fc_user('me.eth'), ATProto, 'me.eth.fc.brid.gy'),
            (fc_user('me'), Farcaster, 'me'),
            (fc_user('me'), Nostr, 'me@fc.brid.gy'),
            (fc_user('me'), Web, 'me'),

            (nostr_user('user@dom.ain'), Nostr, 'user@dom.ain'),
            (nostr_user('user@dom.ain'), ActivityPub, '@user.dom.ain@nostr.brid.gy'),
            (nostr_user('user@dom.ain'), ATProto, 'user.dom.ain.nostr.brid.gy'),
            (nostr_user('user@dom.ain'), Fake, 'fake:handle:user@dom.ain'),
            (nostr_user('user@dom.ain'), Farcaster, 'user-dom-ain'),
            (nostr_user('user@dom.ain'), Web, 'user@dom.ain'),

            # domain-only NIP-05 shortcut ('_@si.te' in the profile);
            # Nostr.handle already strips the leading _@, so the real handle
            # is the bare domain
            (nostr_user('_@example.com'), Nostr, 'example.com'),
            (nostr_user('_@example.com'), ActivityPub, '@example.com@nostr.brid.gy'),
            (nostr_user('_@example.com'), ATProto, 'example.com.nostr.brid.gy'),
            (nostr_user('_@example.com'), Fake, 'fake:handle:example.com'),
            (nostr_user('_@example.com'), Farcaster, 'example-com'),
            (nostr_user('_@example.com'), Web, 'example.com'),

            # instance actor, protocol bot users
            (Web(id='fed.brid.gy'), ActivityPub, '@fed.brid.gy@fed.brid.gy'),
            (Web(id='bsky.brid.gy'), ActivityPub, '@bsky.brid.gy@bsky.brid.gy'),
            (Web(id='ap.brid.gy'), ATProto, 'ap.brid.gy'),
            (Web(id='ap.brid.gy'), Nostr, 'ap.brid.gy'),
        ]:
            with self.subTest(from_=from_user.LABEL, handle=from_user.handle,
                              to=to.LABEL):
                self.assertEqual(expected, translate_handle(from_=from_user, to=to))
                self.assertEqual(expected, translate_handle(
                    handle=from_user.handle, from_=from_user.__class__, to=to))

        for input in '@_user@instance', '@user~@instance':
            with self.subTest(input=input), self.assertRaises(ValueError):
                translate_handle(from_=ActivityPub(
                    id='https://instance/user', webfinger_addr=input), to=ATProto)

        # to ActivityPub, short=True
        self.store_object(id='did:plc:us-er', raw={
            'id': 'did:plc:us-er', 'alsoKnownAs': ['at://us.er']})
        for from_user in (
            ActivityPub(id='https://instance/user', webfinger_addr='@us.er@instance'),
            ATProto(id='did:plc:us-er'),
            self.make_user(id=PUBKEY_URI, cls=Nostr, obj_nostr={
                'id': hashlib.sha256(b'us-er-1').hexdigest(), 'kind': KIND_PROFILE, 'pubkey': PUBKEY,
                'content': json_dumps({'nip05': 'us@er'})}),
            self.make_user(id=PUBKEY_URI, cls=Nostr, obj_nostr={
                'id': hashlib.sha256(b'underscore-us-er-1').hexdigest(), 'kind': KIND_PROFILE, 'pubkey': PUBKEY,
                'content': json_dumps({'nip05': '_@us.er'})}),
        ):
            self.assertEqual('@us.er', translate_handle(
                from_=from_user, to=ActivityPub, short=True))

    @patch('ids.ATPROTO_HANDLE_DOMAINS', set(('example.com',)))
    def test_translate_handle_atproto_handle_domains(self):
        self.assertEqual('alice.example.com', translate_handle(
            from_=Web(id='alice.example.com'), to=ATProto))

        bob = ActivityPub(id='https://instance/bob',
                          webfinger_addr='@bob@example.com')
        self.assertEqual('bob.example.com', translate_handle(from_=bob, to=ATProto))

        bob = self.make_user(id=PUBKEY_URI, cls=Nostr, obj_nostr={
                'id': hashlib.sha256(b'bob-example-com-1').hexdigest(),
                'kind': KIND_PROFILE,
                'pubkey': PUBKEY,
                'content': json_dumps({'nip05': 'bob@example.com'}),
        })
        self.assertEqual('bob.example.com', translate_handle(from_=bob, to=ATProto))

    def test_translate_handle_web_domain_override(self):
        """Web users always translate via their domain, not a custom username."""
        user = Web(id='user.com', obj=Object(
            id='a', as2={'url': ['acct:baz@user.com']}))
        self.assertEqual('baz', user.handle)

        self.assertEqual('fake:handle:user.com',
                         translate_handle(from_=user, to=Fake))

    def test_translate_handle_atproto_did_doc_override(self):
        """Translating to ATProto prefers the handle in the user's own DID doc."""
        self.store_object(id='did:plc:xyz', raw={
            'id': 'did:plc:xyz',
            'alsoKnownAs': ['at://custom.example.com'],
        })
        user = Fake(id='fake:user',
                    copies=[Target(uri='did:plc:xyz', protocol='atproto')])

        self.assertEqual('custom.example.com',
                         translate_handle(from_=user, to=ATProto))

    def test_translate_handle_farcaster_profile_override(self):
        """Translating to Farcaster prefers the username in the copy's profile Object."""
        self.store_object(id='farcaster://123', our_as1={'username': 'alice'})
        user = Fake(id='fake:user',
                    copies=[Target(uri='farcaster://123', protocol='farcaster')])

        self.assertEqual('alice', translate_handle(from_=user, to=Farcaster))

    def test_translate_object_id(self):
        self.store_object(id='http://po.st', copies=[
            Target(uri='at://did:plc:abc/web/post', protocol='atproto'),
            Target(uri=NOSTR_ID_0, protocol='nostr')])
        self.store_object(id='https://inst/post', copies=[
            Target(uri='at://did:plc:abc/ap/post', protocol='atproto'),
            Target(uri=NOSTR_ID_1, protocol='nostr')])
        self.store_object(id='fake:post', copies=[
            Target(uri='at://did:plc:abc/fa/post', protocol='atproto'),
            Target(uri=NOSTR_ID_2, protocol='nostr')])
        self.store_object(id=NOSTR_ID_3, copies=[
            Target(uri='at://did:plc:abc/no/post', protocol='atproto')])

        # DID doc and ATProto, used to resolve handle in bsky.app URL
        did = self.store_object(id='did:plc:123', raw={
            'id': 'did:plc:123',
            'alsoKnownAs': ['at://user.com'],
        })
        ATProto(id='did:plc:123', obj_key=did.key).put()

        for from_, id, to, expected in [
            (ActivityPub, 'https://inst/post', ActivityPub, 'https://inst/post'),
            (ActivityPub, 'https://inst/post', Fake, 'fake:o:ap:https://inst/post'),
            (ActivityPub, 'https://inst/post',
             Web, 'https://ap.brid.gy/convert/web/https://inst/post'),
            (ATProto, 'at://did:plc:abc/atp/post', ATProto, 'at://did:plc:abc/atp/post'),
            (Nostr, NOSTR_ID_3, Nostr, NOSTR_ID_3),

            # copies
            (ActivityPub, 'https://inst/post', ATProto, 'at://did:plc:abc/ap/post'),
            (ATProto, 'at://did:plc:abc/web/post', Web, 'http://po.st'),
            (ATProto, 'at://did:plc:abc/ap/post', ActivityPub, 'https://inst/post'),
            (ATProto, 'at://did:plc:abc/fa/post', Fake, 'fake:post'),
            (ATProto, 'at://did:plc:abc/no/post', Nostr, NOSTR_ID_3),
            (Nostr, NOSTR_ID_0, Web, 'http://po.st'),
            (Nostr, NOSTR_ID_1, ActivityPub, 'https://inst/post'),
            (Nostr, NOSTR_ID_2, Fake, 'fake:post'),
            (Nostr, NOSTR_ID_3, ATProto, 'at://did:plc:abc/no/post'),
            (Web, 'http://po.st', ATProto, 'at://did:plc:abc/web/post'),
            (Web, 'http://po.st', Nostr, NOSTR_ID_0),
            (Fake, 'fake:post', Nostr, NOSTR_ID_2),

            # no copies
            (ATProto, 'did:plc:x', Web, 'https://bsky.brid.gy/convert/web/did:plc:x'),
            (ATProto, 'did:plc:x',
             ActivityPub, 'https://bsky.brid.gy/convert/ap/did:plc:x'),
            (ATProto, 'did:plc:x', Fake, 'fake:o:bsky:did:plc:x'),
            (ATProto, 'https://bsky.app/profile/user.com/post/456',
             ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/did:plc:123/post/456',
             ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'did:plc:x', Nostr, 'did:plc:x'),
            (Fake, 'fake:post',
             ActivityPub, 'https://fa.brid.gy/convert/ap/fake:post'),
            (Fake, 'fake:post', ATProto, 'at://did:plc:abc/fa/post'),
            (Fake, 'fake:post', Fake, 'fake:post'),
            (Fake, 'fake:post', Web, 'https://fa.brid.gy/convert/web/fake:post'),
            (Fake, 'fake:other-post', Nostr, 'fake:other-post'),
            (Web, 'http://po.st', ActivityPub, 'http://localhost/r/http://po.st'),
            (Web, 'http://localhost/po/st', ActivityPub, 'http://localhost/po/st'),
            (Web, 'https://fed.brid.gy/x', ActivityPub, 'https://fed.brid.gy/x'),
            (Web, 'https://bsky.brid.gy/x', ActivityPub, 'https://bsky.brid.gy/x'),
            (Web, 'http://po.st', Fake, 'fake:o:web:http://po.st'),
            (Web, 'http://po.st', Web, 'http://po.st'),
            (Nostr, 'nostr:456', Fake, 'fake:o:nostr:nostr:456'),
            (Farcaster, 'farcaster://123/0xabc', Web,
             'https://fc.brid.gy/convert/web/farcaster://123/0xabc'),
            (Farcaster, 'farcaster://123/0xabc', ActivityPub,
             'https://fc.brid.gy/convert/ap/farcaster://123/0xabc'),
            (Farcaster, 'farcaster://123/0xabc', ATProto, 'farcaster://123/0xabc'),
            (Farcaster, 'farcaster://123/0xabc', Nostr, 'farcaster://123/0xabc'),
            (Web, 'http://po.st', Farcaster, 'http://po.st'),

            (Nostr, 'nostr:456', ActivityPub,
             'https://nostr.brid.gy/convert/ap/nostr:456'),
            (Nostr, 'nostr:456', ATProto, 'nostr:456'),
            (Nostr, 'nostr:456', Web, 'https://nostr.brid.gy/convert/web/nostr:456'),
        ]:
            with self.subTest(id=id, from_=from_.LABEL, to=to.LABEL):
                self.assertEqual(expected, translate_object_id(
                    id=id, from_=from_, to=to))

    def test_translate_object_id_web_ap_subdomain_fed(self):
        self.make_user('on-fed.com', cls=Web, ap_subdomain='fed')

        for base_url in ['https://web.brid.gy/', 'https://fed.brid.gy/']:
            with app.test_request_context('/', base_url=base_url):
                got = translate_object_id(id='http://on-fed.com/post', from_=Web,
                                          to=ActivityPub)
                self.assertEqual('https://fed.brid.gy/r/http://on-fed.com/post', got)

                got = translate_object_id(id='http://on-web.com/post', from_=Web,
                                          to=ActivityPub)
                self.assertEqual('https://web.brid.gy/r/http://on-web.com/post', got)

    def test_handle_as_domain(self):
        for handle, expected in [
            (None, None),
            ('', None),

            ('user.com', 'user.com'),
            ('UsEr.cOm', 'user.com'),
            ('@user@instance.com', 'user.instance.com'),
            ('user@instance.com', 'user.instance.com'),
            ('uSeR@instAnce.cOm', 'user.instance.com'),

            ('user_name@instance.com', 'user-name.instance.com'),
            ('@alice@inst~test.com', 'alice.inst-test.com'),
            ('alice_bob@server.com', 'alice-bob.server.com'),
            ('alice~bob:jones@server.com', 'alice-bob-jones.server.com'),

            ('alice.bsky.social', 'alice.bsky.social'),
            ('alice_bob.bsky.social', 'alice-bob.bsky.social'),
            ('han.dull.brid.gy', 'han.dull.brid.gy'),

            ('fake:handle:user', 'fake-handle-user'),
            ('fake:handle:alice_bob', 'fake-handle-alice-bob'),
            ('fake:handle:alice~bob:jones', 'fake-handle-alice-bob-jones'),
            ('other:handle:user', 'other-handle-user'),
            ('other:handle:alice_bob~jones', 'other-handle-alice-bob-jones'),
        ]:
            with self.subTest(handle=handle):
                self.assertEqual(expected, ids.handle_as_domain(handle))
