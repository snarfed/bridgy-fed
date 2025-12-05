"""Unit tests for ids.py."""
from unittest.mock import patch

from granary.tests.test_nostr import ID, NPUB, NPUB_URI, PUBKEY, PUBKEY_URI

from activitypub import ActivityPub
from atproto import ATProto
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
        Web(id='user.com',
            copies=[Target(uri='did:plc:123', protocol='atproto')]).put()
        ActivityPub(id='https://inst/user',
                    copies=[Target(uri='did:plc:456', protocol='atproto')]).put()
        fake_user = Fake(id='fake:user',
                         copies=[Target(uri='did:plc:789', protocol='atproto')])
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
            (ActivityPub, 'https://bsky.app/profile/user.com', ATProto, 'did:plc:123'),
            (ActivityPub, 'https://bsky.app/profile/did:plc:123',
             ATProto, 'did:plc:123'),
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

            # no copies
            (ATProto, 'did:plc:x', Web, 'https://bsky.brid.gy/web/did:plc:x'),
            (ATProto, 'did:plc:x', ActivityPub, 'https://bsky.brid.gy/ap/did:plc:x'),
            (ATProto, 'did:plc:x', Fake, 'fake:u:did:plc:x'),
            (ATProto, 'did:plc:456', Nostr, None),
            (ATProto, 'https://bsky.app/profile/user.com', ATProto, 'did:plc:123'),
            (ATProto, 'https://bsky.app/profile/did:plc:123', ATProto, 'did:plc:123'),

            (Nostr, ID, Web, f'https://nostr.brid.gy/web/{ID_URI}'),
            (Nostr, ID_URI, Web, f'https://nostr.brid.gy/web/{ID_URI}'),
            (Nostr, ID, ActivityPub, f'https://nostr.brid.gy/ap/{ID_URI}'),
            (Nostr, ID_URI, ActivityPub, f'https://nostr.brid.gy/ap/{ID_URI}'),
            (Nostr, ID, ATProto, None),
            (Nostr, ID_URI, ATProto, None),
            (Nostr, ID, Fake, f'fake:u:{ID_URI}'),
            (Nostr, ID_URI, Fake, f'fake:u:{ID_URI}'),

            (ActivityPub, 'https://inst/user', Nostr, None),
            (Web, 'user.com', Nostr, None),
            (Fake, 'fake:user', Nostr, None),

            # user, not enabled, no copy
            (ATProto, 'did:plc:000', ActivityPub, 'https://bsky.app/profile/zero.com'),

            (Fake, 'fake:user', ActivityPub, 'web:fake:user'),
            (Fake, 'fake:user', ATProto, 'did:plc:789'),
            (Fake, 'fake:user', Fake, 'fake:user'),
            (Fake, 'fake:user', Web, 'web:fake:user'),

            (Web, 'user.com', ActivityPub, 'http://localhost/user.com'),
            (Web, 'https://user.com/', ActivityPub, 'http://localhost/user.com'),
            (Web, 'user.com', ATProto, 'did:plc:123'),
            (Web, 'https://user.com', ATProto, 'did:plc:123'),
            (Web, 'https://bsky.app/profile/user.com', ATProto, 'did:plc:123'),
            (Web, 'https://bsky.app/profile/did:plc:123', ATProto, 'did:plc:123'),
            (Web, 'user.com', Fake, 'fake:u:user.com'),
            (Web, 'user.com', Web, 'user.com'),
            (Web, 'https://user.com/', Web, 'user.com'),
            (ActivityPub, 'https://web.brid.gy/ap/user.com', Web, 'user.com'),
            (ActivityPub, 'https://web.brid.gy/ap/user.com', Fake, 'fake:u:user.com'),

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

        user = Nostr(id=PUBKEY_URI, obj_key=Object(id=NOSTR_ID_0).key)
        user.put()
        self.assertEqual(PUBKEY_URI,
                         ids.normalize_user_id(id=NOSTR_ID_0.removeprefix('nostr:'),
                                               proto=Nostr))
        self.assertEqual(PUBKEY_URI, ids.normalize_user_id(id=NOSTR_ID_0, proto=Nostr))

    def test_normalize_user_id_not_user_id(self):
        for proto, id in [
            (ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/post/456'),
            (ATProto, 'https://bsky.app/profile/han.dull/lists/abc'),
        ]:
            with self.subTest(id=id, proto=proto.LABEL):
                self.assertEqual(id, ids.normalize_user_id(id=id, proto=proto))

    def test_normalize_object_id(self):
        for proto, id, expected in [
            (ActivityPub, 'https://inst/user', 'https://inst/user'),
            (ATProto, 'https://bsky.app/profile/did:plc:123/post/abc',
             'at://did:plc:123/app.bsky.feed.post/abc'),
            (Fake, 'fake:obj', 'fake:obj'),
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

    def test_translate_handle(self):
        for from_, handle, to, expected in [
            # basic
            (Web, 'user.com', ActivityPub, '@user.com@web.brid.gy'),
            (Web, 'user.com', ATProto, 'user.com.web.brid.gy'),
            (Web, 'user.com', Fake, 'fake:handle:user.com'),
            (Web, 'u_se-r.com', Fake, 'fake:handle:u_se-r.com'),
            (Web, 'user.com', Web, 'user.com'),
            (Web, 'user.com', Nostr, 'user.com@web.brid.gy'),

            (ActivityPub, '@user@instance', ActivityPub, '@user@instance'),
            (ActivityPub, '@user@instance', ATProto, 'user.instance.ap.brid.gy'),
            (ActivityPub, '@u_se~r@instance', ATProto, 'u-se-r.instance.ap.brid.gy'),
            (ActivityPub, '@user@instance', Fake, 'fake:handle:@user@instance'),
            (ActivityPub, '@user@instance', Web, 'https://instance/@user'),
            (ActivityPub, '@user@instance', Nostr, 'user.instance@ap.brid.gy'),

            (ATProto, 'user.com', ActivityPub, '@user.com@bsky.brid.gy'),
            (ATProto, 'u-se-r.com', ActivityPub, '@u-se-r.com@bsky.brid.gy'),
            (ATProto, 'user.com', ATProto, 'user.com'),
            (ATProto, 'user.com', Fake, 'fake:handle:user.com'),
            (ATProto, 'user.com', Web, 'user.com'),
            (ATProto, 'user.com', Nostr, 'user.com@bsky.brid.gy'),

            (Fake, 'fake:handle:user', ActivityPub, '@fake-handle-user@fa.brid.gy'),
            (Fake, 'fake:handle:user', ATProto, 'fake-handle-user.fa.brid.gy'),
            (Fake, 'fake:handle:user', Fake, 'fake:handle:user'),
            (Fake, 'fake:handle:user', Web, 'fake:handle:user'),
            (Fake, 'fake:handle:user', Nostr, 'fake-handle-user@fa.brid.gy'),

            (Nostr, 'user@dom.ain', Nostr, 'user@dom.ain'),
            (Nostr, 'user@dom.ain', ActivityPub, '@user.dom.ain@nostr.brid.gy'),
            (Nostr, 'user@dom.ain', ATProto, 'user.dom.ain.nostr.brid.gy'),
            (Nostr, 'user@dom.ain', Web, 'user@dom.ain'),
            (Nostr, 'user@dom.ain', Fake, 'fake:handle:user@dom.ain'),

            (Nostr, '_@dom.ain', Nostr, '_@dom.ain'),
            (Nostr, '_@dom.ain', ActivityPub, '@dom.ain@nostr.brid.gy'),
            (Nostr, '_@dom.ain', ATProto, 'dom.ain.nostr.brid.gy'),
            (Nostr, '_@dom.ain', Web, 'dom.ain'),
            (Nostr, '_@dom.ain', Fake, 'fake:handle:dom.ain'),

            # instance actor, protocol bot users
            (Web, 'fed.brid.gy', ActivityPub, '@fed.brid.gy@fed.brid.gy'),
            (Web, 'bsky.brid.gy', ActivityPub, '@bsky.brid.gy@bsky.brid.gy'),
            (Web, 'ap.brid.gy', ATProto, 'ap.brid.gy'),
            (Web, 'ap.brid.gy', Nostr, 'ap.brid.gy'),
        ]:
            with self.subTest(from_=from_.LABEL, handle=handle, to=to.LABEL):
                self.assertEqual(expected, translate_handle(
                    handle=handle, from_=from_, to=to))

        for input in '@_user@instance', '@user~@instance':
            with self.subTest(input=input), self.assertRaises(ValueError):
                translate_handle(handle=input, from_=ActivityPub, to=ATProto)

        # to ActivityPub, short=True
        for from_, handle in (
            (ActivityPub, '@us.er@instance'),
            (ATProto, 'us.er'),
            (Nostr, 'us@er'),
            (Nostr, '_@us.er'),
        ):
            self.assertEqual('@us.er',translate_handle(
                handle=handle, from_=from_, to=ActivityPub, short=True))

    @patch('ids.ATPROTO_HANDLE_DOMAINS', set(('example.com',)))
    def test_translate_handle_atproto_handle_domains(self):
        self.assertEqual('alice.example.com', translate_handle(
            handle='alice.example.com', from_=Web, to=ATProto))
        self.assertEqual('bob.example.com', translate_handle(
            handle='@bob@example.com', from_=ActivityPub, to=ATProto))
        self.assertEqual('bob.example.com', translate_handle(
            handle='bob@example.com', from_=Nostr, to=ATProto))

    def test_translate_object_id(self):
        self.store_object(id='http://po.st', copies=[
            Target(uri='at://did:abc/web/post', protocol='atproto'),
            Target(uri=NOSTR_ID_0, protocol='nostr')])
        self.store_object(id='https://inst/post', copies=[
            Target(uri='at://did:abc/ap/post', protocol='atproto'),
            Target(uri=NOSTR_ID_1, protocol='nostr')])
        self.store_object(id='fake:post', copies=[
            Target(uri='at://did:abc/fa/post', protocol='atproto'),
            Target(uri=NOSTR_ID_2, protocol='nostr')])
        self.store_object(id=NOSTR_ID_3, copies=[
            Target(uri='at://did:abc/no/post', protocol='atproto')])

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
            (ATProto, 'at://did:abc/atp/post', ATProto, 'at://did:abc/atp/post'),
            (Nostr, NOSTR_ID_3, Nostr, NOSTR_ID_3),

            # copies
            (ActivityPub, 'https://inst/post', ATProto, 'at://did:abc/ap/post'),
            (ATProto, 'at://did:abc/web/post', Web, 'http://po.st'),
            (ATProto, 'at://did:abc/ap/post', ActivityPub, 'https://inst/post'),
            (ATProto, 'at://did:abc/fa/post', Fake, 'fake:post'),
            (ATProto, 'at://did:abc/no/post', Nostr, NOSTR_ID_3),
            (Nostr, NOSTR_ID_0, Web, 'http://po.st'),
            (Nostr, NOSTR_ID_1, ActivityPub, 'https://inst/post'),
            (Nostr, NOSTR_ID_2, Fake, 'fake:post'),
            (Nostr, NOSTR_ID_3, ATProto, 'at://did:abc/no/post'),
            (Web, 'http://po.st', ATProto, 'at://did:abc/web/post'),
            (Web, 'http://po.st', Nostr, NOSTR_ID_0),
            (Fake, 'fake:post', Nostr, NOSTR_ID_2),

            # no copies
            (ATProto, 'did:plc:x', Web, 'https://bsky.brid.gy/convert/web/did:plc:x'),
            (ATProto, 'did:plc:x', ActivityPub, 'https://bsky.brid.gy/convert/ap/did:plc:x'),
            (ATProto, 'did:plc:x', Fake, 'fake:o:bsky:did:plc:x'),
            (ATProto, 'https://bsky.app/profile/user.com/post/456',
             ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'https://bsky.app/profile/did:plc:123/post/456',
             ATProto, 'at://did:plc:123/app.bsky.feed.post/456'),
            (ATProto, 'did:plc:x', Nostr, 'did:plc:x'),
            (Fake, 'fake:post',
             ActivityPub, 'https://fa.brid.gy/convert/ap/fake:post'),
            (Fake, 'fake:post', ATProto, 'at://did:abc/fa/post'),
            (Fake, 'fake:post', Fake, 'fake:post'),
            (Fake, 'fake:post', Web, 'https://fa.brid.gy/convert/web/fake:post'),
            (Fake, 'fake:other-post', Nostr, 'fake:other-post'),
            (Web, 'http://po.st', ActivityPub, 'http://localhost/r/http://po.st'),
            (Web, 'http://po.st', Fake, 'fake:o:web:http://po.st'),
            (Web, 'http://po.st', Web, 'http://po.st'),
            (Nostr, 'nostr:456', Fake, 'fake:o:nostr:nostr:456'),
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
