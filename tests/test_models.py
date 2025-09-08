"""Unit tests for models.py."""
from datetime import timedelta
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
import arroba.server
from arroba.util import at_uri
from google.cloud import ndb
from google.cloud.ndb import tasklets
from google.cloud.tasks_v2.types import Task
from granary.bluesky import NO_AUTHENTICATED_LABEL
from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_BSKY
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil import util
from werkzeug.exceptions import Forbidden

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub
from atproto import ATProto
import common
import memcache
import models
from models import Follower, Object, OBJECT_EXPIRE_AGE, PROTOCOLS, Target, User
from nostr import Nostr
import protocol
from protocol import Protocol
from web import Web

from granary.nostr import bech32_prefix_for, is_bech32
from granary.tests.test_nostr import PRIVKEY, PUBKEY, NPUB_URI, NSEC_URI
from .test_activitypub import ACTOR
from .test_atproto import DID_DOC


class UserTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('y.za', cls=Web)

    def test_get_by_id_opted_out(self):
        self.assert_entities_equal(self.user, Web.get_by_id('y.za'))

        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        self.user.put()

        self.assertIsNone(Web.get_by_id('y.za'))
        self.assert_entities_equal(self.user, Web.get_by_id('y.za', allow_opt_out=True))

    def test_get_by_id_use_instead_opted_out(self):
        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        self.user.put()

        user = Fake.get_or_create('fake:a')
        user.use_instead = self.user.key
        user.put()

        self.assertIsNone(Fake.get_by_id('fake:a'))
        self.assert_entities_equal(self.user,
                                   Fake.get_by_id('fake:a', allow_opt_out=True))

    def test_get_by_id_use_instead_doesnt_exist(self):
        self.user.use_instead = Fake(id='fake:a').key
        self.user.put()
        self.assertIsNone(Web.get_by_id('y.za'))

    def test_get_or_create(self):
        user = Fake.get_or_create('fake:user')
        assert isinstance(user, Fake)
        self.assertEqual('fake:user', user.key.id())
        assert not user.existing

    def test_get_or_create_existing_merge_enabled_protocols(self):
        self.user.enabled_protocols = ['fake']
        self.user.put()

        user = Web.get_or_create('y.za', enabled_protocols=['other'])
        self.assertCountEqual(['fake', 'other'], user.enabled_protocols)

    @patch.object(Fake, 'DEFAULT_ENABLED_PROTOCOLS', ['other'])
    def test_get_or_create_propagate_fake_other(self):
        user = Fake.get_or_create('fake:user', propagate=True)
        self.assertEqual(['fake:user'], OtherFake.created_for)

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post', return_value=requests_response('OK'))  # create DID on PLC
    def test_get_or_create_propagate_atproto(self, mock_post, mock_create_task):
        common.RUN_TASKS_INLINE = False

        Fake.fetchable = {
            'fake:profile:user': {
                **ACTOR_AS,
                'image': None,  # don't try to fetch as blob
            },
        }
        user = Fake.get_or_create('fake:user', enabled_protocols=['atproto'],
                                  propagate=True)

        # check that profile was fetched remotely
        self.assertEqual(['fake:profile:user'], Fake.fetched)

        # check user, repo
        user = Fake.get_by_id('fake:user')
        self.assertEqual('fake:handle:user', user.handle)
        did = user.get_copy(ATProto)
        repo = arroba.server.storage.load_repo(did)

        # check profile record
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there\n\n🌉 bridged from 🤡 web:fake:user by https://fed.brid.gy/',
            'bridgyOriginalDescription': 'hi there',
            'bridgyOriginalUrl': 'https://alice.com/',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val' : 'bridged-from-bridgy-fed-fake'}],
            },
        }, profile)

        obj = Object.get_by_id('fake:profile:user')
        self.assertEqual([
            Target(protocol='atproto',
                   uri=at_uri(did, 'app.bsky.actor.profile', 'self')),
            Target(protocol='other', uri='other:o:fa:fake:profile:user'),
        ], obj.copies)

        mock_create_task.assert_called()

    @patch('ids.COPIES_PROTOCOLS', ['efake', 'atproto'])
    @patch.object(tasks_client, 'create_task')
    @patch('requests.post')
    @patch('requests.get')
    def test_get_or_create_propagate_not_enabled(self, mock_get, mock_post,
                                                 mock_create_task):
        mock_get.return_value = self.as2_resp(ACTOR)

        user = ActivityPub.get_or_create('https://mas.to/actor', propagate=True)

        mock_post.assert_not_called()
        mock_create_task.assert_not_called()

        user = ActivityPub.get_by_id('https://mas.to/actor')
        self.assertIsNone(user.get_copy(ATProto))
        self.assertEqual(0, AtpRepo.query().count())

    @patch.object(ExplicitFake, 'create_for', side_effect=ValueError('foo'))
    def test_get_or_create_propagate_create_for_fails_re_disable_protocol(self, _):
        user = Fake.get_or_create('fake:a', enabled_protocols=['efake'],
                                  propagate=True)
        self.assertEqual([], user.enabled_protocols)

    def test_get_or_create_use_instead(self):
        user = Fake.get_or_create('fake:a')
        user.use_instead = self.user.key
        user.put()

        got = Fake.get_or_create('fake:a')
        self.assertEqual('y.za', got.key.id())
        assert got.existing

    def test_get_or_create_by_copies(self):
        other = self.make_user(id='other:ab', cls=OtherFake,
                               copies=[Target(uri='fake:ab', protocol='fake')])
        self.assert_entities_equal(other, Fake.get_or_create('fake:ab'))

    def test_get_or_create_existing_opted_out(self):
        user = self.make_user('fake:user', cls=Fake,
                              obj_as1={'summary': '#nobridge'})
        self.assertIsNone(Fake.get_or_create('fake:user'))

    def test_get_or_create_new_opted_out(self):
        self.assertIsNone(Fake.get_or_create('fake:user', manual_opt_out=True))

    def test_public_pem(self):
        user = Fake(id='fake:a')
        self.assertIsNone(user.mod)
        self.assertIsNone(user.private_exponent)
        self.assertIsNone(user.public_exponent)

        pem = user.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)
        self.assertIsNotNone(user.mod)
        self.assertIsNotNone(user.private_exponent)
        self.assertIsNotNone(user.public_exponent)

        self.assertEqual(pem, user.key.get().public_pem())

    def test_private_pem(self):
        user = Fake(id='fake:a')
        self.assertIsNone(user.mod)
        self.assertIsNone(user.private_exponent)
        self.assertIsNone(user.public_exponent)

        pem = user.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)
        self.assertIsNotNone(user.mod)
        self.assertIsNotNone(user.private_exponent)
        self.assertIsNotNone(user.public_exponent)

        self.assertEqual(pem, user.key.get().private_pem())

    def test_nsec_new(self):
        user = Fake(id='fake:a')
        self.assertIsNone(user.nostr_key_bytes)

        nsec = user.nsec()
        self.assertTrue(is_bech32(nsec))
        self.assertIsNotNone(user.nostr_key_bytes)
        self.assertIsNotNone(user.key.get().nostr_key_bytes)

    def test_nsec_existing(self):
        self.user.nostr_key_bytes = bytes.fromhex(PRIVKEY)
        self.assertEqual(NSEC_URI.removeprefix('nostr:'), self.user.nsec())

    def test_npub_new(self):
        user = Fake(id='fake:a')
        self.assertIsNone(user.nostr_key_bytes)

        npub = user.npub()
        self.assertTrue(is_bech32(npub))
        self.assertIsNotNone(user.nostr_key_bytes)
        self.assertIsNotNone(user.key.get().nostr_key_bytes)

    def test_npub_existing(self):
        self.user.nostr_key_bytes = bytes.fromhex(PRIVKEY)
        self.assertEqual(NPUB_URI.removeprefix('nostr:'), self.user.npub())

    def test_hex_pubkey(self):
        self.user.nostr_key_bytes = bytes.fromhex(PRIVKEY)
        self.assertEqual(PUBKEY, self.user.hex_pubkey())

    def test_user_page_path(self):
        self.assertEqual('/web/y.za', self.user.user_page_path())
        self.assertEqual('/web/y.za/followers', self.user.user_page_path('followers'))

        fake_foo = self.make_user('fake:foo', cls=Fake)
        self.assertEqual('/fa/fake:handle:foo', fake_foo.user_page_path())
        self.assertEqual('/fa/fake:foo', fake_foo.user_page_path(prefer_id=True))

    def test_user_link_pictures_true(self):
        self.assert_multiline_equals(
            '<span class="logo" title="Web">🌐</span> <a class="h-card u-author mention" rel="me" href="https://y.za/" title="y.za"><span style="unicode-bidi: isolate">y.za</span></a>',
            self.user.user_link(pictures=True, handle=False))

        self.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals(
            '<span class="logo" title="Web">🌐</span> <a class="h-card u-author mention" rel="me" href="https://y.za/" title="Mrs. ☕ Foo"><img src="https://user.com/me.jpg" class="profile"> <span style="unicode-bidi: isolate">Mrs. ☕ Foo</span></a>',
            self.user.user_link(pictures=True, handle=False))

    def test_user_link_pictures_false(self):
        self.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="https://y.za/" title="Mrs. ☕ Foo"><span style="unicode-bidi: isolate">Mrs. ☕ Foo</span></a>',
            self.user.user_link(pictures=False, handle=False))

    def test_user_link_handle_true(self):
        self.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="https://y.za/" title="Mrs. ☕ Foo &middot; y.za"><span style="unicode-bidi: isolate">Mrs. ☕ Foo</span> &middot; y.za</a>',
            self.user.user_link(pictures=False, handle=True))

    def test_user_link_name_false(self):
        self.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="https://y.za/" title="y.za">y.za</a>',
            self.user.user_link(pictures=False, name=False))

    def test_user_link_dont_duplicate_handle_as_name(self):
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="https://y.za/" title="y.za">y.za</a>',
            self.user.user_link(pictures=False, name=True, handle=True))

    def test_user_link_proto(self):
        self.user.obj = Object(id='y.za', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="web:fake:y.za" title="Mrs. ☕ Foo &middot; fake:handle:y.za"><span style="unicode-bidi: isolate">Mrs. ☕ Foo</span> &middot; fake:handle:y.za</a>',
            self.user.user_link(proto=Fake, handle=True))

    def test_user_link_proto_activitypub_short(self):
        user = Fake(id='fake:x', enabled_protocols=['activitypub'])
        user.obj = Object(id='fake:profile:x', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="https://fa.brid.gy/ap/fake:x" title="@fake-handle-x@fa.brid.gy">@fake-handle-x</a>',
            user.user_link(proto=ActivityPub, handle='short', name=False))

    def test_user_link_proto_fallback(self):
        self.user.obj = Object(id='y.za', as2=ACTOR)
        self.assert_multiline_equals(
            '<a class="h-card u-author mention" rel="me" href="http://localhost/y.za" title="Mrs. ☕ Foo &middot; @y.za@web.brid.gy"><span style="unicode-bidi: isolate">Mrs. ☕ Foo</span> &middot; @y.za@web.brid.gy</a>',
            self.user.user_link(proto=ActivityPub, proto_fallback=True, handle=True))

    def test_user_link_proto_not_enabled(self):
        with self.assertRaises(AssertionError):
            self.user.user_link(proto=ExplicitFake)

    def test_is_web_url(self):
        for url in 'y.za', '//y.za', 'http://y.za', 'https://y.za':
            self.assertTrue(self.user.is_web_url(url), url)

        for url in (None, '', 'user', 'com', 'com.user', 'ftp://y.za',
                    'https://user', '://y.za'):
            self.assertFalse(self.user.is_web_url(url), url)

    def test_name(self):
        self.assertEqual('y.za', self.user.name())

        self.user.obj = Object(id='a', as2={'id': 'abc'})
        self.assertEqual('y.za', self.user.name())

        self.user.obj = Object(id='a', as2={'name': 'alice'})
        self.assertEqual('alice', self.user.name())

    def test_handle(self):
        self.assertEqual('y.za', self.user.handle)

    def test_handle_as_domain(self):
        self.assertEqual('fake-handle-user', Fake(id='fake:user').handle_as_domain)
        self.assertEqual('fake-handle-user', Fake(id='fake:uSeR').handle_as_domain)
        self.assertEqual('fake-handle-alice-bob',
                         Fake(id='fake:alice_bob').handle_as_domain)
        self.assertEqual('fake-handle-alice-bob-jones',
                         Fake(id='fake:alice~bob:jones').handle_as_domain)

    def test_id_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:user', user.id_as(Fake))
        self.assertEqual('fake:user', user.id_as('fake'))

        self.assertEqual('web:fake:user', user.id_as('ap'))
        user.enabled_protocols = ['activitypub']
        user.put()
        self.assertEqual('https://fa.brid.gy/ap/fake:user', user.id_as('ap'))

    def test_handle_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:handle:user', user.handle_as(Fake))
        self.assertEqual('fake:handle:user', user.handle_as('fake'))
        self.assertEqual('@fake-handle-user@fa.brid.gy', user.handle_as('ap'))
        self.assertEqual('@fake-handle-user', user.handle_as('ap', short=True))

    def test_handle_as_web_custom_username(self, *_):
        self.user.obj.our_as1 = {
            'objectType': 'person',
            'url': 'acct:alice@y.za',
        }
        self.assertEqual('alice', self.user.username())
        self.assertEqual('@y.za@web.brid.gy', self.user.handle_as('ap'))

    def test_handle_as_atproto_custom_handle(self, *_):
        self.assertEqual('y.za.web.brid.gy', self.user.handle_as(ATProto))

        self.user.copies = [Target(uri='did:plc:user', protocol='atproto')]
        self.assertEqual('y.za.web.brid.gy', self.user.handle_as(ATProto))

        self.store_object(id='did:plc:user', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://ha.nl'],
        })
        self.assertEqual('ha.nl', self.user.handle_as(ATProto))

    def test_handle_as_None(self):
        class NoHandle(Fake):
            ABBREV = 'nohandle'
            @ndb.ComputedProperty
            def handle(self):
                return None

        try:
            user = NoHandle()
            self.assertIsNone(user.handle_as(OtherFake))
        finally:
            PROTOCOLS.pop('nohandle')

    def test_load_multi(self):
        # obj_key is None
        alice = Fake(id='alice.com')
        alice.put()

        # obj_key points to nonexistent entity
        bob = Fake(id='bob.com', obj_key=Object(id='bob').key)
        bob.put()

        user = self.user.key.get(use_cache=False)
        self.assertFalse(hasattr(user, '_obj'))
        self.assertFalse(hasattr(alice, '_obj'))
        self.assertIsNone(bob._obj)

        User.load_multi([user, alice, bob])
        self.assertIsNotNone(user._obj)
        self.assertIsNone(alice._obj)
        self.assertIsNone(bob._obj)

    def test_status(self):
        self.assertIsNone(self.user.status)

        user = self.make_user('fake:user', cls=Fake, obj_as1={
            'summary': 'I like this',
        })
        self.assertIsNone(user.status)

        user.obj.our_as1.update({
            'summary': 'well #nobot yeah',
        })
        self.assertEqual('nobot', user.status)

        user.obj.our_as1.update({
            'summary': '🤷',
            # This is Mastodon's HTML around hashtags
            'displayName': '<a href="..." class="hashtag">#<span>nobridge</span></a>',
        })
        self.assertEqual('nobridge', user.status)

        user.obj.our_as1.update({
            'displayName': 'hi',
            'bridgeable': False,
        })
        self.assertEqual('opt-out', user.status)

        user = User(manual_opt_out=True)
        self.assertEqual('opt-out', user.status)

    def test_status_private(self):
        self.user.obj.our_as1 = {
            'to': [{'objectType': 'group', 'alias': '@unlisted'}],
        }
        self.assertEqual('private', self.user.status)

    def test_status_nobridge_overrides_enabled_protocols(self):
        self.assertIsNone(self.user.status)

        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        self.user.enabled_protocols = ['activitypub']
        self.assertEqual('nobridge', self.user.status)

    @patch.object(Fake, 'REQUIRES_AVATAR', True)
    def test_requires_avatar(self):
        user = self.make_user(id='fake:user', cls=Fake,
                              obj_as1={'displayName': 'Alice'})
        self.assertEqual('requires-avatar', user.status)

        user.enabled_protocols = ['efake']
        self.assertEqual('requires-avatar', user.status)

        user.obj.our_as1['image'] = 'http://pic'
        self.assertIsNone(user.status)

    @patch.object(Fake, 'REQUIRES_NAME', True)
    def test_requires_name(self):
        user = self.make_user(id='fake:user', cls=Fake,
                              obj_as1={'image': 'http://pic'})
        self.assertEqual('requires-name', user.status)

        user.obj.our_as1['displayName'] = 'fake:user'
        self.assertEqual('requires-name', user.status)

        user.obj.our_as1['displayName'] = 'fake:handle:user'
        self.assertEqual('requires-name', user.status)

        user.enabled_protocols = ['efake']
        self.assertEqual('requires-name', user.status)

        user.obj.our_as1['displayName'] = 'Alice'
        self.assertIsNone(user.status)

    @patch.object(Fake, 'REQUIRES_OLD_ACCOUNT', True)
    def test_requires_old_account(self):
        user = self.make_user(id='fake:user', cls=Fake, obj_as1={'foo': 'bar'})
        self.assertIsNone(user.status)

        too_young = util.now() - common.OLD_ACCOUNT_AGE + timedelta(minutes=1)
        user.obj.our_as1['published'] = too_young.isoformat()
        self.assertEqual('requires-old-account', user.status)

        user.enabled_protocols = ['efake']
        self.assertEqual('requires-old-account', user.status)

        user.obj.our_as1['published'] = (too_young - timedelta(minutes=2)).isoformat()
        self.assertIsNone(user.status)

    def test_status_manual_opt_out_false_overrides_spam_filters(self):
        too_young = util.now() - common.OLD_ACCOUNT_AGE + timedelta(minutes=1)
        user = self.make_user(id='fake:user', cls=Fake, manual_opt_out=False,
                              obj_as1={'published': too_young.isoformat()})
        self.assertIsNone(user.status)

        with (patch.object(Fake, 'REQUIRES_OLD_ACCOUNT', True),
              patch.object(Fake, 'REQUIRES_NAME', True),
              patch.object(Fake, 'REQUIRES_AVATAR', True)):
            self.assertIsNone(user.status)

    def test_get_copy(self):
        user = Fake(id='x')
        self.assertEqual('x', user.get_copy(Fake))
        self.assertIsNone(user.get_copy(OtherFake))

        user.copies.append(Target(uri='fake:foo', protocol='fake'))
        self.assertIsNone(user.get_copy(OtherFake))

        self.assertIsNone(user.get_copy(OtherFake))
        user.copies = [Target(uri='other:foo', protocol='other')]
        self.assertEqual('other:foo', user.get_copy(OtherFake))

        self.assertIsNone(OtherFake().get_copy(Fake))

    def test_count_followers(self):
        self.assertEqual((0, 0), self.user.count_followers())

        Follower(from_=self.user.key, to=Fake(id='a').key).put()
        Follower(from_=self.user.key, to=Fake(id='b').key).put()
        Follower(from_=Fake(id='c').key, to=self.user.key).put()

        # cached in both memcache and memory
        user = Web.get_by_id('y.za')
        self.assertEqual((0, 0), user.count_followers())

        # clear memory cache, still cached in memcache
        user.count_followers.cache.clear()
        self.assertEqual((0, 0), user.count_followers())

        # clear both
        memcache.pickle_memcache.client_pool.clear()
        user.count_followers.cache.clear()
        self.assertEqual((1, 2), user.count_followers())

    def test_count_followers_protocol_bot_user(self):
        bot = self.make_user(id='fa.brid.gy', cls=Web)
        Follower(from_=bot.key, to=Fake(id='b').key).put()
        Follower(from_=Fake(id='c').key, to=bot.key).put()
        self.assertEqual((0, 0), bot.count_followers())

    def test_is_enabled_default_enabled_protocols(self):
        web = self.make_user('a.com', cls=Web)

        self.assertTrue(web.is_enabled(ActivityPub))
        self.assertTrue(ActivityPub(id='').is_enabled(Web))
        self.assertTrue(ActivityPub(id='').is_enabled(ActivityPub))
        self.assertTrue(Fake(id='').is_enabled(OtherFake))
        self.assertTrue(ATProto(id='').is_enabled(Web))

        self.assertFalse(ActivityPub(id='').is_enabled(ATProto))
        self.assertFalse(ATProto(id='').is_enabled(ActivityPub))
        self.assertFalse(web.is_enabled(ATProto))
        self.assertFalse(ExplicitFake(id='').is_enabled(Fake))
        self.assertFalse(ExplicitFake(id='').is_enabled(OtherFake))
        self.assertFalse(ExplicitFake(id='').is_enabled(Web))
        self.assertFalse(Fake(id='').is_enabled(ExplicitFake))
        self.assertFalse(OtherFake(id='').is_enabled(ExplicitFake))

    def test_is_enabled_default_enabled_protocols_explicit(self):
        self.user.enabled_protocols = ['atproto']
        self.assertTrue(self.user.is_enabled(ATProto, explicit=True))

        assert 'activitypub' in Web.DEFAULT_ENABLED_PROTOCOLS
        self.assertFalse(self.user.is_enabled(ActivityPub, explicit=True))

    def test_is_enabled_enabled_protocols_overrides_nobot(self):
        user = self.make_user('efake:user', cls=ExplicitFake,
                              obj_as1={'summary': '#nobot'})
        self.assertFalse(user.is_enabled(Web))
        self.assertEqual('nobot', user.status)

        user.enabled_protocols = ['web']
        self.assertTrue(user.is_enabled(Web))
        self.assertIsNone(user.status)

        # manual opt out should still take precedence thoough
        user.manual_opt_out = True
        self.assertFalse(user.is_enabled(Web))
        self.assertEqual('opt-out', user.status)

    def test_is_enabled_enabled_protocols_overrides_non_public_profile_opt_out(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        user = self.make_user('did:plc:user', cls=ATProto,
                              obj_bsky={
                                  **ACTOR_PROFILE_BSKY,
                                  'labels': {
                                      'values': [{'val': NO_AUTHENTICATED_LABEL}],
                                  },
                              })
        self.assertFalse(user.is_enabled(Web))
        self.assertEqual('private', user.status)

        user.enabled_protocols = ['web']
        user.put()
        self.assertTrue(user.is_enabled(Web))
        self.assertIsNone(user.status)

    def test_is_enabled_manual_opt_out(self):
        user = self.make_user('user.com', cls=Web)
        self.assertTrue(user.is_enabled(ActivityPub))

        user.manual_opt_out = True
        user.put()
        self.assertFalse(user.is_enabled(ActivityPub))

        user.enabled_protocols = ['activitypub']
        user.put()
        self.assertFalse(user.is_enabled(ActivityPub))

    def test_is_enabled_enabled_protocols(self):
        user = self.make_user(id='efake:foo', cls=ExplicitFake)
        self.assertFalse(user.is_enabled(Fake))

        user.enabled_protocols = ['web']
        user.put()
        self.assertFalse(user.is_enabled(Fake))

        user.enabled_protocols = ['web', 'fake']
        user.put()
        self.assertTrue(user.is_enabled(Fake))

    def test_is_enabled_protocol_bot_users(self):
        # protocol bot users should always be enabled to *other* protocols
        self.assertTrue(Web(id='efake.brid.gy').is_enabled(Fake))
        self.assertTrue(Web(id='fa.brid.gy').is_enabled(ExplicitFake))
        self.assertTrue(Web(id='other.brid.gy').is_enabled(Fake))
        self.assertTrue(Web(id='ap.brid.gy').is_enabled(ATProto))
        self.assertTrue(Web(id='bsky.brid.gy').is_enabled(ActivityPub))

        # ...but not to their own protocol
        self.assertFalse(Web(id='ap.brid.gy').is_enabled(ActivityPub))
        self.assertFalse(Web(id='bsky.brid.gy').is_enabled(ATProto))

    def test_add_to_copies_updates_memcache(self):
        cache_key = memcache.memoize_key(
            models.get_original_user_key, 'other:x')
        self.assertIsNone(memcache.pickle_memcache.get(cache_key))

        user = Fake(id='fake:x')
        copy = Target(protocol='other', uri='other:x')
        user.add('copies', copy)

        self.assertEqual(user.key, memcache.pickle_memcache.get(cache_key))

    def test_add_to_copies_doesnt_update_if_already_there(self):
        copy = Target(protocol='other', uri='other:x')
        user = Fake(id='fake:x', copies=[copy])
        user.add('copies', copy)

        cache_key = memcache.memoize_key(
            models.get_original_user_key, 'other:x')
        self.assertIsNone(memcache.pickle_memcache.get(cache_key))

    def test_remove(self):
        user = Fake(id='fake:x', enabled_protocols=['web', 'activitypub'])
        user.remove('enabled_protocols', 'web')
        self.assertEqual(['activitypub'], user.enabled_protocols)

    def test_remove_from_copies_deletes_from_get_original_user_memoize(self):
        copy = Target(protocol='other', uri='other:x')
        user = Fake(id='fake:x', copies=[copy])
        user.put()

        # check that it's memoized
        self.assertEqual(user.key, models.get_original_user_key('other:x'))
        cache_key = memcache.memoize_key(models.get_original_user_key, 'other:x')
        self.assertEqual(user.key, memcache.pickle_memcache.get(cache_key))

        user.remove('copies', copy)
        user.put()

        # check that it's no longer memoized
        models.get_original_user_key.cache_clear()  # lru_cache
        self.assertIsNone(models.get_original_user_key('other:x'))

    def test_remove_nonexistent_value_noop(self):
        user = Fake(id='fake:x', enabled_protocols=[])
        user.remove('enabled_protocols', 'activitypub')
        self.assertEqual([], user.enabled_protocols)

        user.enabled_protocols = ['web']
        user.remove('enabled_protocols', 'activitypub')
        self.assertEqual(['web'], user.enabled_protocols)

    def test_remove_copies_on(self):
        user = Fake(id='fake:x', copies=[
            Target(protocol='other', uri='other:x'),
            Target(protocol='efake', uri='efake:y'),
            Target(protocol='other', uri='other:z'),
        ])
        user.put()

        self.assertEqual(user.key, models.get_original_user_key('other:x'))
        self.assertEqual(user.key, models.get_original_user_key('other:z'))

        user.remove_copies_on(OtherFake)
        self.assertEqual([Target(protocol='efake', uri='efake:y')], user.copies)
        user.put()

        models.get_original_user_key.cache_clear()  # lru_cache
        self.assertIsNone(models.get_original_user_key('other:x'))
        self.assertIsNone(models.get_original_user_key('other:z'))

    def test_remove_copies_on_empty(self):
        user = Fake(id='fake:x', copies=[Target(protocol='fake', uri='fake:y')])
        user.remove_copies_on(OtherFake)
        self.assertEqual([Target(protocol='fake', uri='fake:y')], user.copies)


class ObjectTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = None

    def test_target_hashable(self):
        target = Target(protocol='ui', uri='http://foo')

        # just check that these don't crash
        assert isinstance(id(target), int)

    @patch('models._MAX_KEYPART_BYTES', 20)
    def test_get_by_id_truncate_id(self):
        id = 'http://my/long/url/ok/then'
        self.assertIsNone(Object.get_by_id(id))

        obj = Object.get_or_create(id, our_as1={'content': 'foo'})
        self.assert_entities_equal(obj, Object.get_by_id(id))
        self.assertEqual('http://my/long/url/o', obj.key.id())

    def test_get_or_create(self):
        def check(obj1, obj2):
            self.assert_entities_equal(obj1, obj2, ignore=['expire', 'updated'])

        self.assertEqual(0, Object.query().count())

        user = ndb.Key(Web, 'user.com')
        obj = Object.get_or_create('fake:foo', our_as1={'content': 'foo'},
                                   source_protocol='fake', notify=[user])
        check([obj], Object.query().fetch())
        self.assertTrue(obj.new)
        self.assertFalse(obj.changed)
        self.assertEqual('fake:foo', obj.key.id())
        self.assertEqual({'content': 'foo', 'id': 'fake:foo'}, obj.as1)
        self.assertEqual('fake', obj.source_protocol)
        self.assertEqual([user], obj.notify)

        obj2 = Object.get_or_create('fake:foo', authed_as='fake:foo')
        self.assertFalse(obj2.new)
        self.assertFalse(obj2.changed)
        check(obj, obj2)
        check([obj2], Object.query().fetch())

        # non-null **props should be populated
        obj3 = Object.get_or_create('fake:foo', authed_as='fake:foo',
                                    our_as1={'content': 'bar'},
                                    source_protocol=None, notify=[])
        self.assertEqual('fake:foo', obj3.key.id())
        self.assertEqual({'content': 'bar', 'id': 'fake:foo'}, obj3.as1)
        self.assertEqual('fake', obj3.source_protocol)
        self.assertEqual([user], obj3.notify)
        self.assertFalse(obj3.new)
        self.assertTrue(obj3.changed)
        check([obj3], Object.query().fetch())
        check(obj3, Object.get_by_id('fake:foo'))

        obj4 = Object.get_or_create('fake:foo', authed_as='fake:foo',
                                    our_as1={'content': 'bar'})
        self.assertEqual({'content': 'bar', 'id': 'fake:foo'}, obj4.as1)
        self.assertFalse(obj4.new)
        self.assertFalse(obj4.changed)
        check(obj4, Object.get_by_id('fake:foo'))

        obj5 = Object.get_or_create('bar')
        self.assertTrue(obj5.new)
        self.assertFalse(obj5.changed)

        obj6 = Object.get_or_create('baz', notify=[ndb.Key(Web, 'other')])
        self.assertTrue(obj6.new)
        self.assertFalse(obj6.changed)

        self.assertEqual(3, Object.query().count())

        # if no data property is set, don't clear existing data properties
        obj7 = Object.get_or_create('http://b.ee/ff', as2={'a': 'b'}, mf2={'c': 'd'},
                                    source_protocol='web')
        Object.get_or_create('http://b.ee/ff', authed_as='http://b.ee/ff',
                             users=[ndb.Key(Web, 'me')],
                             copies=[Target(protocol='ui', uri='http://foo')])
        self.assert_object('http://b.ee/ff', as2={'a': 'b'}, mf2={'c': 'd'},
                           users=[ndb.Key(Web, 'me')], source_protocol='web',
                           copies=[Target(protocol='ui', uri='http://foo')])

        # repeated properties should merge, not overwrite
        Object.get_or_create('http://b.ee/ff', authed_as='http://b.ee/ff',
                             users=[ndb.Key(Web, 'you')],
                             copies=[Target(protocol='ui', uri='http://bar')])
        self.assert_object('http://b.ee/ff', as2={'a': 'b'}, mf2={'c': 'd'},
                           users=[ndb.Key(Web, 'me'), ndb.Key(Web, 'you')],
                           source_protocol='web',
                           copies=[Target(protocol='ui', uri='http://foo'),
                                   Target(protocol='ui', uri='http://bar')])

    def test_get_or_create_auth_check(self):
        Object(id='fake:foo', our_as1={'author': 'fake:alice'},
               source_protocol='fake').put()

        obj = Object.get_or_create('fake:foo', authed_as='fake:alice',
                                   source_protocol='fake',
                                   our_as1={'author': 'fake:alice', 'bar': 'baz'})

        expected = {
            'id': 'fake:foo',
            'bar': 'baz',
            'author': 'fake:alice',
        }
        self.assertEqual(expected, obj.as1)
        self.assertEqual(expected, Object.get_by_id('fake:foo').as1)

        with self.assertRaises(Forbidden):
            Object.get_or_create('fake:foo', authed_as='fake:eve',
                                 our_as1={'bar': 'biff'})

    def test_get_or_create_auth_check_normalize_profile_id(self):
        Object(id='https://www.foo.com', source_protocol='web',
               our_as1={'foo': 'bar'}).put()
        obj = Object.get_or_create('https://www.foo.com', authed_as='foo.com',
                                   our_as1={'foo': 'baz'})
        self.assertEqual({
            'id': 'https://www.foo.com',
            'foo': 'baz',
        }, obj.as1)

    def test_get_or_create_auth_check_profile_id(self):
        # https://console.cloud.google.com/errors/detail/CMDC_cirnMT0FQ;time=P1D;locations=global?project=bridgy-federated
        Object(id='fake:profile:alice', source_protocol='fake',
               our_as1={'x': 'y'}).put()

        obj = Object.get_or_create('fake:profile:alice', authed_as='fake:alice',
                                   our_as1={'x': 'z'})
        self.assertEqual({'id': 'fake:profile:alice', 'x': 'z'}, obj.as1)

    def test_get_or_create_authed_as_different_protocol(self):
        obj = Object(id='https://si.te/x', source_protocol='activitypub',
                     our_as1={'foo': 'bar'})
        obj.put()

        with self.assertRaises(Forbidden):
            Object.get_or_create('https://si.te/x', authed_as='si.te')

    def test_activity_changed(self):
        obj = Object()
        self.assertFalse(obj.activity_changed(None))
        self.assertFalse(obj.activity_changed({}))
        self.assertTrue(obj.activity_changed({'content': 'x'}))

        obj.our_as1 = {}
        self.assertFalse(obj.activity_changed(None))
        self.assertFalse(obj.activity_changed({}))
        self.assertTrue(obj.activity_changed({'content': 'x'}))

        obj.our_as1 = {'content': 'x'}
        self.assertTrue(obj.activity_changed(None))
        self.assertTrue(obj.activity_changed({}))
        self.assertFalse(obj.activity_changed({'content': 'x'}))

        obj.our_as1 = {'content': 'y'}
        self.assertTrue(obj.activity_changed(None))
        self.assertTrue(obj.activity_changed({}))
        self.assertTrue(obj.activity_changed({'content': 'x'}))

    def test_actor_link(self):
        for expected, as2 in (
                ('', {}),
                ('href="http://foo">foo', {'actor': 'http://foo'}),
                ('href="http://foo">foo', {'actor': {'id': 'http://foo'}}),
                ('href="">Alice', {'actor': {'name': 'Alice'}}),
                ('href="http://foo/">Alice', {'actor': {
                    'name': 'Alice',
                    'url': 'http://foo',
                }}),
                ("""\
        title="Alice">
          <img class="profile" src="http://pic/" />
          <span style="unicode-bidi: isolate">Alice</span>""", {'actor': {
              'name': 'Alice',
              'icon': {'type': 'Image', 'url': 'http://pic'},
          }}),
        ):
            with self.subTest(expected=expected, as2=as2):
                obj = Object(id='x', as2=as2)
                self.assert_multiline_in(expected, obj.actor_link(),
                                         ignore_blanks=True)

        self.assertEqual(
            '<a class="h-card u-author" href="http://foo">foo</a>',
            Object(id='x', our_as1={'actor': {'id': 'http://foo'}}).actor_link())

    def test_actor_link_user(self):
        self.user = Fake(id='fake:user', obj=Object(id='a', as2={"name": "Alice"}))
        obj = Object(id='x', source_protocol='ui', users=[self.user.key])

        got = obj.actor_link(user=self.user)
        self.assertIn('href="web:fake:user" title="Alice">', got)
        self.assertIn('Alice', got)

    def test_actor_link_object_in_datastore(self):
        Object(id='fake:alice', as2={'name': 'Alice'}).put()
        obj = Object(id='fake:bob', source_protocol='fake',
                     our_as1={'actor': 'fake:alice'})
        self.assertIn('Alice', obj.actor_link())

    def test_actor_link_no_image(self):
        obj = Object(id='x', our_as1={
            'actor': {
                'displayName': 'Alice',
                'image': 'foo.jpg',
            },
        })
        self.assert_multiline_equals(
            '<a class="h-card u-author" href="">Alice</a>',
            obj.actor_link(image=False))

    def test_actor_link_sized(self):
        obj = Object(id='x', our_as1={
            'actor': {
                'displayName': 'Alice',
                'image': 'foo.jpg',
            },
        })
        self.assert_multiline_equals("""\
<a class="h-card u-author" href="" title="Alice">
  <img class="profile" src="foo.jpg" width="32"/>
  <span style="unicode-bidi: isolate">Alice</span>
</a>""", obj.actor_link(sized=True), ignore_blanks=True)

    def test_actor_link_composite_url(self):
        obj = Object(id='x', our_as1={
            'actor': {
                'url': {
                    'value': 'https://mas.to/@foo',
                }
            },
        })
        self.assert_multiline_equals(
            '<a class="h-card u-author" href="https://mas.to/@foo">mas.to/@foo</a>',
            obj.actor_link(image=False))

    def test_computed_properties_without_as1(self):
        Object(id='a').put()

    def test_expire(self):
        obj = Object(id='a', our_as1={'objectType': 'activity', 'verb': 'update'})
        self.assertEqual(NOW + OBJECT_EXPIRE_AGE, obj.expire)

        obj.our_as1['verb'] = 'like'
        self.assertIsNone(obj.expire)

        obj.our_as1['objectType'] = 'note'
        self.assertIsNone(obj.expire)

        obj.our_as1['objectType'] = 'person'
        self.assertIsNone(obj.expire)

        obj.deleted = True
        self.assertEqual(NOW + timedelta(days=1), obj.expire)

    def test_as1_from_as2(self):
        self.assert_equals({
            'objectType': 'person',
            'id': 'https://mas.to/users/swentel',
            'displayName': 'Mrs. ☕ Foo',
            'image': [{'url': 'https://user.com/me.jpg'}],
            'inbox': 'http://mas.to/inbox',
        }, Object(as2=ACTOR).as1, ignore=['publicKey'])

        self.assertEqual({'foo': 'bar'}, Object(our_as1={'foo': 'bar'}).as1)
        self.assertEqual({'id': 'x', 'foo': 'bar'},
                         Object(id='x', our_as1={'foo': 'bar'}).as1)

    def test_as1_from_as2_protocol_bot_user(self):
        self.assert_equals({
            'objectType': 'service',
            'id': 'fed.brid.gy',
            'url': 'https://fed.brid.gy/',
            'displayName': 'Bridgy Fed',
            'username': 'fed.brid.gy',
            'image': [{
                'displayName': 'Bridgy Fed',
                'url': 'https://fed.brid.gy/static/bridgy_logo_square.jpg',
            }, {
                'objectType': 'featured',
                'url': 'https://fed.brid.gy/static/bridgy_fed_banner.png',
            }],
            'alsoKnownAs': ['https://fed.brid.gy/'],
            'manuallyApprovesFollowers': False,
        }, Web.load('https://fed.brid.gy/').as1, ignore=['summary'])

    def test_atom_url_overrides_id(self):
        obj = Object(our_as1={
            'objectType': 'note',
            'id': 'bad',
            'url': 'good',
        }, source_protocol='web')
        self.assert_equals('good', obj.as1['id'])

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_as1_from_bsky(self, mock_get):
        like_bsky = {
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:alice/post/123',
                'cid': 'TODO',
            },
        }
        like_as1 = {
            'objectType': 'activity',
            'verb': 'like',
            'id': 'at://did:plc:foo/like/123',
            'actor': 'did:plc:foo',
            'object': 'at://did:plc:alice/post/123',
        }

        obj = Object(id='at://did:plc:foo/like/123', bsky=like_bsky)
        self.assert_equals(like_as1, obj.as1)

    def test_as1_from_bsky_image_blob(self):
        self.store_object(id='did:web:alice.com', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://alice.com'],
        })

        obj = Object(id='at://did:web:alice.com/app.bsky.actor.profile/self', bsky={
            **ACTOR_PROFILE_BSKY,
            'banner': None,
        })
        self.assert_equals({
            **ACTOR_AS,
            'username': 'alice.com',
            'url': 'https://bsky.app/profile/alice.com',
            'urls': ['https://bsky.app/profile/alice.com', 'https://alice.com/'],
            'image': [{
                'url': 'https://some.pds/xrpc/com.atproto.sync.getBlob?did=did:web:alice.com&cid=bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq',
            }],
        }, obj.as1)

    def test_as1_from_bsky_messageView(self):
        self.store_object(id='did:alice', raw=DID_DOC)
        obj = Object(id='at://did:alice/chat.bsky.convo.defs.messageView/123', bsky={
            '$type': 'chat.bsky.convo.defs#messageView',
            'id': '123',
            'rev': '456',
            'sender': {'did': 'did:bob'},
            'text': 'foo bar',
        })
        self.assert_equals({
            'author': 'did:bob',
            'content': 'foo bar',
            'id': 'at://did:alice/chat.bsky.convo.defs.messageView/123',
            'objectType': 'note',
            'to': ['?'],
        }, obj.as1)

    def test_as1_from_bsky_unsupported_type(self):
        self.store_object(id='did:plc:user', raw=DID_DOC)
        obj = Object(id='at://did:plc:user/un.known/123', bsky={
            '$type': 'un.known',
            'foo': 'bar',
        })
        self.assertIsNone(obj.as1)

    def test_as1_from_mf2_uses_url_as_id(self):
        mf2 = {
            'properties': {
                'url': ['http://x', 'http://y'],
                'author': [{'properties': {'url': ['http://a', 'http://b']}}],
                'repost-of': [{'properties': {'url': ['http://c', 'http://d']}}],
            },
            'url': 'http://z',
        }
        obj = Object(mf2=mf2)
        self.assertEqual('http://z', obj.as1['id'])
        self.assertEqual('http://a', obj.as1['actor']['id'])
        self.assertEqual('http://c', obj.as1['object']['id'])

        # fragment URL should override final fetched URL
        obj = Object(id='http://foo#123', mf2=mf2)
        self.assertEqual('http://foo#123', obj.as1['id'])

        obj = Object(mf2={
            'properties': {
                'author': ['a', 'b'],
                'repost-of': ['c', 'd'],
            },
        })
        self.assertNotIn('id', obj.as1)
        self.assertNotIn('id', obj.as1['actor'])
        self.assertEqual(['c', 'd'], obj.as1['object'])

        obj = Object(mf2={
            'properties': {
                'uid': ['z.com'],
                'url': ['http://x'],
            },
        })
        self.assertEqual('z.com', obj.as1['id'])

    def test_as1_from_nostr_note(self):
        obj = Object(id='nostr:note123', nostr={
            'kind': 1,
            'id': '12ab',
            'content': 'Something to say',
            'created_at': 1641092645,
            'tags': [],
        })
        self.assert_equals({
            'objectType': 'note',
            'id': 'nostr:note1z24swknlsf',
            'content': 'Something to say',
            'published': '2022-01-02T03:04:05+00:00',
        }, obj.as1)

    def test_as1_image_proxy_domain(self):
        self.assert_equals({
            'id': 'https://www.threads.net/foo',
            'image': 'https://aujtzahimq.cloudimg.io/v7/http://pic?x&y',
        }, Object(our_as1={
            'id': 'https://www.threads.net/foo',
            'image': 'http://pic?x&y',
        }).as1)

        self.assert_equals({
            'id': 'https://www.threads.net/foo',
            'image': [
                'https://aujtzahimq.cloudimg.io/v7/http://pic/1',
                {'url': 'https://aujtzahimq.cloudimg.io/v7/http://pic/2'},
            ],
        }, Object(our_as1={
            'id': 'https://www.threads.net/foo',
            'image': ['http://pic/1', {'url': 'http://pic/2'}],
        }).as1)

    def test_validate_id(self):
        # DID repo ids
        Object(id='at://did:plc:123/app.bsky.feed.post/abc').put()
        Object(id='at://did:plc:foo.com/app.bsky.actor.profile/self').put()

        with self.assertRaises(ValueError):
            # non-DID (bare handle) repo id
            Object(id='at://foo.com/app.bsky.feed.post/abc').put()

    def test_put_strips_context(self):
        # no actor/object
        obj = Object(id='x', as2={
            '@context': ['baz', {'baj': 1}],
            'foo': 'bar'
        })
        obj.put()
        self.assertEqual({'foo': 'bar'}, obj.key.get().as2)

        # string actor/object
        obj.as2 = {
            '@context': ['baz', {'baj': 1}],
            'actor': 'baz',
            'object': 'baj',
            'foo': 'bar'
        }
        obj.put()
        self.assertEqual({
            'foo': 'bar',
            'actor': 'baz',
            'object': 'baj',
        }, obj.key.get().as2)

        # dict actor/object with @context
        obj.as2 = {
            '@context': ['baz', {'baj': 1}],
            'actor': {'@context': ['baz', {'baj': 1}]},
            'object': {'@context': ['baz', {'baj': 1}]},
            'foo': 'bar'
        }
        obj.put()
        self.assertEqual({
            'foo': 'bar',
            'actor': {},
            'object': {},
        }, obj.key.get().as2)

    def test_put_requires_protocol_owns_id(self):
        Object(id='asdf foo').put()  # ok, no source protocol
        Object(id='fake:foo', source_protocol='fake').put()  # ok, valid id

        with self.assertRaises(AssertionError):
            Object(id='not a fake', source_protocol='fake').put()

    def test_put_blocklisted_id(self):
        Object(id='asdf foo').put()  # ok, no source protocol
        Object(id='fake:foo', source_protocol='fake').put()  # ok, valid id

        with self.assertRaises(AssertionError):
            Object(id='not a fake', source_protocol='fake').put()

    def test_resolve_ids_empty(self):
        obj = Object()
        obj.resolve_ids()
        self.assertIsNone(obj.as1)

    def test_resolve_ids_copies_follow(self):
        follow = {
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }
        obj = Object(our_as1=follow, source_protocol='fake')

        # no matching copy users
        obj.resolve_ids()
        self.assert_equals(follow, obj.our_as1)

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.pickle_memcache.client_pool.clear()

        # matching copy users
        self.make_user('other:alice', cls=OtherFake,
                       copies=[Target(uri='fake:alice', protocol='fake')])
        self.make_user('other:bob', cls=OtherFake,
                       copies=[Target(uri='fake:bob', protocol='fa')])
        obj.resolve_ids()
        self.assert_equals({
            **follow,
            'actor': 'other:alice',
            'object': 'other:bob',
        }, obj.our_as1)

    def test_resolve_ids_copies_reply(self):
        reply = {
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'fake:reply',
                'objectType': 'note',
                'inReplyTo': 'fake:post',
                'author': {
                    'id': 'fake:alice',
                },
                'tags': [{
                    'objectType': 'mention',
                    'url': 'fake:bob',
                }],
            },
        }
        obj = Object(our_as1=reply, source_protocol='fake')

        # no matching copy users or objects
        obj.resolve_ids()
        self.assert_equals(reply, obj.our_as1)

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.pickle_memcache.client_pool.clear()

        # matching copies
        self.make_user('other:alice', cls=OtherFake,
                       copies=[Target(uri='fake:alice', protocol='fake')])
        self.make_user('other:bob', cls=OtherFake,
                       copies=[Target(uri='fake:bob', protocol='fake')])
        self.store_object(id='other:post',
                          copies=[Target(uri='fake:post', protocol='fa')])
        self.store_object(id='other:reply',
                          copies=[Target(uri='fake:reply', protocol='fake')])

        obj.resolve_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'other:reply',
                'objectType': 'note',
                'inReplyTo': 'other:post',
                'author': 'other:alice',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'other:bob',
                }],
            },
        }, obj.our_as1)

    def test_resolve_ids_multiple_in_reply_to(self):
        note = {
            'id': 'fake:note',
            'objectType': 'note',
            'inReplyTo': ['fake:a', 'fake:b'],
        }
        obj = Object(our_as1=note, source_protocol='fake')

        # no matching copy users or objects
        obj.resolve_ids()
        self.assert_equals(note, obj.our_as1)

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.pickle_memcache.client_pool.clear()

        # matching copies
        self.store_object(id='other:a',
                          copies=[Target(uri='fake:a', protocol='fa')])
        self.store_object(id='other:b',
                          copies=[Target(uri='fake:b', protocol='fake')])
        obj.resolve_ids()
        self.assert_equals({
            'id': 'fake:note',
            'objectType': 'note',
            'inReplyTo': ['other:a', 'other:b'],
        }, obj.our_as1)

    def test_resolve_ids_subdomain_urls(self):
        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'id': 'https://fa.brid.gy/web/foo.com',
            'object': {
                'id': 'https://web.brid.gy/fa/fake:reply',
                'inReplyTo': 'https://ap.brid.gy/fa/fake:post',
                'author': 'https://bsky.brid.gy/ap/did:plc:123',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'https://ap.brid.gy/atproto/http://inst.com/@me',
                }],
            },
        }, source_protocol='fake')

        obj.resolve_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'post',
            'id': 'https://foo.com/',
            'object': {
                'id': 'fake:reply',
                'inReplyTo': 'fake:post',
                'author': 'did:plc:123',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'http://inst.com/@me',
                }],
            },
        }, obj.our_as1)

    def test_resolve_ids_quote_post_in_attachments(self):
        obj = Object(source_protocol='fake', our_as1={
            'objectType': 'note',
            'id': 'fake:quote',
            'attachments': [{
                'objectType': 'note',
                'id': 'other:copy',
            }],
        })

        self.store_object(id='fake:orig',
                          copies=[Target(uri='other:copy', protocol='other')])

        obj.resolve_ids()
        self.assert_equals({
            'objectType': 'note',
            'id': 'fake:quote',
            'attachments': [{
                'objectType': 'note',
                'id': 'fake:orig',
            }],
        }, obj.our_as1)

    def test_normalize_ids_empty(self):
        obj = Object()
        obj.normalize_ids()
        self.assertIsNone(obj.as1)

    def test_normalize_ids_follow_atproto(self):
        # for ATProto handle resolution
        self.store_object(id='did:plc:user', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://ha.nl'],
        })
        alice = self.make_user(id='did:plc:user', cls=ATProto)

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'https://bsky.app/profile/did:plc:123',
            'object': 'https://bsky.app/profile/ha.nl',
        })
        obj.normalize_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'did:plc:123',
            'object': 'did:plc:user',
        }, obj.our_as1)

    def test_normalize_ids_block(self):
        user = self.make_user('bob.com', cls=Web)

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'block',
            'actor': 'fake:alice',
            'object': 'https://bob.com/',
        })
        obj.normalize_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'block',
            'actor': 'fake:alice',
            'object': 'bob.com',
        }, obj.our_as1)

    def test_normalize_ids_reply(self):
        # for ATProto handle resolution
        self.store_object(id='did:plc:user', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://ha.nl'],
        })
        self.make_user(id='did:plc:user', cls=ATProto)

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'https://bsky.app/profile/ha.nl/post/456',
                'objectType': 'note',
                'inReplyTo': 'https://bsky.app/profile/did:plc:123/post/789',
                'author': 'https://bsky.app/profile/ha.nl',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'https://bsky.app/profile/did:plc:123',
                }],
            },
        })
        obj.normalize_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'at://did:plc:user/app.bsky.feed.post/456',
                'objectType': 'note',
                'inReplyTo': 'at://did:plc:123/app.bsky.feed.post/789',
                'author': 'did:plc:user',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'did:plc:123',
                }],
            },
        }, obj.our_as1)

    def test_get_original_user_key(self):
        self.assertIsNone(models.get_original_user_key('other:user'))
        models.get_original_user_key.cache_clear()
        memcache.pickle_memcache.client_pool.clear()
        user = self.make_user('fake:user', cls=Fake,
                              copies=[Target(uri='other:user', protocol='other')])
        self.assertEqual(user.key, models.get_original_user_key('other:user'))

    def test_get_original_object_key(self):
        self.assertIsNone(models.get_original_object_key('other:post'))
        models.get_original_object_key.cache_clear()
        memcache.pickle_memcache.client_pool.clear()
        obj = self.store_object(id='fake:post',
                                copies=[Target(uri='other:post', protocol='other')])
        self.assertEqual(obj.key, models.get_original_object_key('other:post'))

    def test_get_copy(self):
        obj = Object(id='x')
        self.assertIsNone(obj.get_copy(Fake))

        obj.source_protocol = 'other'
        self.assertEqual('x', obj.get_copy(OtherFake))

        obj.copies = [Target(uri='other:foo', protocol='other')]
        self.assertIsNone(obj.get_copy(Fake))

        obj.copies.append(Target(uri='fake:foo', protocol='fake'))
        self.assertEqual('fake:foo', obj.get_copy(Fake))

    def test_add_to_copies_updates_memcache(self):
        cache_key = memcache.memoize_key(
            models.get_original_object_key, 'other:x')
        self.assertIsNone(memcache.pickle_memcache.get(cache_key))

        obj = Object(id='x')
        copy = Target(protocol='other', uri='other:x')
        obj.add('copies', copy)

        self.assertEqual(obj.key, memcache.pickle_memcache.get(cache_key))

    def test_add_to_copies_doesnt_update_if_already_there(self):
        copy = Target(protocol='other', uri='other:x')
        user = Object(id='x', copies=[copy])
        user.add('copies', copy)

        cache_key = memcache.memoize_key(
            models.get_original_object_key, 'other:x')
        self.assertIsNone(memcache.pickle_memcache.get(cache_key))

    def test_remove(self):
        obj = Object(id='x', users=[ndb.Key(Web, 'user1'), ndb.Key(Web, 'user2')])
        obj.remove('users', ndb.Key(Web, 'user1'))
        self.assertEqual([ndb.Key(Web, 'user2')], obj.users)

    def test_remove_from_copies_deletes_from_get_original_object_memoize(self):
        copy = Target(protocol='other', uri='other:x')
        obj = Object(id='x', copies=[copy])
        obj.put()

        # check that it's memoized
        self.assertEqual(obj.key, models.get_original_object_key('other:x'))
        cache_key = memcache.memoize_key(models.get_original_object_key, 'other:x')
        self.assertEqual(obj.key, memcache.pickle_memcache.get(cache_key))

        obj.remove('copies', copy)
        obj.put()

        # check that it's no longer memoized
        models.get_original_object_key.cache_clear()  # lru_cache
        self.assertIsNone(models.get_original_object_key('other:x'))

    def test_remove_nonexistent_value_noop(self):
        user = ndb.Key(Web, 'user')
        obj = Object(id='x', users=[])
        obj.remove('users', user)
        self.assertEqual([], obj.users)

        obj.users = [user]
        obj.remove('users', ndb.Key(Web, 'other'))
        self.assertEqual([user], obj.users)

    def test_hydrate_note(self):
        self.store_object(id='fake:alice', our_as1=ACTOR_AS)
        # self.store_object(id='fake:post', our_as1=)

        note = {
            'objectType': 'note',
            'content': 'hello world',
            'author': 'fake:alice',
        }
        tasklets.wait_all(models.hydrate(note))

        self.assertEqual({
            'objectType': 'note',
            'content': 'hello world',
            'author': ACTOR_AS,
        }, note)

    def test_hydrate_repost(self):
        self.store_object(id='fake:alice', our_as1=ACTOR_AS)

        repost = {
            'objectType': 'activity',
            'verb': 'repost',
            'actor': 'fake:alice',
            'object': 'fake:post',
        }
        tasklets.wait_all(models.hydrate(repost))

        self.assertEqual({
            'objectType': 'activity',
            'verb': 'repost',
            'actor': ACTOR_AS,
            'object': 'fake:post',
        }, repost)

    def test_hydrate_like(self):
        self.store_object(id='fake:post', our_as1={
            'objectType': 'note',
            'content': 'hello world',
        })

        like = {
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
        }
        tasklets.wait_all(models.hydrate(like))

        self.assertEqual({
            'objectType': 'activity',
            'verb': 'like',
            'object': {
                'objectType': 'note',
                'id': 'fake:post',
                'content': 'hello world',
            },
        }, like)


class FollowerTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:foo', cls=Fake)
        self.other_user = self.make_user('other:bar', cls=OtherFake)

    def test_from_to_same_type_fails(self):
        with self.assertRaises(AssertionError):
            Follower(from_=Web.key_for('foo.com'), to=Web.key_for('bar.com')).put()

        with self.assertRaises(AssertionError):
            Follower.get_or_create(from_=Web(id='foo.com'), to=Web(id='bar.com'))

    def test_get_or_create(self):
        follower = Follower.get_or_create(from_=self.user, to=self.other_user)

        self.assertEqual(self.user.key, follower.from_)
        self.assertEqual(self.other_user.key, follower.to)
        self.assertEqual(1, Follower.query().count())

        follower2 = Follower.get_or_create(from_=self.user, to=self.other_user)
        self.assert_entities_equal(follower, follower2)
        self.assertEqual(1, Follower.query().count())

        Follower.get_or_create(to=self.user, from_=self.other_user)
        Follower.get_or_create(from_=self.user,
                               to=self.make_user('efake:baz', cls=ExplicitFake))
        self.assertEqual(3, Follower.query().count())

        # check that kwargs get set on existing entity
        follower = Follower.get_or_create(from_=self.user, to=self.other_user,
                                          status='inactive')
        got = follower.key.get()
        self.assertEqual('inactive', got.status)
