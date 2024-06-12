"""Unit tests for models.py."""
from datetime import timedelta
from unittest import skip
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
from arroba.mst import dag_cbor_cid
import arroba.server
from arroba.util import at_uri
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from google.cloud import ndb
from google.cloud.tasks_v2.types import Task
from granary.bluesky import NO_AUTHENTICATED_LABEL
from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_BSKY
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil import util
from werkzeug.exceptions import Forbidden

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitEnableFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub
from atproto import ATProto
import common
import models
from models import Follower, Object, OBJECT_EXPIRE_AGE, PROTOCOLS, Target, User
import protocol
from protocol import Protocol
from web import Web

from .test_activitypub import ACTOR
from .test_atproto import DID_DOC


class UserTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('y.z', cls=Web)

    def test_get_by_id_opted_out(self):
        self.assert_entities_equal(self.user, Web.get_by_id('y.z'))

        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        self.user.put()
        self.assertIsNone(Web.get_by_id('y.z'))

    def test_get_or_create(self):
        user = Fake.get_or_create('fake:user')

        assert not user.direct
        assert not user.existing
        assert user.mod
        assert user.public_exponent
        assert user.private_exponent

        # check that we can load the keys
        assert user.public_pem()
        assert user.private_pem()

        # direct should get set even if the user exists
        same = Fake.get_or_create('fake:user', direct=True)
        assert same.existing
        user.direct = True
        self.assert_entities_equal(same, user, ignore=['updated'])

    @patch('ids.COPIES_PROTOCOLS', ['fake', 'other'])
    def test_get_or_create_propagate_fake_other(self):
        user = Fake.get_or_create('fake:user', propagate=True)
        self.assertEqual(['fake:user'], OtherFake.created_for)

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_get_or_create_propagate_atproto(self, mock_post, mock_create_task):
        common.RUN_TASKS_INLINE = False

        Fake.fetchable = {
            'fake:profile:user': {
                **ACTOR_AS,
                'image': None,  # don't try to fetch as blob
            },
        }
        user = Fake.get_or_create('fake:user', propagate=True)

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
            'description': 'hi there\n\n[bridged from web:fake:user on fake-phrase by https://fed.brid.gy/ ]',
            'bridgyOriginalDescription': 'hi there',
            'bridgyOriginalUrl': 'https://alice.com/',
            'labels': {
                '$type': 'com.atproto.label.defs#selfLabels',
                'values': [{'val' : 'bridged-from-bridgy-fed-fake'}],
            },
        }, profile)

        uri = at_uri(did, 'app.bsky.actor.profile', 'self')
        self.assertEqual([Target(uri=uri, protocol='atproto')],
                         Object.get_by_id(id='fake:profile:user').copies)

        mock_create_task.assert_called()

    @patch('ids.COPIES_PROTOCOLS', ['eefake', 'atproto'])
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
        self.assertEqual([], user.copies)
        self.assertEqual(0, AtpRepo.query().count())

    def test_get_or_create_use_instead(self):
        user = Fake.get_or_create('fake:a')
        user.use_instead = self.user.key
        user.put()

        got = Fake.get_or_create('fake:a')
        self.assertEqual('y.z', got.key.id())
        assert got.existing

    def test_get_or_create_by_copies(self):
        other = self.make_user(id='other:ab', cls=OtherFake,
                               copies=[Target(uri='fake:ab', protocol='fake')])
        self.assert_entities_equal(other, Fake.get_or_create('fake:ab'))

    def test_get_or_create_opted_out(self):
        user = self.make_user('fake:user', cls=Fake,
                              obj_as1={'summary': '#nobridge'})
        self.assertIsNone(Fake.get_or_create('fake:user'))

    def test_public_pem(self):
        pem = self.user.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)

    def test_private_pem(self):
        pem = self.user.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)

    def test_user_page_path(self):
        self.assertEqual('/web/y.z', self.user.user_page_path())
        self.assertEqual('/web/y.z/followers', self.user.user_page_path('followers'))

        fake_foo = self.make_user('fake:foo', cls=Fake)
        self.assertEqual('/fa/fake:handle:foo', fake_foo.user_page_path())

    def test_user_link(self):
        self.assert_multiline_equals("""\
<span class="logo" title="Web">🌐</span>
<a class="h-card u-author" href="/web/y.z" title="y.z">
  y.z
</a>""", self.user.user_link(), ignore_blanks=True)

        self.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals("""\
<span class="logo" title="Web">🌐</span>
<a class="h-card u-author" href="/web/y.z" title="Mrs. ☕ Foo">
  <img src="https://user.com/me.jpg" class="profile">
  Mrs. ☕ Foo
</a>""", self.user.user_link())

    def test_is_web_url(self):
        for url in 'y.z', '//y.z', 'http://y.z', 'https://y.z':
            self.assertTrue(self.user.is_web_url(url), url)

        for url in (None, '', 'user', 'com', 'com.user', 'ftp://y.z',
                    'https://user', '://y.z'):
            self.assertFalse(self.user.is_web_url(url), url)

    def test_name(self):
        self.assertEqual('y.z', self.user.name())

        self.user.obj = Object(id='a', as2={'id': 'abc'})
        self.assertEqual('y.z', self.user.name())

        self.user.obj = Object(id='a', as2={'name': 'alice'})
        self.assertEqual('alice', self.user.name())

    def test_handle(self):
        self.assertEqual('y.z', self.user.handle)

    def test_id_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:user', user.id_as(Fake))
        self.assertEqual('fake:user', user.id_as('fake'))
        self.assertEqual('https://fa.brid.gy/ap/fake:user', user.id_as('ap'))

    def test_handle_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:handle:user', user.handle_as(Fake))
        self.assertEqual('fake:handle:user', user.handle_as('fake'))
        self.assertEqual('@fake:handle:user@fa.brid.gy', user.handle_as('ap'))

    def test_handle_as_web_custom_username(self, *_):
        self.user.obj.our_as1 = {
            'objectType': 'person',
            'url': 'acct:alice@y.z',
        }
        self.assertEqual('alice', self.user.username())
        self.assertEqual('@y.z@web.brid.gy', self.user.handle_as('ap'))

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

        user = self.user.key.get()
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
            'to': [{'objectType': 'group', 'alias': '@unlisted'}],
        })
        self.assertEqual('opt-out', user.status)

        user.obj.our_as1.update({
            'summary': 'well #nobot yeah',
            'to': None,
        })
        self.assertEqual('opt-out', user.status)

        user.obj.our_as1.update({
            'summary': '🤷',
            # This is Mastodon's HTML around hashtags
            'displayName': '<a href="..." class="hashtag">#<span>nobridge</span></a>',
        })
        self.assertEqual('opt-out', user.status)

        user = User(manual_opt_out=True)
        self.assertEqual('opt-out', user.status)

    @patch.object(Fake, 'REQUIRES_AVATAR', True)
    def test_requires_avatar(self):
        user = self.make_user(id='fake:user', cls=Fake,
                              obj_as1={'displayName': 'Alice'})
        self.assertEqual('blocked', user.status)

        user.enabled_protocols = ['eefake']
        self.assertEqual('blocked', user.status)

        user.obj.our_as1['image'] = 'http://pic'
        self.assertIsNone(user.status)

    @patch.object(Fake, 'REQUIRES_NAME', True)
    def test_requires_name(self):
        user = self.make_user(id='fake:user', cls=Fake,
                              obj_as1={'image': 'http://pic'})
        self.assertEqual('blocked', user.status)

        user.obj.our_as1['displayName'] = 'fake:user'
        self.assertEqual('blocked', user.status)

        user.obj.our_as1['displayName'] = 'fake:handle:user'
        self.assertEqual('blocked', user.status)

        user.enabled_protocols = ['eefake']
        self.assertEqual('blocked', user.status)

        user.obj.our_as1['displayName'] = 'Alice'
        self.assertIsNone(user.status)

    @patch.object(Fake, 'REQUIRES_OLD_ACCOUNT', True)
    def test_requires_old_account(self):
        user = self.make_user(id='fake:user', cls=Fake, obj_as1={
            'foo': 'bar',
        })
        self.assertIsNone(user.status)

        too_young = util.now() - common.OLD_ACCOUNT_AGE + timedelta(minutes=1)
        user.obj.our_as1['published'] = too_young.isoformat()
        self.assertEqual('blocked', user.status)

        user.enabled_protocols = ['eefake']
        self.assertEqual('blocked', user.status)

        user.obj.our_as1['published'] = (too_young - timedelta(minutes=2)).isoformat()
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

        # still cached
        user = Web.get_by_id('y.z')
        self.assertEqual((0, 0), user.count_followers())

        User.count_followers.cache.clear()
        del self.user
        self.assertEqual((1, 2), user.count_followers())

    def test_is_enabled_default_enabled_protocols(self):
        self.assertTrue(Web(id='').is_enabled(ActivityPub))
        self.assertTrue(ActivityPub(id='').is_enabled(Web))
        self.assertTrue(ActivityPub(id='').is_enabled(ActivityPub))
        self.assertTrue(Fake(id='').is_enabled(OtherFake))
        self.assertTrue(Fake(id='').is_enabled(ExplicitEnableFake))

        self.assertFalse(ActivityPub(id='').is_enabled(ATProto))
        self.assertFalse(ATProto(id='').is_enabled(ActivityPub))
        self.assertFalse(ATProto(id='').is_enabled(Web))
        self.assertFalse(Web(id='').is_enabled(ATProto))
        self.assertFalse(ExplicitEnableFake(id='').is_enabled(Fake))
        self.assertFalse(ExplicitEnableFake(id='').is_enabled(Web))

    def test_is_enabled_default_enabled_protocols_explicit(self):
        self.user.enabled_protocols = ['atproto']
        self.assertTrue(self.user.is_enabled(ATProto, explicit=True))

        assert 'activitypub' in Web.DEFAULT_ENABLED_PROTOCOLS
        self.assertFalse(self.user.is_enabled(ActivityPub, explicit=True))

    def test_is_enabled_enabled_protocols_overrides_bio_opt_out(self):
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              obj_as1={'summary': '#nobridge'})
        self.assertFalse(user.is_enabled(Web))
        self.assertEqual('opt-out', user.status)

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
        self.assertEqual('opt-out', user.status)

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
        user = self.make_user(id='eefake:foo', cls=ExplicitEnableFake)
        self.assertFalse(user.is_enabled(Fake))

        user.enabled_protocols = ['web']
        user.put()
        self.assertFalse(user.is_enabled(Fake))

        user.enabled_protocols = ['web', 'fake']
        user.put()
        self.assertTrue(user.is_enabled(Fake))

    def test_is_enabled_protocol_bot_users(self):
        # protocol bot users should always be enabled to *other* protocols
        self.assertTrue(Web(id='eefake.brid.gy').is_enabled(Fake))
        self.assertTrue(Web(id='fa.brid.gy').is_enabled(ExplicitEnableFake))
        self.assertTrue(Web(id='other.brid.gy').is_enabled(Fake))
        self.assertTrue(Web(id='ap.brid.gy').is_enabled(ATProto))
        self.assertTrue(Web(id='bsky.brid.gy').is_enabled(ActivityPub))

        # ...but not to their own protocol
        self.assertFalse(Web(id='ap.brid.gy').is_enabled(ActivityPub))
        self.assertFalse(Web(id='bsky.brid.gy').is_enabled(ATProto))


class ObjectTest(TestCase):
    def setUp(self):
        super().setUp()
        self.user = None

    def test_target_hashable(self):
        target = Target(protocol='ui', uri='http://foo')

        # just check that these don't crash
        assert isinstance(id(target), int)

    def test_ndb_in_memory_cache_off(self):
        """It has a weird bug that we want to avoid.

        https://github.com/googleapis/python-ndb/issues/888
        """
        from google.cloud.ndb import Model, StringProperty
        class Foo(Model):
            a = StringProperty()

        f = Foo(id='x', a='asdf')
        f.put()
        # print(id(f))

        f.a = 'qwert'

        got = Foo.get_by_id('x')
        # print(got)
        # print(id(got))
        self.assertEqual('asdf', got.a)

    def test_get_or_create(self):
        def check(obj1, obj2):
            self.assert_entities_equal(obj1, obj2, ignore=['expire', 'updated'])

        self.assertEqual(0, Object.query().count())

        user = ndb.Key(Web, 'user.com')
        obj = Object.get_or_create('fake:foo', our_as1={'content': 'foo'},
                                   source_protocol='fake', notify=[user])
        check([obj], Object.query().fetch())
        self.assertTrue(obj.new)
        self.assertIsNone(obj.changed)
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
        self.assertIsNone(obj5.changed)

        obj6 = Object.get_or_create('baz', notify=[ndb.Key(Web, 'other')])
        self.assertTrue(obj6.new)
        self.assertIsNone(obj6.changed)

        self.assertEqual(3, Object.query().count())

        # if no data property is set, don't clear existing data properties
        obj7 = Object.get_or_create('http://b.i/ff', as2={'a': 'b'}, mf2={'c': 'd'},
                                    source_protocol='web')
        Object.get_or_create('http://b.i/ff', authed_as='http://b.i/ff',
                             users=[ndb.Key(Web, 'me')])
        self.assert_object('http://b.i/ff', as2={'a': 'b'}, mf2={'c': 'd'},
                           users=[ndb.Key(Web, 'me')],
                           source_protocol='web')

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

    def test_get_or_create_auth_check_profile_id(self):
        Object(id='fake:profile:alice', source_protocol='fake',
               our_as1={'x': 'y'}).put()

        obj = Object.get_or_create('fake:profile:alice', authed_as='fake:alice',
                                   our_as1={'x': 'z'})
        self.assertEqual({'id': 'fake:profile:alice', 'x': 'z'}, obj.as1)

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

    def test_put(self):
        with self.assertRaises(AssertionError):
            Object(id='x^^y').put()

    def test_get_by_id(self):
        self.assertIsNone(Object.get_by_id('abc'))
        self.assertIsNone(Object.get_by_id('ab^^c'))

        obj = Object(id='abc')
        obj.put()
        self.assertIsNotNone(obj, Object.get_by_id('abc'))

        obj = Object(id='ab#c')
        obj.put()
        self.assert_entities_equal(obj, Object.get_by_id('ab^^c'))


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
          Alice""", {'actor': {
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
  Alice
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

    def test_put_adds_removes_activity_label(self):
        obj = Object(id='x#y', our_as1={})
        obj.put()
        self.assertEqual([], obj.labels)

        obj.our_as1 = {'objectType': 'activity'}
        obj.put()
        self.assertEqual(['activity'], obj.labels)

        obj.labels = ['user']
        obj.put()
        self.assertEqual(['user', 'activity'], obj.labels)

        obj.labels = ['activity', 'user']
        obj.put()
        self.assertEqual(['activity', 'user'], obj.labels)

        obj.our_as1 = {'foo': 'bar'}
        obj.put()
        self.assertEqual(['user'], obj.labels)

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
            'objectType': 'application',
            'id': 'fed.brid.gy',
            'url': 'https://fed.brid.gy/',
            'displayName': 'Bridgy Fed',
            'username': 'fed.brid.gy',
            'image': [{
                'displayName': 'Bridgy Fed',
                'url': 'https://fed.brid.gy/static/bridgy_logo_square.jpg',
            }, {
                'objectType': 'featured',
                'url': 'https://fed.brid.gy/static/bridgy_logo.jpg',
            }],
        }, Web.load('https://fed.brid.gy/').as1, ignore=['summary'])

    def test_atom_url_overrides_id(self):
        obj = {
            'objectType': 'note',
            'id': 'bad',
            'url': 'good',
        }
        self.assert_equals('good', Object(our_as1=obj, atom='trigger').as1['id'])

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
            'url': ['https://bsky.app/profile/alice.com', 'https://alice.com/'],
            'image': [{
                'url': 'https://some.pds/xrpc/com.atproto.sync.getBlob?did=did:web:alice.com&cid=bafkreim',
            }],
        }, obj.as1)

    def test_as1_from_mf2_uses_url_as_id(self):
        mf2 = {
            'properties': {
                'url': ['x', 'y'],
                'author': [{'properties': {'url': ['a', 'b']}}],
                'repost-of': [{'properties': {'url': ['c', 'd']}}],
            },
            'url': 'z',
        }
        obj = Object(mf2=mf2)
        self.assertEqual('z', obj.as1['id'])
        self.assertEqual('a', obj.as1['actor']['id'])
        self.assertEqual('c', obj.as1['object']['id'])

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
                'url': ['x'],
            },
        })
        self.assertEqual('z.com', obj.as1['id'])

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
            'verb': 'create',
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
            'verb': 'create',
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
            'verb': 'create',
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
            'verb': 'create',
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

    def test_normalize_ids_empty(self):
        obj = Object()
        obj.normalize_ids()
        self.assertIsNone(obj.as1)

    def test_normalize_ids_follow_atproto(self):
        # for ATProto handle resolution
        self.store_object(id='did:plc:user', raw=DID_DOC)
        alice = self.make_user(id='did:plc:user', cls=ATProto)

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'https://bsky.app/profile/did:plc:123',
            'object': 'https://bsky.app/profile/han.dull',
        })
        obj.normalize_ids()
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'did:plc:123',
            'object': 'did:plc:user',
        }, obj.our_as1)

    def test_normalize_ids_reply(self):
        # for ATProto handle resolution
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.make_user(id='did:plc:user', cls=ATProto)

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'https://bsky.app/profile/han.dull/post/456',
                'objectType': 'note',
                'inReplyTo': 'https://bsky.app/profile/did:plc:123/post/789',
                'author': 'https://bsky.app/profile/han.dull',
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

    def test_get_originals(self):
        self.assertEqual([], models.get_originals(['foo', 'did:plc:bar']))

        obj = self.store_object(id='fake:post',
                                copies=[Target(uri='other:foo', protocol='other')])
        user = self.make_user('other:user', cls=OtherFake,
                              copies=[Target(uri='fake:bar', protocol='fake')])

        self.assert_entities_equal(
            [obj, user], models.get_originals(['other:foo', 'fake:bar', 'baz']))

    def test_get_copy(self):
        obj = Object(id='x')
        self.assertIsNone(obj.get_copy(Fake))

        obj.source_protocol = 'other'
        self.assertEqual('x', obj.get_copy(OtherFake))

        obj.copies = [Target(uri='other:foo', protocol='other')]
        self.assertIsNone(obj.get_copy(Fake))

        obj.copies.append(Target(uri='fake:foo', protocol='fake'))
        self.assertEqual('fake:foo', obj.get_copy(Fake))


class FollowerTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:foo', cls=Fake)
        self.other_user = self.make_user('fake:bar', cls=Fake)

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
        Follower.get_or_create(from_=self.user, to=self.make_user('fake:baz', cls=Fake))
        self.assertEqual(3, Follower.query().count())

        # check that kwargs get set on existing entity
        follower = Follower.get_or_create(from_=self.user, to=self.other_user,
                                          status='inactive')
        got = follower.key.get()
        self.assertEqual('inactive', got.status)
