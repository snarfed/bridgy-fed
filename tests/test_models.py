# coding=utf-8
"""Unit tests for models.py."""
from arroba.mst import dag_cbor_cid
from Crypto.PublicKey import ECC
from flask import g
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY
from oauth_dropins.webutil.testutil import NOW

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from models import AtpNode, Follower, Object, OBJECT_EXPIRE_AGE, Target, User
import protocol
from protocol import Protocol
from web import Web

from .test_activitypub import ACTOR


class UserTest(TestCase):

    def setUp(self):
        super().setUp()
        g.user = self.make_user('y.z')

    def test_get_or_create(self):
        user = Fake.get_or_create('a.b')

        assert not user.direct
        assert user.mod
        assert user.public_exponent
        assert user.private_exponent
        assert user.p256_key

        # check that we can load the keys
        assert user.public_pem()
        assert user.private_pem()

        p256_key = ECC.import_key(user.p256_key)
        assert isinstance(p256_key, ECC.EccKey)
        self.assertEqual('NIST P-256', p256_key.curve)

        # direct should get set even if the user exists
        same = Fake.get_or_create('a.b', direct=True)
        user.direct = True
        self.assert_entities_equal(same, user, ignore=['updated'])

    def test_get_or_create_use_instead(self):
        user = Fake.get_or_create('a.b')
        user.use_instead = g.user.key
        user.put()

        self.assertEqual('y.z', Fake.get_or_create('a.b').key.id())

    def test_href(self):
        href = g.user.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(g.user.mod, href)
        self.assertIn(g.user.public_exponent, href)

    def test_public_pem(self):
        pem = g.user.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)

    def test_private_pem(self):
        pem = g.user.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)

    def test_user_page_path(self):
        self.assertEqual('/web/y.z', g.user.user_page_path())
        self.assertEqual('/web/y.z/followers', g.user.user_page_path('followers'))
        self.assertEqual('/fa/foo', self.make_user('foo', cls=Fake).user_page_path())

    def test_user_page_link(self):
        self.assertEqual('<a class="h-card u-author" href="/web/y.z"><img src="" class="profile"> y.z</a>', g.user.user_page_link())
        g.user.obj = Object(id='a', as2=ACTOR)
        self.assertEqual('<a class="h-card u-author" href="/web/y.z"><img src="https://user.com/me.jpg" class="profile"> Mrs. ☕ Foo</a>', g.user.user_page_link())

    def test_is_web_url(self):
        for url in 'y.z', '//y.z', 'http://y.z', 'https://y.z':
            self.assertTrue(g.user.is_web_url(url), url)

        for url in (None, '', 'user', 'com', 'com.user', 'ftp://y.z',
                    'https://user', '://y.z'):
            self.assertFalse(g.user.is_web_url(url), url)

    def test_name(self):
        self.assertEqual('y.z', g.user.name())

        g.user.obj = Object(id='a', as2={'id': 'abc'})
        self.assertEqual('y.z', g.user.name())

        g.user.obj = Object(id='a', as2={'name': 'alice'})
        self.assertEqual('alice', g.user.name())

    def test_readable_id(self):
        self.assertIsNone(g.user.readable_id)

    def test_as2(self):
        self.assertEqual({}, g.user.as2())

        obj = Object(id='foo')
        g.user.obj_key = obj.key  # doesn't exist
        self.assertEqual({}, g.user.as2())

        del g.user._obj
        obj.as2 = {'foo': 'bar'}
        obj.put()
        self.assertEqual({'foo': 'bar'}, g.user.as2())

    def test_load_multi(self):
        # obj_key is None
        alice = Fake(id='alice.com')
        alice.put()

        # obj_key points to nonexistent entity
        bob = Fake(id='bob.com', obj_key=Object(id='bob').key)
        bob.put()

        user = g.user.key.get()
        self.assertFalse(hasattr(user, '_obj'))
        self.assertFalse(hasattr(alice, '_obj'))
        self.assertFalse(hasattr(bob, '_obj'))

        User.load_multi([user, alice, bob])
        self.assertIsNotNone(user._obj)
        self.assertIsNone(alice._obj)
        self.assertIsNone(bob._obj)


class ObjectTest(TestCase):
    def setUp(self):
        super().setUp()
        g.user = None

    def test_target_hashable(self):
        target = Target(protocol='ui', uri='http://foo')

        # just check that these don't crash
        assert isinstance(id(target), int)
        {target: 'foo'}

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

        obj = Object.get_or_create('foo', our_as1={'content': 'foo'},
                                   source_protocol='ui', labels=['notification'])
        check([obj], Object.query().fetch())
        self.assertTrue(obj.new)
        self.assertIsNone(obj.changed)
        self.assertEqual('foo', obj.key.id())
        self.assertEqual({'content': 'foo', 'id': 'foo'}, obj.as1)
        self.assertEqual('ui', obj.source_protocol)
        self.assertEqual(['notification'], obj.labels)

        obj2 = Object.get_or_create('foo')
        self.assertFalse(obj2.new)
        self.assertFalse(obj2.changed)
        check(obj, obj2)
        check([obj2], Object.query().fetch())

        # non-null **props should be populated
        obj3 = Object.get_or_create('foo', our_as1={'content': 'bar'},
                                    source_protocol=None, labels=[])
        self.assertEqual('foo', obj3.key.id())
        self.assertEqual({'content': 'bar', 'id': 'foo'}, obj3.as1)
        self.assertEqual('ui', obj3.source_protocol)
        self.assertEqual(['notification'], obj3.labels)
        self.assertFalse(obj3.new)
        self.assertTrue(obj3.changed)
        check([obj3], Object.query().fetch())
        check(obj3, Object.get_by_id('foo'))

        obj4 = Object.get_or_create('foo', our_as1={'content': 'bar'})
        self.assertEqual({'content': 'bar', 'id': 'foo'}, obj4.as1)
        self.assertFalse(obj4.new)
        self.assertFalse(obj4.changed)
        check(obj4, Object.get_by_id('foo'))

        obj5 = Object.get_or_create('bar')
        self.assertTrue(obj5.new)
        self.assertIsNone(obj5.changed)

        obj6 = Object.get_or_create('baz', labels=['feed'])
        self.assertTrue(obj6.new)
        self.assertIsNone(obj6.changed)

        self.assertEqual(3, Object.query().count())

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

    def test_proxy_url(self):
        obj = Object(id='abc', source_protocol='bluesky')
        self.assertEqual('http://localhost/convert/bluesky/web/abc',
                         obj.proxy_url())

        obj = Object(id='ab#c', source_protocol='ui')
        self.assertEqual('http://localhost/convert/ui/web/ab^^c',
                         obj.proxy_url())

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

    def test_get_by_id_uses_cache(self):
        obj = Object(id='foo', our_as1={'x': 'y'})
        protocol.objects_cache['foo'] = obj
        loaded = Fake.load('foo')
        self.assert_entities_equal(obj, loaded)

        # check that it's a separate copy of the entity in the cache
        # https://github.com/snarfed/bridgy-fed/issues/558#issuecomment-1603203927
        loaded.our_as1 = {'a': 'b'}
        self.assertEqual({'x': 'y'}, Protocol.load('foo').our_as1)

    def test_put_cached_makes_copy(self):
        obj = Object(id='foo', our_as1={'x': 'y'})
        obj.put()
        obj.our_as1 = {'a': 'b'}
        # don't put()

        self.assertEqual({'x': 'y'}, Fake.load('foo').our_as1)

    def test_get_by_id_cached_makes_copy(self):
        obj = Object(id='foo', our_as1={'x': 'y'})
        protocol.objects_cache['foo'] = obj
        loaded = Fake.load('foo')
        self.assert_entities_equal(obj, loaded)

        # check that it's a separate copy of the entity in the cache
        # https://github.com/snarfed/bridgy-fed/issues/558#issuecomment-1603203927
        loaded.our_as1 = {'a': 'b'}
        self.assertEqual({'x': 'y'}, Protocol.load('foo').our_as1)

    def test_actor_link(self):
        for expected, as2 in (
                ('href="">', {}),
                ('href="http://foo">foo', {'actor': 'http://foo'}),
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
                self.assert_multiline_in(expected, obj.actor_link())

    def test_actor_link_user(self):
        g.user = Fake(id='user.com', obj=Object(id='a', as2={"name": "Alice"}))
        obj = Object(id='x', source_protocol='ui', users=[g.user.key])
        self.assertIn(
            'href="/fa/user.com"><img src="" class="profile"> Alice</a>',
            obj.actor_link())

    def test_put_updates_load_cache(self):
        obj = Object(id='x', as2={})
        obj.put()
        self.assert_entities_equal(obj, protocol.objects_cache['x'])

    def test_put_fragment_id_doesnt_update_load_cache(self):
        obj = Object(id='x#y', as2={})
        obj.put()
        self.assertNotIn('x#y', protocol.objects_cache)
        self.assertNotIn('x', protocol.objects_cache)

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

    def test_as_as2(self):
        obj = Object()
        self.assertEqual({}, obj.as_as2())

        obj.our_as1 = {}
        self.assertEqual({}, obj.as_as2())

        obj.our_as1 = {
            'objectType': 'person',
            'foo': 'bar',
        }
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'foo': 'bar',
        }, obj.as_as2())

        obj.as2 = {'baz': 'biff'}
        self.assertEqual({'baz': 'biff'}, obj.as_as2())

    def test_as1(self):
        self.assertEqual({
            'objectType': 'person',
            'id': 'https://mas.to/users/swentel',
            'displayName': 'Mrs. ☕ Foo',
            'image': [{'url': 'https://user.com/me.jpg'}],
            'inbox': 'http://mas.to/inbox',
        }, Object(as2=ACTOR).as1)

        self.assertEqual({'foo': 'bar'}, Object(our_as1={'foo': 'bar'}).as1)
        self.assertEqual({'id': 'x', 'foo': 'bar'},
                         Object(id='x', our_as1={'foo': 'bar'}).as1)

    def test_as1_from_mf2_uses_url_as_id(self):
        obj = Object(mf2={
            'properties': {
                'url': ['x', 'y'],
                'author': [{'properties': {'url': ['a', 'b']}}],
                'repost-of': [{'properties': {'url': ['c', 'd']}}],
            },
        })
        self.assertEqual('x', obj.as1['id'])
        self.assertEqual('a', obj.as1['actor']['id'])
        self.assertEqual('c', obj.as1['object']['id'])

        obj = Object(mf2={
            'properties': {
                'author': ['a', 'b'],
                'repost-of': ['c', 'd'],
            },
        })
        self.assertNotIn('id', obj.as1)
        self.assertNotIn('id', obj.as1['actor'])
        self.assertEqual(['c', 'd'], obj.as1['object'])


class FollowerTest(TestCase):

    def setUp(self):
        super().setUp()
        g.user = self.make_user('foo', cls=Fake)
        self.other_user = self.make_user('bar', cls=Fake)

    def test_from_to_same_type_fails(self):
        with self.assertRaises(AssertionError):
            Follower(from_=Web.key_for('foo.com'), to=Web.key_for('bar.com')).put()

        with self.assertRaises(AssertionError):
            Follower.get_or_create(from_=Web(id='foo.com'), to=Web(id='bar.com'))

    def test_get_or_create(self):
        follower = Follower.get_or_create(from_=g.user, to=self.other_user)

        self.assertEqual(g.user.key, follower.from_)
        self.assertEqual(self.other_user.key, follower.to)
        self.assertEqual(1, Follower.query().count())

        follower2 = Follower.get_or_create(from_=g.user, to=self.other_user)
        self.assert_entities_equal(follower, follower2)
        self.assertEqual(1, Follower.query().count())

        Follower.get_or_create(to=g.user, from_=self.other_user)
        Follower.get_or_create(from_=g.user, to=self.make_user('baz', cls=Fake))
        self.assertEqual(3, Follower.query().count())

        # check that kwargs get set on existing entity
        follower = Follower.get_or_create(from_=g.user, to=self.other_user,
                                          status='inactive')
        got = follower.key.get()
        self.assertEqual('inactive', got.status)


class AtpNodeTest(TestCase):

    def test_create(self):
        AtpNode.create(ACTOR_PROFILE_BSKY)
        stored = AtpNode.get_by_id(dag_cbor_cid(ACTOR_PROFILE_BSKY).encode('base32'))
        self.assertEqual(ACTOR_PROFILE_BSKY, stored.data)
