"""Unit tests for models.py."""
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob
from arroba.mst import dag_cbor_cid
import arroba.server
from arroba.util import at_uri
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from flask import g
from google.cloud import ndb
from google.cloud.tasks_v2.types import Task
from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_BSKY
from multiformats import CID
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil import util

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from atproto import ATProto
from models import Follower, Object, OBJECT_EXPIRE_AGE, Target, User
import protocol
from protocol import Protocol
from web import Web

from .test_activitypub import ACTOR
from .test_atproto import DID_DOC


class UserTest(TestCase):

    def setUp(self):
        super().setUp()
        g.user = self.make_user('y.z', cls=Web)

    def test_get_or_create(self):
        user = Fake.get_or_create('fake:user')

        assert not user.direct
        assert user.mod
        assert user.public_exponent
        assert user.private_exponent

        # check that we can load the keys
        assert user.public_pem()
        assert user.private_pem()

        # direct should get set even if the user exists
        same = Fake.get_or_create('fake:user', direct=True)
        user.direct = True
        self.assert_entities_equal(same, user, ignore=['updated'])

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_get_or_create_propagate(self, mock_post, mock_create_task):
        Fake.fetchable = {
            'fake:user': {
                **ACTOR_AS,
                'image': None,  # don't try to fetch as blob
            },
        }

        user = Fake.get_or_create('fake:user', propagate=True)

        # check that profile was fetched remotely
        self.assertEqual(['fake:user'], Fake.fetched)

        # check user, repo
        user = Fake.get_by_id('fake:user')
        self.assertEqual('fake:handle:user', user.handle)
        self.assertEqual([Target(uri=user.atproto_did, protocol='atproto')],
                         user.copies)
        repo = arroba.server.storage.load_repo(user.atproto_did)

        # check profile record
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there',
        }, profile)

        uri = at_uri(user.atproto_did, 'app.bsky.actor.profile', 'self')
        self.assertEqual([Target(uri=uri, protocol='atproto')],
                         Object.get_by_id(id='fake:user').copies)

        mock_create_task.assert_called()

    def test_get_or_create_propagate_reloads_existing_profile_object(self):
        self.store_object(id='fake:user', our_as1={
            'objectType': 'person',
            'foo': 'bar',
        })
        self.test_get_or_create_propagate()

    def test_validate_atproto_did(self):
        user = Fake()

        with self.assertRaises(ValueError):
            user.atproto_did = 'did:foo:bar'

        user.atproto_did = 'did:plc:123'
        user.atproto_did = None

    def test_get_for_copies(self):
        self.assertEqual([], User.get_for_copies(['did:plc:foo']))

        target = Target(uri='did:plc:foo', protocol='atproto')
        fake_user = self.make_user('fake:user', cls=Fake, copies=[target])
        self.assertEqual([fake_user], User.get_for_copies(['did:plc:foo']))

    def test_get_or_create_use_instead(self):
        user = Fake.get_or_create('a.b')
        user.use_instead = g.user.key
        user.put()

        self.assertEqual('y.z', Fake.get_or_create('a.b').key.id())

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

    def test_user_link(self):
        self.assert_multiline_equals("""\
<a class="h-card u-author" href="https://y.z/">
  <img src="" class="profile">
  y.z</a>""", g.user.user_link())

        g.user.obj = Object(id='a', as2=ACTOR)
        self.assert_multiline_equals("""\
<a class="h-card u-author" href="https://y.z/">
<img src="https://user.com/me.jpg" class="profile">
  Mrs. ☕ Foo</a>""", g.user.user_link())

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

    def test_handle(self):
        self.assertEqual('y.z', g.user.handle)

    def test_as2(self):
        self.assertEqual({}, g.user.as2())

        obj = Object(id='foo')
        g.user.obj_key = obj.key  # doesn't exist
        self.assertEqual({}, g.user.as2())

        del g.user._obj
        obj.as2 = {'foo': 'bar'}
        obj.put()
        self.assertEqual({'foo': 'bar'}, g.user.as2())

    def test_id_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:user', user.id_as(Fake))
        self.assertEqual('fake:user', user.id_as('fake'))
        self.assertEqual('http://localhost/fa/ap/fake:user', user.id_as('ap'))

    def test_handle_as(self):
        user = self.make_user('fake:user', cls=Fake)
        self.assertEqual('fake:handle:user', user.handle_as(Fake))
        self.assertEqual('fake:handle:user', user.handle_as('fake'))
        self.assertEqual('@fake:handle:user@fa.brid.gy', user.handle_as('ap'))

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_ap_actor(self, mock_get):
        user = self.make_user('did:plc:abc', cls=ATProto)
        self.assertEqual('https://atproto.brid.gy/ap/did:plc:abc',
                         user.ap_actor())
        self.assertEqual('https://atproto.brid.gy/ap/did:plc:abc/foo',
                         user.ap_actor(rest='foo'))

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
        obj = Object.get_or_create('foo', our_as1={'content': 'foo'},
                                   source_protocol='ui', notify=[user])
        check([obj], Object.query().fetch())
        self.assertTrue(obj.new)
        self.assertIsNone(obj.changed)
        self.assertEqual('foo', obj.key.id())
        self.assertEqual({'content': 'foo', 'id': 'foo'}, obj.as1)
        self.assertEqual('ui', obj.source_protocol)
        self.assertEqual([user], obj.notify)

        obj2 = Object.get_or_create('foo')
        self.assertFalse(obj2.new)
        self.assertFalse(obj2.changed)
        check(obj, obj2)
        check([obj2], Object.query().fetch())

        # non-null **props should be populated
        obj3 = Object.get_or_create('foo', our_as1={'content': 'bar'},
                                    source_protocol=None, notify=[])
        self.assertEqual('foo', obj3.key.id())
        self.assertEqual({'content': 'bar', 'id': 'foo'}, obj3.as1)
        self.assertEqual('ui', obj3.source_protocol)
        self.assertEqual([user], obj3.notify)
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

        obj6 = Object.get_or_create('baz', notify=[ndb.Key(Web, 'other')])
        self.assertTrue(obj6.new)
        self.assertIsNone(obj6.changed)

        self.assertEqual(3, Object.query().count())

        # if no data property is set, don't clear existing data properties
        obj7 = Object.get_or_create('biff', as2={'a': 'b'}, mf2={'c': 'd'})
        Object.get_or_create('biff', users=[ndb.Key(Web, 'me')])
        self.assert_object('biff', as2={'a': 'b'}, mf2={'c': 'd'},
                           users=[ndb.Key(Web, 'me')])

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
        obj = Object(id='abc', source_protocol='activitypub')
        self.assertEqual('https://ap.brid.gy/convert/web/abc',
                         obj.proxy_url())

        obj = Object(id='ab#c', source_protocol='ui')
        self.assertEqual('https://fed.brid.gy/convert/web/ab%23c',
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
                self.assert_multiline_in(expected, obj.actor_link())

        self.assertEqual(
            '<a class="h-card u-author" href="http://foo">foo</a>',
            Object(id='x', our_as1={'actor': {'id': 'http://foo'}}).actor_link())

    def test_actor_link_user(self):
        g.user = Fake(id='fake:user', obj=Object(id='a', as2={"name": "Alice"}))
        obj = Object(id='x', source_protocol='ui', users=[g.user.key])

        got = obj.actor_link()
        self.assertIn('href="fake:user">', got)
        self.assertIn('Alice', got)

    def test_actor_link_object_in_datastore(self):
        Object(id='fake:alice', as2={"name": "Alice"}).put()
        obj = Object(id='x', source_protocol='fake', our_as1={'actor': 'fake:alice'})
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
</a>""", obj.actor_link(sized=True))

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

    def test_as1_from_as2(self):
        self.assert_equals({
            'objectType': 'person',
            'id': 'https://mas.to/users/swentel',
            'displayName': 'Mrs. ☕ Foo',
            'image': [{'url': 'https://user.com/me.jpg'}],
            'inbox': 'http://mas.to/inbox',
        }, Object(as2=ACTOR).as1)

        self.assertEqual({'foo': 'bar'}, Object(our_as1={'foo': 'bar'}).as1)
        self.assertEqual({'id': 'x', 'foo': 'bar'},
                         Object(id='x', our_as1={'foo': 'bar'}).as1)

    @patch('requests.get', return_value=requests_response(DID_DOC))
    def test_as1_from_bsky(self, mock_get):
        like_bsky = {
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'http://example.com/original/post',
                'cid': 'TODO',
            },
        }
        like_as1 = {
            'objectType': 'activity',
            'verb': 'like',
            'id': 'at://did:plc:foo/co.ll/123',
            'actor': 'did:plc:foo',
            'object': 'http://example.com/original/post',
        }

        # no user
        obj = Object(id='at://did:plc:foo/co.ll/123', bsky=like_bsky)
        self.assert_equals(like_as1, obj.as1)

        # matching user without Object
        user = Fake(id='fake:user',
                    copies=[Target(uri='did:plc:foo', protocol='atproto')])
        user.put()
        self.assertEqual({
            **like_as1,
            'actor': 'fake:user',
        }, obj.as1)

        # matching user with Object
        user.obj = self.store_object(id='at://did:plc:foo/profile/self',
                                     our_as1={'foo': 'bar'})
        user.put()
        self.assertEqual({
            **like_as1,
            'actor': {
                'id': 'fake:user',
                'foo': 'bar',
            },
        }, obj.as1)

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

    def test_as_bsky_blobs_false(self):
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
        }, Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }).as_bsky())

    @patch('requests.get', return_value=requests_response(
        'blob contents', content_type='image/png'))
    def test_as_bsky_fetch_blobs_true(self, mock_get):
        cid = CID.decode('bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'avatar': {
                '$type': 'blob',
                'ref': cid,
                'mimeType': 'image/png',
                'size': 13,
            },
        }, Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }).as_bsky(fetch_blobs=True))

        mock_get.assert_has_calls([self.req('http://my/pic')])

    def test_as_bsky_fetch_blobs_true_existing_atp_remote_blob(self):
        cid = 'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq'
        AtpRemoteBlob(id='http://my/pic', cid=cid, size=8).put()

        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'avatar': {
                '$type': 'blob',
                'ref': CID.decode(cid),
                'mimeType': 'application/octet-stream',
                'size': 8,
            },
        }, Object(our_as1={
            'objectType': 'person',
            'id': 'did:web:alice.com',
            'displayName': 'Alice',
            'image': [{'url': 'http://my/pic'}],
        }).as_bsky(fetch_blobs=True))

    def test_clear(self):
        ab = {'a': 'b'}
        obj = Object(our_as1=ab, as2=ab, mf2=ab, bsky=ab)
        obj.clear()
        self.assertIsNone(obj.our_as1)
        self.assertIsNone(obj.as2)
        self.assertIsNone(obj.mf2)
        self.assertIsNone(obj.bsky)

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
