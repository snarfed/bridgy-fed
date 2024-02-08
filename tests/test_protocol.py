"""Unit tests for protocol.py."""
import copy
from datetime import timedelta
import logging
from unittest import skip
from unittest.mock import patch

from arroba.tests.testutil import dns_answer
from flask import g
from google.cloud import ndb
from granary import as2
from oauth_dropins.webutil import appengine_info, util
from oauth_dropins.webutil.flask_util import CLOUD_TASKS_QUEUE_HEADER, NoContent
from oauth_dropins.webutil.testutil import NOW, requests_response
import requests
from werkzeug.exceptions import BadRequest

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, OtherFake, TestCase

from activitypub import ActivityPub
from app import app
from atproto import ATProto
import common
from models import Follower, Object, PROTOCOLS, Target, User
import protocol
from protocol import Protocol
from ui import UIProtocol
from web import Web

from .test_activitypub import ACTOR
from .test_atproto import DID_DOC
from .test_web import ACTOR_HTML_RESP, ACTOR_AS1_UNWRAPPED_URLS, ACTOR_MF2_REL_URLS


class ProtocolTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('foo.com', cls=Web, has_hcard=True)

    def tearDown(self):
        PROTOCOLS.pop('greedy', None)
        super().tearDown()

    def test_protocols_global(self):
        self.assertEqual(Fake, PROTOCOLS['fake'])
        self.assertEqual(Web, PROTOCOLS['web'])
        self.assertEqual(Web, PROTOCOLS['webmention'])

    def test_for_bridgy_subdomain_for_request(self):
        for domain, expected in [
                ('fake.brid.gy', Fake),
                ('ap.brid.gy', ActivityPub),
                ('activitypub.brid.gy', ActivityPub),
                ('web.brid.gy', Web),
                (None, None),
                ('', None),
                ('brid.gy', None),
                ('www.brid.gy', None),
                ('fed.brid.gy', None),
                ('fake.fed.brid.gy', None),
                ('fake', None),
                ('fake.com', None),
        ]:
            with self.subTest(domain=domain, expected=expected):
                self.assertEqual(expected, Protocol.for_bridgy_subdomain(domain))
                with app.test_request_context('/foo', base_url=f'https://{domain}/'):
                    self.assertEqual(expected, Protocol.for_request())

    def test_for_bridgy_subdomain_for_request_fed(self):
        for url, expected in [
            ('https://fed.brid.gy/', Fake),
            ('http://localhost/foo', Fake),
            ('https://ap.brid.gy/bar', ActivityPub),
            ('https://baz/biff', None),
        ]:
            with self.subTest(url=url, expected=expected):
                self.assertEqual(expected,
                                 Protocol.for_bridgy_subdomain(url, fed=Fake))
                self.assertEqual(expected,
                                 Protocol.for_bridgy_subdomain(url, fed='fake'))
                with app.test_request_context('/foo', base_url=url):
                    self.assertEqual(expected, Protocol.for_request(fed=Fake))

    def test_for_id(self):
        for id, expected in [
                (None, None),
                ('', None),
                ('foo://bar', None),
                ('fake:foo', Fake),
                ('at://foo', ATProto),
                ('https://ap.brid.gy/foo/bar', ActivityPub),
                ('https://web.brid.gy/foo/bar', Web),
        ]:
            self.assertEqual(expected, Protocol.for_id(id))

    def test_for_id_true_overrides_none(self):
        class Greedy(Protocol, User):
            @classmethod
            def owns_id(cls, id):
                return True

        self.assertEqual(Greedy, Protocol.for_id('http://foo'))
        self.assertEqual(Greedy, Protocol.for_id('https://bar/baz'))

    def test_for_id_object(self):
        self.store_object(id='http://ui/obj', source_protocol='ui')
        self.assertEqual(UIProtocol, Protocol.for_id('http://ui/obj'))

    def test_for_id_object_missing_source_protocol(self):
        self.store_object(id='http://bad/obj')
        self.assertIsNone(Protocol.for_id('http://bad/obj'))

    @patch('requests.get')
    def test_for_id_activitypub_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(ACTOR)
        self.assertEqual(ActivityPub, Protocol.for_id('http://ap/actor'))
        self.assertIn(self.as2_req('http://ap/actor'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_activitypub_fetch_fails(self, mock_get):
        mock_get.return_value = requests_response('', status=403)
        self.assertIsNone(Protocol.for_id('http://ap/actor'))
        self.assertIn(self.as2_req('http://ap/actor'), mock_get.mock_calls)
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_for_id_web_fetch(self, mock_get):
        mock_get.return_value = ACTOR_HTML_RESP
        self.assertEqual(Web, Protocol.for_id('http://web.site/'))
        self.assertIn(self.req('http://web.site/'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_web_fetch_no_mf2(self, mock_get):
        mock_get.return_value = requests_response('<html></html>')
        self.assertIsNone(Protocol.for_id('http://web.site/'))
        self.assertIn(self.req('http://web.site/'), mock_get.mock_calls)

    def test_for_handle_deterministic(self):
        for handle, expected in [
            (None, (None, None)),
            ('', (None, None)),
            ('foo://bar', (None, None)),
            ('fake:foo', (None, None)),
            ('fake:handle:foo', (Fake, None)),
            ('@me@foo', (ActivityPub, None)),
        ]:
            self.assertEqual(expected, Protocol.for_handle(handle))

    def test_for_handle_stored_user(self):
        user = self.make_user(id='user.com', cls=Web)
        self.assertEqual('user.com', user.handle)
        self.assertEqual((Web, 'user.com'), Protocol.for_handle('user.com'))

    def test_for_handle_opted_out_user(self):
        user = self.make_user(id='user.com', cls=Web, obj_as1={'summary': '#nobot'})
        self.assertEqual('user.com', user.handle)
        self.assertEqual((None, None), Protocol.for_handle('user.com'))

    @patch('dns.resolver.resolve', return_value = dns_answer(
            '_atproto.han.dull.', '"did=did:plc:123abc"'))
    def test_for_handle_atproto_resolve(self, _):
        self.assertEqual((ATProto, 'did:plc:123abc'), Protocol.for_handle('han.dull'))

    def test_load(self):
        Fake.fetchable['foo'] = {'x': 'y'}

        loaded = Fake.load('foo')
        self.assertEqual({
            'id': 'foo',
            'x': 'y',
        }, loaded.our_as1)
        self.assertFalse(loaded.changed)
        self.assertTrue(loaded.new)

        self.assertIsNotNone(Object.get_by_id('foo'))
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_existing(self):
        self.store_object(id='foo', our_as1={'x': 'y'})

        loaded = Fake.load('foo')
        self.assertEqual({
            'id': 'foo',
            'x': 'y',
        }, loaded.our_as1)
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)

        self.assertEqual([], Fake.fetched)

    def test_load_existing_empty_deleted(self):
        stored = self.store_object(id='foo', deleted=True)

        loaded = Fake.load('foo')
        self.assert_entities_equal(stored, loaded)
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)

        self.assertEqual([], Fake.fetched)

    def test_load_cached(self):
        obj = Object(id='foo', our_as1={'x': 'y'}, updated=util.as_utc(NOW))
        protocol.objects_cache['foo'] = obj
        loaded = Fake.load('foo')
        self.assert_entities_equal(obj, loaded)

        # check that it's a separate copy of the entity in the cache
        # https://github.com/snarfed/bridgy-fed/issues/558#issuecomment-1603203927
        loaded.our_as1 = {'a': 'b'}
        self.assertEqual({
            'id': 'foo',
            'x': 'y',
        }, Protocol.load('foo').our_as1)

    def test_load_remote_true_existing_empty(self):
        Fake.fetchable['foo'] = {'x': 'y'}
        Object(id='foo', our_as1={}, status='in progress').put()

        loaded = Fake.load('foo', remote=True)
        self.assertEqual({'id': 'foo', 'x': 'y'}, loaded.as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
        # check that it merged in fields like status
        self.assertEqual('in progress', loaded.status)
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_true_new_empty(self):
        Fake.fetchable['foo'] = None
        self.store_object(id='foo', our_as1={'x': 'y'})

        loaded = Fake.load('foo', remote=True)
        self.assertIsNone(loaded.as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_true_unchanged(self):
        obj = self.store_object(id='fake:foo', our_as1={'x': 'stored'},
                                source_protocol='fake')
        Fake.fetchable['fake:foo'] = {'x': 'stored'}

        loaded = Fake.load('fake:foo', remote=True)
        self.assert_entities_equal(obj, loaded,
                                   ignore=['expire', 'created', 'updated'])
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['fake:foo'], Fake.fetched)

    def test_load_remote_true_local_false(self):
        Fake.fetchable['foo'] = our_as1={'x': 'y'}

        loaded = Fake.load('foo', local=False, remote=True)
        self.assertEqual({'id': 'foo', 'x': 'y'}, loaded.as1)
        self.assertIsNone(loaded.changed)
        self.assertIsNone(loaded.new)
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_true_changed(self):
        self.store_object(id='foo', our_as1={'content': 'stored'})
        Fake.fetchable['foo'] = {'content': 'new'}

        loaded = Fake.load('foo', remote=True)
        self.assertEqual({
            'id': 'foo',
            'content': 'new',
        }, loaded.our_as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['foo'], Fake.fetched)

    @patch('requests.get', return_value=ACTOR_HTML_RESP)
    def test_load_remote_true_clear_our_as1(self, _):
        self.store_object(id='https://foo', our_as1={'should': 'disappear'},
                          source_protocol='web')

        expected_mf2 = {
            **ACTOR_MF2_REL_URLS,
            'url': 'https://user.com/',
        }

        loaded = Web.load('https://foo', remote=True)
        self.assertEqual(expected_mf2, loaded.mf2)
        self.assertIsNone(loaded.our_as1)
        self.assertEqual(ACTOR_AS1_UNWRAPPED_URLS, loaded.as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)

    def test_load_remote_false(self):
        self.assertIsNone(Fake.load('nope', remote=False))
        self.assertEqual([], Fake.fetched)

        obj = self.store_object(id='foo', our_as1={'content': 'stored'})
        self.assert_entities_equal(obj, Fake.load('foo', remote=False))
        self.assertEqual([], Fake.fetched)

    def test_load_remote_false_existing_object_empty(self):
        obj = self.store_object(id='foo')
        self.assert_entities_equal(obj, Protocol.load('foo', remote=False))

    def test_load_local_false_missing(self):
        self.assertIsNone(Fake.load('foo', local=False))
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_local_false_existing(self):
        self.store_object(id='foo', our_as1={'content': 'stored'}, source_protocol='ui')

        Fake.fetchable['foo'] = {'foo': 'bar'}
        Fake.load('foo', local=False)
        self.assert_object('foo', source_protocol='fake', our_as1={'foo': 'bar'})
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_false_local_false_assert(self):
        with self.assertRaises(AssertionError):
            Fake.load('nope', local=False, remote=False)

    def test_load_resolve_ids(self):
        follow = {
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }
        Fake.fetchable = {
            'fake:follow': follow,
        }

        # no matching copy users
        obj = Fake.load('fake:follow', remote=True)
        self.assert_equals(follow, obj.our_as1)

        # matching copy user
        self.make_user('other:bob', cls=OtherFake,
                       copies=[Target(uri='fake:bob', protocol='fake')])

        obj = Fake.load('fake:follow', remote=True)
        self.assert_equals({
            **follow,
            'id': 'fake:follow',
            'object': 'other:bob',
        }, obj.our_as1)

    def test_load_preserves_fragment(self):
        stored = self.store_object(id='http://the/id#frag', our_as1={'foo': 'bar'})
        got = ActivityPub.load('http://the/id#frag')
        self.assert_entities_equal(stored, got)
        self.assertEqual([], Fake.fetched)

    def test_load_refresh(self):
        Fake.fetchable['foo'] = {'fetched': 'x'}

        too_old = (NOW.replace(tzinfo=None)
                   - protocol.OBJECT_REFRESH_AGE
                   - timedelta(days=1))
        with patch('models.Object.updated._now', return_value=too_old):
            obj = Object(id='foo', our_as1={'orig': 'y'}, status='in progress')
            obj.put()

        protocol.objects_cache['foo'] = obj

        loaded = Fake.load('foo')
        self.assertEqual({'fetched': 'x', 'id': 'foo'}, loaded.our_as1)

    def test_actor_key(self):
        user = self.make_user(id='fake:a', cls=Fake)
        a_key = user.key

        for expected, obj in [
                (None, Object()),
                (None, Object(our_as1={})),
                (None, Object(our_as1={'foo': 'bar'})),
                (None, Object(our_as1={'foo': 'bar'})),
                (None, Object(our_as1={'actor': ''})),
                (a_key, Object(our_as1={'actor': 'fake:a'})),
                (a_key, Object(our_as1={'author': 'fake:a'})),
        ]:
            self.assertEqual(expected, Fake.actor_key(obj))

        self.assertIsNone(Fake.actor_key(Object()))

    def test_key_for(self):
        self.assertEqual(self.user.key, Protocol.key_for(self.user.key.id()))

        user = Fake(id='fake:other', use_instead=self.user.key).put()
        self.assertEqual(self.user.key, Protocol.key_for('fake:other'))

        # no stored user
        self.assertEqual(ndb.Key('Fake', 'fake:foo'), Protocol.key_for('fake:foo'))

        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        self.assertIsNone(Protocol.key_for(self.user.key.id()))

    def test_targets_checks_blocklisted_per_protocol(self):
        """_targets should call the target protocol's is_blocklisted()."""
        # non-ATProto account, ATProto target (PDS) is atproto.brid.gy
        # shouldn't be blocklisted
        user = self.make_user(
            id='fake:user', cls=Fake,
            copies=[Target(uri='did:plc:foo', protocol='atproto')])

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = 'http://localhost/'
        self.store_object(id='did:plc:foo', raw=did_doc)

        # store Objects so we don't try to fetch them remotely
        self.store_object(id='at://did:plc:foo/co.ll/post', our_as1={'foo': 'bar'})
        self.store_object(id='fake:post', our_as1={'foo': 'baz'})

        obj = Object(our_as1={
            'id': 'other:reply',
            'objectType': 'note',
            'inReplyTo': [
                'fake:post',
                'fake:blocklisted-post',
                'https://t.co/foo',
                'http://localhost/post',
                'at://did:plc:foo/co.ll/post',
            ],
        })
        self.assertCountEqual([
            Target(protocol='fake', uri='fake:post:target'),
            Target(protocol='atproto', uri='https://atproto.brid.gy/'),
        ], Protocol.targets(obj).keys())

    def test_targets_composite_inreplyto(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
        }
        self.assertEqual({Target(protocol='fake', uri='fake:post:target')},
                         Fake.targets(Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'other:reply',
                'objectType': 'note',
                'inReplyTo': {
                    'id': 'fake:post',
                    'url': 'http://foo',
                },
            },
        })).keys())

    def test_translate_ids_follow(self):
        self.assert_equals({
            'id': 'other:o:fa:fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'other:u:fake:alice',
            'object': 'other:u:fake:bob',
        }, OtherFake.translate_ids({
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }))

    def test_translate_ids_reply(self):
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'other:o:fa:fake:reply',
                'objectType': 'note',
                'inReplyTo': 'other:o:fa:fake:post',
                'author': 'other:u:fake:alice',
                'tags': [{
                    'objectType': 'mention',
                    'url': 'other:u:fake:bob',
                }],
            },
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'fake:reply',
                'objectType': 'note',
                'inReplyTo': 'fake:post',
                'author': {'id': 'fake:alice'},
                'tags': [{
                    'objectType': 'mention',
                    'url': 'fake:bob',
                }],
            },
        }))

    def test_translate_ids_update_profile(self):
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'other:u:fake:alice',
            'object': {
                'objectType': 'person',
                'id': 'other:u:fake:alice',
            },
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:alice',
            'object': {
                'objectType': 'person',
                'id': 'fake:alice',
            },
        }))

    def test_translate_ids_copies(self):
        self.store_object(id='fake:post',
                          copies=[Target(uri='other:post', protocol='other')])
        self.make_user('other:user', cls=OtherFake,
                       copies=[Target(uri='fake:user', protocol='fake')])

        self.assert_equals({
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'other:user',
            'object': {
                'id': 'other:o:fa:fake:reply',
                'inReplyTo': 'other:post',
            },
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': {
                'id': 'fake:reply',
                'inReplyTo': 'fake:post',
            },
        }))


class ProtocolReceiveTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:user', cls=Fake, obj_id='fake:user')
        self.alice = self.make_user('fake:alice', cls=Fake, obj_id='fake:alice')
        self.bob = self.make_user('fake:bob', cls=Fake, obj_id='fake:bob')

    def assert_object(self, id, **props):
        props.setdefault('source_protocol', 'fake')
        props.setdefault('delivered_protocol', 'fake')
        return super().assert_object(id, **props)

    def make_followers(self):
        Follower.get_or_create(to=self.user, from_=self.alice)
        Follower.get_or_create(to=self.user, from_=self.bob)
        Follower.get_or_create(to=self.user, from_=Fake(id='fake:eve'),
                               status='inactive')

    def test_create_post(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
        }
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': post_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[self.alice.key, self.bob.key],
                           )
        obj = self.assert_object('fake:create',
                                 status='complete',
                                 our_as1=create_as1,
                                 delivered=['shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_create_post_bare_object(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[self.alice.key, self.bob.key],
                           )

        obj = self.assert_object('fake:post#bridgy-fed-create',
                                 status='complete',
                                 our_as1={
                                     'objectType': 'activity',
                                     'verb': 'post',
                                     'id': 'fake:post#bridgy-fed-create',
                                     'actor': 'fake:user',
                                     'object': post_as1,
                                     'published': '2022-01-02T03:04:05+00:00',
                                 },
                                 delivered=['shared:target'],
                                 type='post',
                                 users=[Fake(id='fake:user').key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_create_post_bare_object_existing_failed_create(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1)
        self.store_object(id='fake:post#bridgy-fed-create', status='failed')

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        obj = self.assert_object('fake:post#bridgy-fed-create',
                                 status='complete',
                                 delivered=['shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 ignore=['our_as1'],
                                 )

        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_create_post_bare_object_no_existing_create(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1)

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        obj = self.assert_object('fake:post#bridgy-fed-create',
                                 status='complete',
                                 delivered=['shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 ignore=['our_as1'],
                                 )

        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_create_post_use_instead(self):
        self.make_user('fake:not-this', cls=Fake, use_instead=self.user.key, obj_mf2={
            'type': ['h-card'],
            'properties': {
                # this is the key part to test; Object.as1 uses this as id
                'url': ['fake:user'],
            },
        })
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        obj = self.store_object(id='fake:post', our_as1=post_as1)

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))
        self.assertEqual(1, len(Fake.sent))
        self.assertEqual('shared:target', Fake.sent[0][1])

    def test_update_post_wrong_actor_error(self):
        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1)

        with self.assertRaises(NoContent), self.assertLogs() as logs:
            Fake.receive_as1({
                'id': 'fake:update',
                'objectType': 'activity',
                'verb': 'update',
                'actor': 'fake:other',
                'object': post_as1,
            })

        self.assertIn(
            "WARNING:models:actor fake:other isn't fake:post's author or actor ['fake:user']",
            logs.output)

    def test_update_post(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
        }
        self.store_object(id='fake:post', our_as1=post_as1)

        update_as1 = {
            'id': 'fake:update',
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': post_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(update_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[self.alice.key, self.bob.key],
                           )
        obj = self.assert_object('fake:update',
                                 status='complete',
                                 our_as1=update_as1,
                                 delivered=['shared:target'],
                                 type='update',
                                 users=[self.user.key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_update_post_bare_object(self):
        self.make_followers()

        # post has no author
        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'first',
        }
        self.store_object(id='fake:post', our_as1=post_as1)
        existing = Object.get_by_id('fake:post')

        post_as1['content'] = 'second'
        with self.assertRaises(NoContent):
            Fake.receive_as1(post_as1)

        post_as1['updated'] = '2022-01-02T03:04:05+00:00'
        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[],
                           )

        update_id = 'fake:post#bridgy-fed-update-2022-01-02T03:04:05+00:00'
        obj = self.assert_object(update_id,
                                 status='ignored',
                                 our_as1={
                                     'objectType': 'activity',
                                     'verb': 'update',
                                     'id': update_id,
                                     'actor': 'fake:alice',
                                     'object': post_as1,
                                 },
                                 delivered=[],
                                 type='update',
                                 users=[Fake(id='fake:alice').key],
                                 notify=[],
                                 )

        self.assertEqual([], Fake.sent)

    def test_create_reply(self):
        self.make_followers()

        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }
        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:alice',
        }
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': reply_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object('fake:reply',
                           our_as1=reply_as1,
                           type='note',
                           )
        obj = self.assert_object('fake:create',
                                 status='complete',
                                 our_as1=create_as1,
                                 delivered=['fake:post:target'],
                                 type='post',
                                 users=[self.user.key, self.alice.key],
                                 notify=[self.bob.key],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:post:target')], Fake.sent)

    def test_create_reply_bare_object(self):
        self.make_followers()

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:alice',
        }
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'id': 'fake:post',
            'author': 'fake:bob',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object('fake:reply',
                           our_as1=reply_as1,
                           type='note',
                           )

        create_as1 = {
            'id': 'fake:reply#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:alice',
            'object': reply_as1,
            'published': '2022-01-02T03:04:05+00:00',
        }
        obj = self.assert_object('fake:reply#bridgy-fed-create',
                                 status='complete',
                                 our_as1=create_as1,
                                 delivered=['fake:post:target'],
                                 type='post',
                                 users=[self.alice.key],
                                 notify=[self.bob.key],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:post:target')], Fake.sent)

    def test_create_reply_to_self_delivers_to_followers(self):
        self.make_followers()
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        Follower.get_or_create(to=self.user, from_=eve)

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:user',
        }
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'id': 'fake:post',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object('fake:reply', our_as1=reply_as1, type='note',
                           feed=[self.alice.key, self.bob.key, eve.key])

        obj = Object.get_by_id(id='fake:reply#bridgy-fed-create')
        self.assertEqual([
            (obj.key.id(), 'fake:post:target'),
            (obj.key.id(), 'shared:target'),
        ], Fake.sent)
        self.assertEqual([
            (obj.key.id(), 'other:eve:target'),
        ], OtherFake.sent)

    def test_reply_skips_mention_of_original_post_author(self):
        bob = self.store_object(id='fake:bob', our_as1={'foo': 1})
        eve = self.store_object(id='fake:eve', our_as1={'foo': 2})

        reply_as1 = {
            'id': 'other:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'other:alice',
            'content': 'foo',
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:eve',
            }, {
                'objectType': 'mention',
                'url': 'fake:bob',
            }],
        }
        Fake.fetchable = {
            'fake:post': {
                'objectType': 'note',
                'id': 'fake:post',
                'author': 'fake:bob',
            },
        }
        self.assertEqual(('OK', 202), OtherFake.receive_as1(reply_as1))

        obj = Object.get_by_id('other:reply#bridgy-fed-create')
        self.assertEqual([Fake(id='fake:bob').key], obj.notify)
        self.assertEqual([
            # bob shouldn't be here, we should suppress the mention
            (obj.key.id(), 'fake:eve:target'),
            (obj.key.id(), 'fake:post:target'),
        ], Fake.sent)

    def test_update_reply(self):
        self.make_followers()

        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }
        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:alice',
        }
        self.store_object(id='fake:reply', our_as1=reply_as1)

        update_as1 = {
            'id': 'fake:update',
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': reply_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(update_as1))

        self.assert_object('fake:reply',
                           our_as1=reply_as1,
                           type='note',
                           )
        obj = self.assert_object('fake:update',
                                 status='complete',
                                 our_as1=update_as1,
                                 delivered=['fake:post:target'],
                                 type='update',
                                 users=[self.user.key, self.alice.key],
                                 notify=[self.bob.key],
                                 )
        self.assertEqual([(obj.key.id(), 'fake:post:target')], Fake.sent)

    def test_repost(self):
        self.make_followers()

        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }
        repost_as1 = {
            'id': 'fake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(repost_as1))

        obj = self.assert_object('fake:repost',
                                 status='complete',
                                 our_as1={
                                     **repost_as1,
                                     'object': {
                                         'id': 'fake:post',
                                         'objectType': 'note',
                                         'author': 'fake:bob',
                                     },
                                 },
                                 delivered=['fake:post:target', 'shared:target'],
                                 type='share',
                                 users=[self.user.key],
                                 notify=[self.bob.key],
                                 feed=[self.alice.key, self.bob.key],
                                 )
        self.assertEqual([
            (obj.key.id(), 'fake:post:target'),
            (obj.key.id(), 'shared:target'),
        ], Fake.sent)

    def test_repost_twitter_blocklisted(self):
        """Reposts of non-fediverse (ie blocklisted) sites aren't yet supported."""
        repost_as1 = {
            'id': 'fake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:user',
            'object': 'https://twitter.com/foo',
        }
        with self.assertRaises(NoContent):
            Fake.receive_as1(repost_as1)

        obj = self.assert_object('fake:repost',
                                 status='ignored',
                                 our_as1=repost_as1,
                                 delivered=[],
                                 type='share',
                                 users=[self.user.key],
                                 )
        self.assertEqual([], Fake.sent)

    def test_like(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }

        like_as1 = {
            'id': 'fake:like',
            'objectType': 'activity',
            'verb': 'like',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(like_as1))

        like_obj = self.assert_object('fake:like',
                                      users=[self.user.key],
                                      notify=[self.bob.key],
                                      status='complete',
                                      our_as1=like_as1,
                                      delivered=['fake:post:target'],
                                      type='like',
                                      object_ids=['fake:post'])

        self.assertEqual([(like_obj.key.id(), 'fake:post:target')], Fake.sent)

    def test_like_no_object_error(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:like',
                'objectType': 'activity',
                'verb': 'like',
                'actor': 'fake:user',
                'object': None,
        })

    def test_share_no_object_error(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:share',
                'objectType': 'activity',
                'verb': 'share',
                'actor': 'fake:user',
                'object': None,
        })

    def test_delete(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1)

        delete_as1 = {
            'id': 'fake:delete',
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(delete_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           deleted=True,
                           source_protocol=None,
                           feed=[self.alice.key, self.bob.key],
                           )

        obj = self.assert_object('fake:delete',
                                 status='complete',
                                 our_as1=delete_as1,
                                 delivered=['shared:target'],
                                 type='delete',
                                 users=[self.user.key],
                                 notify=[],
                                 )
        self.assertEqual([(obj.key.id(), 'shared:target')], Fake.sent)

    def test_delete_no_followers_no_stored_object(self):
        delete_as1 = {
            'id': 'fake:delete',
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        with self.assertRaises(NoContent):
            Fake.receive_as1(delete_as1)

        self.assert_object('fake:post',
                           deleted=True,
                           source_protocol=None,
                           feed=[],
                           )

        self.assert_object('fake:delete',
                           status='ignored',
                           our_as1=delete_as1,
                           delivered=[],
                           type='delete',
                           users=[self.user.key],
                           notify=[],
                           )
        self.assertEqual([], Fake.sent)

    def test_delete_actor(self):
        follower = Follower.get_or_create(to=self.user, from_=self.alice)
        followee = Follower.get_or_create(to=self.alice, from_=self.bob)
        other = Follower.get_or_create(to=self.user, from_=self.bob)
        self.assertEqual(3, Follower.query().count())

        with self.assertRaises(NoContent):
            Fake.receive_as1({
                'objectType': 'activity',
                'verb': 'delete',
                'id': 'fake:delete',
                'actor': 'fake:alice',
                'object': 'fake:alice',
            })

        self.assertEqual(3, Follower.query().count())
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

        self.assert_object('fake:alice', deleted=True, source_protocol='fake')

    @patch.object(Fake, 'send')
    @patch.object(Fake, 'target_for')
    def test_send_error(self, mock_target_for, mock_send):
        """Two targets. First send fails, second succeeds."""
        self.make_followers()

        mock_target_for.side_effect = [
            'target:1',
            'target:2',
        ]

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
        }
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': post_as1,
        }

        sent = []
        def send(obj, url, from_user=None, orig_obj=None):
            self.assertEqual(create_as1, obj.as1)
            if not sent:
                self.assertEqual('target:1', url)
                sent.append('fail')
                raise BadRequest()
            else:
                self.assertEqual('target:2', url)
                sent.append('sent')
                return True

        mock_send.side_effect = send

        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[self.alice.key, self.bob.key],
                           )
        obj = self.assert_object('fake:create',
                                 status='complete',
                                 our_as1=create_as1,
                                 delivered=['target:2'],
                                 failed=['target:1'],
                                 type='post',
                                 users=[self.user.key],
                                 )

        self.assertEqual(['fail', 'sent'], sent)

    def test_update_profile(self):
        self.make_followers()

        id = 'fake:user#update-2022-01-02T03:04:05+00:00'
        update_as1 = {
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': 'fake:user',
            'object': {
                'objectType': 'person',
                'id': 'fake:user',
                'displayName': 'Ms. ☕ Baz',
                'urls': [{'displayName': 'Ms. ☕ Baz', 'value': 'https://user.com/'}],
                'updated': '2022-01-02T03:04:05+00:00',
            },
        }

        Fake.receive_as1(update_as1)

        # profile object
        self.assert_object('fake:user',
                           our_as1=update_as1['object'],
                           type='person',
                           feed=[],
                           )

        # update activity
        update_as1['actor'] = update_as1['object']
        update_obj = self.assert_object(
            id,
            users=[self.user.key],
            status='complete',
            our_as1=update_as1,
            delivered=['shared:target'],
            type='update',
            object_ids=['fake:user'],
        )

        self.assertEqual([(update_obj.key.id(), 'shared:target')], Fake.sent)

    def test_mention_object(self, *mocks):
        self.alice.obj.our_as1 = {'id': 'fake:alice', 'objectType': 'person'}
        self.alice.obj.put()
        self.bob.obj.our_as1 = {'id': 'fake:bob', 'objectType': 'person'}
        self.bob.obj.put()

        mention_as1 = {
            'objectType': 'note',
            'id': 'fake:mention',
            'author': 'fake:user',
            'content': 'something',
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:alice',
            }, {
                'objectType': 'mention',
                'url': 'fake:bob',
            }],
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(mention_as1))

        self.assert_object('fake:mention',
                           our_as1=mention_as1,
                           type='note',
                           )

        obj = self.assert_object('fake:mention#bridgy-fed-create',
                                 status='complete',
                                 our_as1={
                                     'objectType': 'activity',
                                     'verb': 'post',
                                     'id': 'fake:mention#bridgy-fed-create',
                                     'actor': 'fake:user',
                                     'object': mention_as1,
                                     'published': '2022-01-02T03:04:05+00:00',
                                 },
                                 delivered=['fake:alice:target', 'fake:bob:target'],
                                 type='post',
                                 users=[self.user.key],
                                 notify=[self.alice.key, self.bob.key],
                                 )

        self.assertEqual([
            (obj.key.id(), 'fake:alice:target'),
            (obj.key.id(), 'fake:bob:target'),
        ], Fake.sent)

    def test_follow(self):
        self._test_follow()

    def test_follow_existing_inactive(self):
        follower = Follower.get_or_create(to=self.user, from_=self.alice,
                                          status='inactive')
        self._test_follow()

    def test_follow_actor_object_composite_objects(self):
        self._test_follow(actor={'id': 'fake:alice', 'objectType': 'person'},
                          object={'id': 'fake:user', 'objectType': 'person'})

    def _test_follow(self, **extra):
        Fake.fetchable['fake:alice'] = {}

        follow_as1 = {
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:user',
            **extra,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(follow_as1))

        user = Fake.get_by_id('fake:user')
        follow_obj = self.assert_object('fake:follow',
                                        our_as1=follow_as1,
                                        status='complete',
                                        users=[self.alice.key],
                                        notify=[user.key],
                                        feed=[],
                                        delivered=['fake:user:target'],
                                        )

        accept_id = 'https://fa.brid.gy/ap/fake:user/followers#accept-fake:follow'
        accept_as1 = {
            'id': accept_id,
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'fake:user',
            'object': follow_as1,
        }
        accept_obj = self.assert_object(accept_id,
                                        our_as1=accept_as1,
                                        type='accept',
                                        status='complete',
                                        delivered=['fake:alice:target'],
                                        users=[],
                                        notify=[],
                                        feed=[],
                                        source_protocol=None,
                                        )

        self.assertEqual([
            (accept_obj.key.id(), 'fake:alice:target'),
            (follow_obj.key.id(), 'fake:user:target'),
        ], Fake.sent)

        self.assert_entities_equal(
            Follower(to=user.key, from_=self.alice.key, status='active',
                     follow=follow_obj.key),
            Follower.query().fetch(),
            ignore=['created', 'updated'],
        )

    def test_follow_with_accepts_protocol(self, **extra):
        OtherFake.fetchable['other:user'] = {}

        follow_as1 = {
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'other:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(follow_as1))

        other = OtherFake.get_by_id('other:user')
        follow_obj = self.assert_object('fake:follow',
                                        our_as1=follow_as1,
                                        status='complete',
                                        users=[self.alice.key],
                                        notify=[other.key],
                                        delivered=['other:user:target'],
                                        delivered_protocol='other',
                                        )

        self.assertIsNone(Object.get_by_id(
            'https://fa.brid.gy/ap/other:user/followers#accept-fake:follow'))
        self.assertEqual(0, Object.query(Object.type == 'accept').count())
        self.assertEqual([], Fake.sent)

    def test_follow_no_actor(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'object': 'fake:user',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_follow_no_object(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'fake:alice',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_follow_object_unknown_protocol(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'fake:alice',
                'object': 'unknown:bob',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_accept_noop(self, **extra):
        eve = self.make_user('other:eve', cls=OtherFake)
        accept_as1 = {
            'id': 'other:accept',
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'other:eve',
            'object': 'fake:follow'
        }

        self.assertEqual('OK', OtherFake.receive_as1(accept_as1))
        self.assertEqual([], Fake.sent)
        self.assertEqual([], OtherFake.sent)

    def test_accept_with_has_accepts_protocol(self, **extra):
        OtherFake.fetchable['other:follow'] = {'id': 'other:follow'}
        accept_as1 = {
            'id': 'fake:accept',
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'fake:alice',
            'object': 'other:follow'
        }

        self.assertEqual(('OK', 202), Fake.receive_as1(accept_as1))
        self.assertEqual([
            ('fake:accept', 'other:follow:target'),
        ], OtherFake.sent)

    def test_stop_following(self):
        follower = Follower.get_or_create(to=self.user, from_=self.alice)

        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        stop_as1 = {
            'id': 'fake:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(stop_as1))

        stop_obj = self.assert_object('fake:stop-following',
                                      our_as1=stop_as1,
                                      type='stop-following',
                                      status='complete',
                                      delivered=['fake:user:target'],
                                      users=[self.alice.key],
                                      notify=[],
                                      feed=[],
                                      )

        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual([(stop_obj.key.id(), 'fake:user:target')], Fake.sent)

    def test_stop_following_doesnt_exist(self):
        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'id': 'fake:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))

        self.assertEqual(0, Follower.query().count())
        self.assertEqual([('fake:stop-following', 'fake:user:target')], Fake.sent)

    def test_stop_following_inactive(self):
        follower = Follower.get_or_create(to=self.user, from_=self.alice,
                                          status='inactive')
        Fake.fetchable['fake:alice'] = {}
        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'id': 'fake:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))

        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual([('fake:stop-following', 'fake:user:target')], Fake.sent)

    @skip
    def test_from_bridgy_fed_domain_fails(self):
        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'https://fed.brid.gy/r/foo',
            })

        self.assertIsNone(Object.get_by_id('https://fed.brid.gy/r/foo'))

        with self.assertRaises(BadRequest):
            Fake.receive_as1({
                'id': 'fake:foo',
                'actor': 'https://ap.brid.gy/user.com',
            })

        self.assertIsNone(Object.get_by_id('foo'))
        self.assertIsNone(Object.get_by_id('https://ap.brid.gy/user.com'))

    def test_skip_same_protocol(self):
        self.make_user('other:carol', cls=OtherFake, obj_id='other:carol')
        self.make_user('other:dan', cls=OtherFake, obj_id='other:dan')

        OtherFake.fetchable = {
            'other:carol': {},
        }

        follow_as1 = {
            'id': 'other:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'other:carol',
            'object': ['other:dan', 'fake:alice'],
        }

        self.assertEqual(('OK', 202), OtherFake.receive_as1(follow_as1))

        self.assertEqual(1, len(OtherFake.sent))
        self.assertEqual(
            'https://fa.brid.gy/ap/fake:alice/followers#accept-other:follow',
            OtherFake.sent[0][0])

        self.assertEqual(1, len(Fake.sent))
        self.assertEqual('other:follow', Fake.sent[0][0])

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual(self.alice.key, followers[0].to)

    @patch('requests.post')
    @patch('requests.get')
    def test_skip_web_same_domain(self, mock_get, mock_post):
        Web.fetchable = {
            'http://x.com/alice': {},
            'http://x.com/bob': {},
            'http://x.com/eve': {},
        }

        follow_as1 = {
            'id': 'http://x.com/follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'http://x.com/alice',
            'object': ['http://x.com/bob', 'http://x.com/eve'],
        }

        with self.assertRaises(NoContent):
            Web.receive(Object(our_as1=follow_as1))

        mock_get.assert_not_called()
        mock_post.assert_not_called()
        self.assertEqual(0, Follower.query().count())

    def test_opted_out(self):
        self.user.obj.our_as1 = {
            'id': 'fake:user',
            'summary': '#nobridge',
        }
        self.user.obj.put()

        with self.assertRaises(NoContent):
            Fake.receive_as1({
                'id': 'fake:post',
                'objectType': 'activity',
                'verb': 'post',
                'actor': 'fake:user',
                'object': {
                    'id': 'fake:note',
                    'content': 'foo',
                },
            })

    def test_resolve_ids_follow(self):
        follow = {
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }

        # no matching copy users
        obj = Object(id='fake:follow', our_as1=follow, source_protocol='fake')
        self.assertEqual(('OK', 202), Fake.receive(obj))
        self.assert_equals(follow, obj.our_as1)

        # matching copy user
        self.make_user('other:bob', cls=OtherFake,
                       copies=[Target(uri='fake:bob', protocol='fake')])

        protocol.seen_ids.clear()
        obj.new = True
        OtherFake.fetchable = {
            'other:bob': {},
        }

        self.assertEqual(('OK', 202), Fake.receive(obj))
        self.assert_equals({
            **follow,
            'actor': {'id': 'fake:alice'},
            'object': 'other:bob',
        }, Object.get_by_id('fake:follow').our_as1)

    def test_resolve_ids_share(self):
        share = {
            'objectType': 'activity',
            'actor': 'fake:alice',
            'verb': 'share',
            'object': 'fake:post',
        }

        # no matching copy object
        obj = Object(id='fake:share', our_as1=share, source_protocol='fake')
        with self.assertRaises(NoContent):
            Fake.receive(obj)
        self.assert_equals(share, obj.our_as1)

        # matching copy object
        self.store_object(id='other:post',
                          copies=[Target(uri='fake:post', protocol='fake')])

        protocol.seen_ids.clear()
        obj.new = True
        with self.assertRaises(NoContent):
            Fake.receive(obj)

        self.assert_equals({
            'id': 'fake:share',
            'objectType': 'activity',
            'actor': 'fake:alice',
            'verb': 'share',
            'object': 'other:post',
        }, obj.our_as1)

    def test_resolve_ids_reply(self):
        reply = {
            'id': 'other:reply',
            'actor': 'other:eve',
            'objectType': 'note',
            'inReplyTo': [
                'other:unknown-post',
                'other:post',
            ],
            'tags': [{
                'objectType': 'mention',
                'url': 'other:alice',
            }, {
                'objectType': 'mention',
                'url': 'other:bob',
            }],
        }

        # no matching copies
        obj = Object(id='other:reply', our_as1=reply, source_protocol='other')
        with self.assertRaises(NoContent):
            OtherFake.receive(obj)
        self.assert_equals(reply, obj.our_as1)

        # matching copies
        self.make_user(
            'fake:alice', cls=Fake,
            copies=[Target(uri='other:alice', protocol='other')])
        self.make_user(
            'fake:bob', cls=Fake,
            copies=[Target(uri='other:bob', protocol='other')])
        self.store_object(
            id='fake:post', our_as1={'foo': 9}, source_protocol='fake',
            copies=[Target(uri='other:post', protocol='other')])

        protocol.seen_ids.clear()
        obj.new = True
        self.assertEqual(('OK', 202), OtherFake.receive(obj))
        self.assertEqual({
            'id': 'other:reply',
            'objectType': 'note',
            'actor': 'other:eve',
            'inReplyTo': [
                'other:unknown-post',
                'fake:post',
            ],
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:alice',
            }, {
                'objectType': 'mention',
                'url': 'fake:bob',
            }],
        }, obj.key.get().our_as1)

    def test_receive_task_handler(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        }
        obj = self.store_object(id='fake:post', our_as1=note,
                                source_protocol='fake')

        create = {
            'id': 'fake:post#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'object': note,
        }
        obj = self.store_object(id='fake:post#bridgy-fed-create',
                                source_protocol='fake', our_as1=create)

        resp = self.post('/queue/receive', data={'obj': obj.key.urlsafe()})
        self.assertEqual(204, resp.status_code)
        obj = Object.get_by_id('fake:post#bridgy-fed-create')
        self.assertEqual('ignored', obj.status)

    def test_receive_task_handler_authed_as(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        }
        obj = self.store_object(id='fake:post', our_as1=note,
                                source_protocol='fake')

        with self.assertLogs() as logs:
            self.client.post('/queue/receive', data={
                'obj': obj.key.urlsafe(),
                'authed_as': 'fake:eve',
            }, headers={CLOUD_TASKS_QUEUE_HEADER: ''})

        self.assertIn(
            "WARNING:protocol:actor fake:other isn't authed user fake:eve",
            logs.output)

    def test_g_user_opted_out(self):
        self.make_followers()
        self.user.obj.our_as1 = {'summary': '#nobot'}
        self.user.obj.put()

        with self.assertRaises(NoContent):
            Fake.receive_as1({
                'id': 'fake:post',
                'objectType': 'note',
                'author': 'fake:user',
            })

        self.assertEqual([], Fake.sent)

    def test_like_not_authed_as_actor(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }

        with self.assertLogs() as logs:
            Fake.receive_as1({
                'id': 'fake:like',
                'objectType': 'activity',
                'verb': 'like',
                'actor': 'fake:user',
                'object': 'fake:post',
            }, authed_as='fake:other')

        self.assertIn(
            "WARNING:protocol:actor fake:user isn't authed user fake:other",
            logs.output)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_post_create_send_tasks(self, mock_create_task):
        common.RUN_TASKS_INLINE = False

        self.make_followers()
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        Follower.get_or_create(to=self.user, from_=eve)

        note_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(note_as1))

        create_key = Object.get_by_id('fake:post#bridgy-fed-create').key.urlsafe()
        self.assert_task(mock_create_task, 'send', '/queue/send', protocol='other',
                         obj=create_key, orig_obj='', url='other:eve:target',
                         user=self.user.key.urlsafe())
        self.assert_task(mock_create_task, 'send', '/queue/send', protocol='fake',
                         obj=create_key, orig_obj='', url='shared:target',
                         user=self.user.key.urlsafe())

        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_reply_send_tasks_orig_obj(self, mock_create_task):
        common.RUN_TASKS_INLINE = False

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:user',
        }
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'id': 'fake:post',
            'author': 'fake:bob',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object('fake:reply',
                           our_as1=reply_as1,
                           type='note',
                           )

        create_key = Object(id='fake:reply#bridgy-fed-create').key.urlsafe()
        orig_obj_key = Object(id='fake:post').key.urlsafe()
        self.assert_task(mock_create_task, 'send', '/queue/send', protocol='fake',
                         obj=create_key, orig_obj=orig_obj_key, url='fake:post:target',
                         user=self.user.key.urlsafe())

        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_send_task_handler(self):
        self.make_followers()

        note = self.store_object(id='fake:note', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
        })
        target = Target(uri='shared:target', protocol='fake')
        create = self.store_object(id='fake:create', undelivered=[target], our_as1={
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': note.as1,
        })
        resp = self.client.post('/queue/send', data={
            'protocol': 'fake',
            'obj': create.key.urlsafe(),
            'orig_obj': note.key.urlsafe(),
            'url': 'shared:target',
            'user': self.user.key.urlsafe(),
        }, headers={CLOUD_TASKS_QUEUE_HEADER: ''})
        self.assertEqual(200, resp.status_code)
