"""Unit tests for protocol.py."""
import copy
from datetime import timedelta
import logging
from threading import Condition, Thread
from unittest import skip
from unittest.mock import patch

from arroba.tests.testutil import dns_answer
from cachetools import LRUCache, TTLCache
from google.cloud import ndb
from google.cloud.ndb.global_cache import _InProcessGlobalCache
from granary import as2
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY
from oauth_dropins.webutil import appengine_info, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import NOW, requests_response
import requests
from werkzeug.exceptions import BadRequest

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitEnableFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub
from app import app
from atproto import ATProto
import common
import models
from models import DM, Follower, Object, PROTOCOLS, Target, User
import protocol
from protocol import ErrorButDoNotRetryTask, Protocol
from ui import UIProtocol
from web import Web

from .test_activitypub import ACTOR, NOTE
from .test_atproto import DID_DOC
from .test_web import (
    ACTOR_HTML_RESP,
    ACTOR_AS1_UNWRAPPED_URLS,
    ACTOR_MF2_REL_URLS,
    NOTE as NOTE_HTML_RESP,
)


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
                ('https:/abc/', None),
                ('https:/[DOMAIN]/', None),
                ('https://[DOMAIN]/', None),
                ('fake:foo', Fake),
                ('at://foo', ATProto),
                # TODO: remove? should we require normalized ids?
                ('https://ap.brid.gy/foo/bar', ActivityPub),
                ('https://web.brid.gy/foo/bar', Web),
                ('https://fed.brid.gy/', Web),
                ('https://web.brid.gy/', Web),
                ('https://bsky.brid.gy/', Web),
                ('bsky.brid.gy', Web),
        ]:
            self.assertEqual(expected, Protocol.for_id(id, remote=False))
            self.assertEqual(expected, Protocol.for_id(id, remote=True))

    def test_for_id_true_overrides_none(self):
        class Greedy(Protocol, User):
            @classmethod
            def owns_id(cls, id):
                return True

        self.assertEqual(Greedy, Protocol.for_id('http://foo'))
        self.assertEqual(Greedy, Protocol.for_id('https://bar/baz'))

    def test_for_id_object(self):
        self.store_object(id='http://ui.org/obj', source_protocol='ui')
        self.assertEqual(UIProtocol, Protocol.for_id('http://ui.org/obj'))

    @patch('requests.get', return_value=requests_response())
    def test_for_id_object_missing_source_protocol(self, _):
        self.store_object(id='http://b.ad/obj')
        self.assertIsNone(Protocol.for_id('http://b.ad/obj'))

    @patch('requests.get')
    def test_for_id_activitypub_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(ACTOR)
        self.assertEqual(ActivityPub, Protocol.for_id('http://ap.org/actor'))
        self.assertIn(self.as2_req('http://ap.org/actor'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_activitypub_fetch_fails(self, mock_get):
        mock_get.return_value = requests_response('', status=403)
        self.assertIsNone(Protocol.for_id('http://ap.org/actor'))
        self.assertIn(self.as2_req('http://ap.org/actor'), mock_get.mock_calls)
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

    @patch('requests.get')
    def test_for_id_web_remote_false(self, mock_get):
        self.assertIsNone(Protocol.for_id('http://web.site/', remote=False))
        mock_get.assert_not_called()

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
            '_atproto.ha.nl.', '"did=did:plc:123abc"'))
    def test_for_handle_atproto_resolve(self, _):
        self.assertEqual((ATProto, 'did:plc:123abc'), Protocol.for_handle('ha.nl'))

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
        self.store_object(id='https://f.ooo', our_as1={'should': 'disappear'},
                          source_protocol='web')

        expected_mf2 = {
            **ACTOR_MF2_REL_URLS,
            'url': 'https://user.com/',
        }

        loaded = Web.load('https://f.ooo', remote=True)
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
            'id': 'fake:follow',
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

        loaded = Fake.load('foo')
        self.assertEqual({'fetched': 'x', 'id': 'foo'}, loaded.our_as1)

    @patch('oauth_dropins.webutil.models.MAX_ENTITY_SIZE', new=50)
    def test_load_too_big(self):
        Fake.fetchable['fake:foo'] = {
            'objectType': 'note',
            'content': 'a bit of text that makes sure we end up over the limit ',
        }
        self.assertIsNone(Fake.load('fake:foo'))

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
        # non-ATProto account, ATProto target (PDS) is bsky.brid.gy
        # shouldn't be blocklisted
        user = self.make_user(id='fake:user', cls=Fake, enabled_protocols=['atproto'])

        did_doc = copy.deepcopy(DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = 'http://localhost/'
        self.store_object(id='did:plc:foo', raw=did_doc)

        # store Objects so we don't try to fetch them remotely
        self.store_object(id='at://did:plc:foo/co.ll/post', our_as1={'foo': 'bar'})
        self.store_object(id='fake:post', our_as1={'foo': 'baz'})

        obj = Object(source_protocol='other', our_as1={
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
            Target(protocol='atproto', uri='https://atproto.brid.gy'),
        ], Protocol.targets(obj, from_user=user).keys())

    def test_targets_undo_share_enabled_protocols(self):
        # https://console.cloud.google.com/errors/detail/CJK54eaoneesMg;time=P30D?project=bridgy-federated
        self.user = self.make_user('fake:user', cls=Fake)

        share = {
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:share',
            'actor': 'fake:user',
            'object': 'fake:orig',
        }
        Fake.fetchable['fake:share'] = share

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': share,
        })
        self.assertEqual({Target(protocol='fake', uri='fake:share:target')},
                         Fake.targets(obj, from_user=self.user).keys())

    def test_targets_composite_inreplyto(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
        }

        obj = Object(our_as1={
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
        })

        self.assertEqual({Target(protocol='fake', uri='fake:post:target')},
                         OtherFake.targets(obj, from_user=self.user).keys())

    def test_targets_link_tag_has_no_orig_obj(self):
        # https://github.com/snarfed/bridgy-fed/issues/1237
        Fake.fetchable['fake:linked-post'] = {
            'objectType': 'note',
        }

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'objectType': 'note',
                'id': 'fake:post',
                'tags': [{'url': 'fake:linked-post'}],
            },
        })
        self.assertEqual({Target(protocol='fake', uri='fake:linked-post:target'): None},
                         OtherFake.targets(obj, from_user=self.user))

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

    def test_translate_ids_delete_actor(self):
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'other:u:fake:alice',
            'object': 'other:u:fake:alice',
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:alice',
            'object': 'fake:alice',
        }))

    def test_translate_ids_attachments_mention_tags(self):
        self.assert_equals({
            'objectType': 'note',
            'attachments': [
                {'id': 'other:o:fa:fake:123'},
                {'id': 'other:o:fa:fake:456',
                 'url': 'fake:456'},
            ],
            'tags': [
                {'objectType': 'mention', 'url': 'other:u:fake:alice'},
                {'url': 'fake:000'},
            ],
        }, OtherFake.translate_ids({
            'objectType': 'note',
            'attachments': [
                {'id': 'fake:123'},
                {'url': 'fake:456'},
            ],
            'tags': [
                {'objectType': 'mention', 'url': 'fake:alice'},
                {'url': 'fake:000'},
            ],
        }))

    def test_translate_ids_attachment_url_blocklisted(self):
        self.assert_equals({
            'objectType': 'note',
            'attachments': [{'url': 'https://t.co/foo'}],
        }, OtherFake.translate_ids({
            'objectType': 'note',
            'attachments': [{'url': 'https://t.co/foo'}],
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
            'attachments': [{
                'objectType': 'note',
                'id': 'other:post',
                'url': 'fake:post',
            }],
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': {
                'id': 'fake:reply',
                'inReplyTo': 'fake:post',
            },
            'attachments': [{
                'objectType': 'note',
                'url': 'fake:post',
            }],
        }))

    def test_translate_ids_multiple_objects(self):
        self.assert_equals({
            'objectType': 'activity',
            'verb': 'flag',
            'object': [
                'other:eve',
                'other:o:fa:fake:bob',
            ],
        }, OtherFake.translate_ids({
            'objectType': 'activity',
            'verb': 'flag',
            'object': [
                'other:eve',
                'fake:bob',
            ]
        }))

    def test_convert_object_is_from_user_adds_source_links(self):
        alice = Fake(id='fake:alice')
        self.assertEqual({
            'objectType': 'application',
            'id': 'other:u:fake:alice',
            'url': 'http://unused',
            'summary': 'something about me<br><br>[<a href="https://fed.brid.gy/fa/fake:handle:alice">bridged</a> from <a href="web:fake:alice">fake:handle:alice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
        }, OtherFake.convert(Object(
            id='fake:profile:alice', source_protocol='fake', our_as1={
                'objectType': 'application',
                'id': 'fake:alice',
                'url': 'http://unused',
                'summary': 'something about me',
            }), from_user=alice))

    def test_convert_object_isnt_from_user_adds_source_links(self):
        bob = Fake(id='fake:bob')
        self.assertEqual({
            'objectType': 'application',
            'id': 'other:u:fake:alice',
            'url': 'http://al/ice',
            'summary': '[bridged from <a href="http://al/ice">al/ice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
        }, OtherFake.convert(Object(id='fake:alice', source_protocol='fake', our_as1={
            'objectType': 'application',
            'id': 'fake:alice',
            'url': 'http://al/ice',
        }), from_user=bob))

    def test_convert_actor_without_from_user_doesnt_add_source_links(self):
        self.assertEqual({
            'objectType': 'application',
            'id': 'other:u:fake:alice',
            'url': 'http://al/ice',
        }, OtherFake.convert(Object(id='fake:alice', source_protocol='fake', our_as1={
            'objectType': 'application',
            'id': 'fake:alice',
            'url': 'http://al/ice',
        })))

    def test_convert_doesnt_duplicate_source_links(self):
        alice = Fake(id='fake:alice')
        summary = 'something about me<br><br>[bridged from <a href="http://al/ice">someone else</a> by <a href="https://fed.brid.gy/">Bridgy Fed</a>]'
        self.assertEqual({
            'objectType': 'application',
            'id': 'other:u:fake:alice',
            'summary': summary,
        }, OtherFake.convert(Object(id='fake:alice', source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:alice',
            'summary': summary,
        }), from_user=alice))

    def test_convert_object_adds_source_links_to_create_update(self):
        alice = Fake(id='fake:alice')
        for verb in 'post', 'update':
            self.assertEqual({
                'objectType': 'activity',
                'verb': verb,
                'id': 'other:o:fa:fake:profile:update',
                'object': {
                    'objectType': 'application',
                    'id': 'other:u:fake:profile:alice',
                    'summary': 'something about me<br><br>[<a href="https://fed.brid.gy/fa/fake:handle:alice">bridged</a> from <a href="web:fake:alice">fake:handle:alice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
                },
            }, OtherFake.convert(
                Object(id='fake:profile:update', source_protocol='fake', our_as1={
                    'objectType': 'activity',
                    'verb': verb,
                    'object': {
                        'id': 'fake:profile:alice',
                        'objectType': 'application',
                        'summary': 'something about me',
                    },
                }), from_user=alice))

    def test_check_supported(self):
        for obj in (
            {'objectType': 'note'},
            {'objectType': 'activity', 'verb': 'post',
             'object': {'objectType': 'note'}},
            {'objectType': 'activity', 'verb': 'follow'},
            {'objectType': 'activity', 'verb': 'delete', 'object': 'x'},
            {'objectType': 'activity', 'verb': 'undo', 'object': {'foo': 'bar'}},
            {'objectType': 'activity', 'verb': 'undo',
             'object': {'objectType': 'activity', 'verb': 'share'}},
            {'objectType': 'activity', 'verb': 'flag'},
        ):
            with self.subTest(obj=obj):
                Fake.check_supported(Object(our_as1=obj))

        for obj in (
            {'objectType': 'event'},
            {'objectType': 'activity', 'verb': 'post',
             'object': {'objectType': 'event'}},
        ):
            with self.subTest(obj=obj), self.assertRaises(NoContent):
                Fake.check_supported(Object(our_as1=obj))

        # Fake doesn't support DMs, ExplicitEnableFake does
        for actor, recip in (
                ('ap.brid.gy', 'did:bob'),
                ('did:bob', 'ap.brid.gy'),
        ):
            bot_dm = Object(our_as1={
                'objectType': 'note',
                'actor': actor,
                'to': [recip],
                'content': 'hello world',
            })
            ExplicitEnableFake.check_supported(bot_dm)
            with self.assertRaises(NoContent):
                Fake.check_supported(bot_dm)

        dm = Object(our_as1={
            'objectType': 'note',
            'actor': 'did:alice',
            'to': ['did:bob'],
            'content': 'hello world',
        })
        for proto in Fake, ExplicitEnableFake:
            with self.subTest(proto=proto), self.assertRaises(NoContent):
                proto.check_supported(dm)

    def test_bot_follow(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='fake:user', cls=Fake, obj_id='fake:user')
        Fake.bot_follow(user)

        self.assertEqual([
            ('https://fa.brid.gy/#follow-back-fake:user-2022-01-02T03:04:05+00:00',
             'fake:user:target'),
        ], Fake.sent)

    def test_bot_follow_user_missing_obj(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = Fake(id='fake:user')
        assert not user.obj
        Fake.bot_follow(user)
        self.assertEqual([], Fake.sent)

    def test_maybe_bot_dm(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='other:user', cls=OtherFake, obj_as1={'x': 'y'})

        Fake.maybe_bot_dm(user, text='hi hi hi', type='replied_to_bridged_user')
        self.assertEqual([
            ('https://fa.brid.gy/#replied_to_bridged_user-dm-other:user-2022-01-02T03:04:05+00:00',
             'other:user:target'),
        ], OtherFake.sent)
        expected_sent_dms = [DM(protocol='fake', type='replied_to_bridged_user')]
        self.assertEqual(expected_sent_dms, user.key.get().sent_dms)

        # now that this type is in sent_dms, another attempt should be a noop
        OtherFake.sent = []
        Fake.maybe_bot_dm(user, text='hi again', type='replied_to_bridged_user')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual(expected_sent_dms, user.key.get().sent_dms)

    def test_maybe_bot_dm_user_missing_obj(self):
        self.make_user(id='other.brid.gy', cls=Web)
        user = OtherFake(id='other:user')
        assert not user.obj

        OtherFake.maybe_bot_dm(user, text='nope', type='welcome')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], user.sent_dms)

    # TODO: translate_ids tests that actually test translation
    def test_translate_ids_empty(self):
        self.assertEqual({}, Fake.translate_ids({}))

    def test_translate_ids_single_inReplyTo(self):
        obj = {'inReplyTo': 'foo'}
        self.assertEqual(obj, Fake.translate_ids(obj))

    def test_translate_ids_multiple_inReplyTo(self):
        obj = {'inReplyTo': ['foo', 'bar']}
        self.assertEqual(obj, Fake.translate_ids(obj))


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
                                 delivered=['fake:shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

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
                                 delivered=['fake:shared:target'],
                                 type='post',
                                 users=[Fake(id='fake:user').key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

    def test_create_post_bare_object_existing_failed_create(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')
        self.store_object(id='fake:post#bridgy-fed-create', status='failed')

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        obj = self.assert_object('fake:post#bridgy-fed-create',
                                 status='complete',
                                 delivered=['fake:shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 ignore=['our_as1'],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

    def test_create_post_bare_object_no_existing_create(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        obj = self.assert_object('fake:post#bridgy-fed-create',
                                 status='complete',
                                 delivered=['fake:shared:target'],
                                 type='post',
                                 users=[self.user.key],
                                 ignore=['our_as1'],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

    @patch.object(ATProto, 'send', return_value=True)
    def test_post_by_user_enabled_atproto_adds_pds_target(self, mock_send):
        self.user.enabled_protocols = ['atproto']
        self.user.put()

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }))

        self.assertEqual(1, mock_send.call_count)
        [obj, url], _ = mock_send.call_args
        self.assertEqual('fake:post#bridgy-fed-create', obj.key.id())
        self.assertEqual(ATProto.PDS_URL, url)

    @patch.object(ATProto, 'send')
    def test_reply_to_not_bridged_account_skips_atproto(self, mock_send):
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('eefake:eve', cls=ExplicitEnableFake)
        self.store_object(id='eefake:post', our_as1={
            'id': 'eefake:post',
            'objectType': 'note',
            'author': 'eefake:eve',
        })

        ExplicitEnableFake.receive_as1({
            'id': 'eefake:reply',
            'objectType': 'note',
            'author': 'eefake:user',
            'inReplyTo': 'eefake:post',
        })

        self.assertEqual(0, mock_send.call_count)

    @patch.object(ATProto, 'send')
    def test_reply_to_non_bridged_post_with_mention_skips_atproto(self, mock_send):
        self.user.enabled_protocols = ['atproto']
        self.user.put()

        self.store_object(id='fake:post', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
        })

        Fake.receive_as1({
            'id': 'fake:reply',
            'objectType': 'note',
            'actor': 'fake:user',
            'inReplyTo': 'fake:post',
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:bob'
            }],
        })

        self.assertEqual(0, mock_send.call_count)

    def test_reply_to_non_bridged_post_skips_enabled_protocol_with_followers(self):
        self.make_user(id='fa.brid.gy', cls=Web)

        # should skip even if it's enabled and we have followers there
        self.user.enabled_protocols = ['eefake']
        self.user.put()

        eve = self.make_user('eefake:eve', cls=ExplicitEnableFake)
        Follower.get_or_create(from_=eve, to=self.user)

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
        })
        _, code = Fake.receive_as1({
            'id': 'fake:reply',
            'objectType': 'note',
            'actor': 'fake:user',
            'inReplyTo': 'fake:post',
        })
        self.assertEqual(202, code)
        self.assertEqual([], ExplicitEnableFake.sent)

    def test_reply_from_non_bridged_post_isnt_bridged_but_gets_dm_prompt(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        self.user.enabled_protocols = ['eefake']
        self.user.put()

        eve = self.make_user('eefake:eve', cls=ExplicitEnableFake, obj_as1={
            'id': 'eefake:eve',
        })

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
        })

        _, code = ExplicitEnableFake.receive_as1({
            'id': 'eefake:reply',
            'objectType': 'note',
            'actor': 'eefake:eve',
            'inReplyTo': 'fake:post',
        })
        self.assertEqual(204, code)

        self.assertEqual([], Fake.sent)
        self.assertEqual([
            ('https://fa.brid.gy/#replied_to_bridged_user-dm-eefake:eve-2022-01-02T03:04:05+00:00',
             'eefake:eve:target'),
        ], ExplicitEnableFake.sent)

        eve = eve.key.get()
        self.assertEqual([DM(protocol='fake', type='replied_to_bridged_user')],
                         eve.sent_dms)

    @patch.object(ATProto, 'send', return_value=True)
    def test_repost_of_non_bridged_account_skips_atproto(self, mock_send):
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('eefake:eve', cls=ExplicitEnableFake)
        self.store_object(id='eefake:post', our_as1={
            'id': 'eefake:post',
            'objectType': 'note',
            'author': 'eefake:eve',
        })

        _, code = ExplicitEnableFake.receive_as1({
            'id': 'eefake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'eefake:user',
            'object': 'eefake:post',
        })
        self.assertEqual(204, code)
        self.assertEqual(0, mock_send.call_count)

    @patch.object(ATProto, 'send', return_value=True)
    def test_repost_of_not_bridged_post_skips_atproto(self, mock_send):
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('eefake:eve', cls=ExplicitEnableFake,
                              enabled_protocols=['atproto'])
        self.store_object(id='eefake:post', our_as1={
            'id': 'eefake:post',
            'objectType': 'note',
            'author': 'eefake:eve',
        })

        _, code = ExplicitEnableFake.receive_as1({
            'id': 'eefake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'eefake:user',
            'object': 'eefake:post',
        })
        self.assertEqual(204, code)
        self.assertEqual(0, mock_send.call_count)

    def test_repost_of_not_bridged_post_skips_enabled_protocol_with_followers(self):
        # should skip even if it's enabled and we have followers there
        self.user.enabled_protocols = ['eefake']
        self.user.put()

        eve = self.make_user('eefake:eve', cls=ExplicitEnableFake)
        Follower.get_or_create(from_=eve, to=self.user)

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
        })
        _, code = Fake.receive_as1({
            'id': 'fake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:user',
            'object': 'fake:post',
        })
        self.assertEqual(202, code)
        self.assertEqual([], ExplicitEnableFake.sent)

    @patch.object(ATProto, 'send', return_value=True)
    def test_follow_of_bridged_account_by_not_bridged_account_skips_atproto(
            self, mock_send):
        user = self.make_user('eefake:user', cls=ExplicitEnableFake)
        self.store_object(id='did:plc:eve', raw=DID_DOC)
        eve = self.make_user('did:plc:eve', cls=ATProto, enabled_protocols=['eefake'],
                             copies=[Target(uri='eefake:eve', protocol='eefake')],
                             obj_bsky=ACTOR_PROFILE_BSKY)

        _, code = ExplicitEnableFake.receive_as1({
            'id': 'eefake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'eefake:user',
            'object': 'eefake:eve',
        })
        self.assertEqual(204, code)

        self.assert_entities_equal(Follower(from_=user.key, to=eve.key,
                                            follow=Object(id='eefake:follow').key),
                                   Follower.query().fetch(),
                                   ignore=['created', 'updated'])
        self.assertEqual(0, mock_send.call_count)

    def test_targets_block(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'fake:block',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }
        self.assertEqual(
            [Target(uri='fake:bob:target', protocol='fake')],
            list(Fake.targets(Object(our_as1=block), from_user=self.user).keys()))

    def test_targets_undo_composite_block(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        undo = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:alice',
            'object': {
                'objectType': 'activity',
                'verb': 'block',
                'id': 'fake:block',
                'actor': 'fake:alice',
                'object': 'fake:bob',
            },
        }
        self.assertEqual(
            [Target(uri='fake:bob:target', protocol='fake')],
            list(Fake.targets(Object(our_as1=undo), from_user=self.user).keys()))

    def test_targets_undo_block_id(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        self.store_object(id='fake:block', our_as1={
            'objectType': 'activity',
            'verb': 'block',
            'id': 'fake:block',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        })

        undo = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:alice',
            'object': 'fake:block',
        }
        self.assertEqual(
            [Target(uri='fake:block:target', protocol='fake'),
             Target(uri='fake:bob:target', protocol='fake')],
            list(Fake.targets(Object(our_as1=undo), from_user=self.user).keys()))

    def test_targets_undo_share_composite(self):
        self.make_followers()

        share = {
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:share',
            'actor': 'fake:user',
            'object': 'fake:orig',
        }
        Fake.fetchable['fake:share'] = share

        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': share,
        })
        self.assertEqual({
            Target(protocol='fake', uri='fake:share:target'),
            Target(protocol='fake', uri='fake:shared:target'),
        }, Fake.targets(obj, from_user=self.user).keys())

    @patch.object(ATProto, 'send', return_value=True)
    def test_atproto_targets_normalize_pds_url(self, mock_send):
        # we were over-normalizing our PDS URL https://atproto.brid.gy , adding
        # a trailing slash, and then ending up with both versions in targets.
        # https://github.com/snarfed/bridgy-fed/issues/1032
        self.user.enabled_protocols = ['atproto']

        # atproto follower
        self.store_object(id='did:plc:eve', raw={**DID_DOC, 'id': 'at://did:plc:eve'})
        obj = self.store_object(id='at://did:plc:eve/app.bsky.actor.profile/self',
                                bsky=ACTOR_PROFILE_BSKY)
        eve = self.make_user('did:plc:eve', cls=ATProto, obj_key=obj.key)
        Follower.get_or_create(from_=eve, to=self.user)

        obj = Object(id='fake:post', our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {
                'id': 'fake:post',
                'objectType': 'note',
                'author': 'fake:user',
            },
        })
        self.assertEqual({
            Target(uri='https://atproto.brid.gy', protocol='atproto'): None,
        }, Fake.targets(obj, from_user=self.user))

    def test_create_post_dont_deliver_to_follower_if_protocol_isnt_enabled(self):
        # user who hasn't enabled either Fake or OtherFake, so we shouldn't
        # deliver to followers on those protocols
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              obj_id='eefake:user')
        frank = self.make_user('other:frank', cls=OtherFake, obj_id='other:frank')
        Follower.get_or_create(to=user, from_=self.alice)
        Follower.get_or_create(to=user, from_=frank)

        _, code = ExplicitEnableFake.receive_as1({
            'objectType': 'note',
            'id': 'eefake:post',
            'author': 'eefake:user',
            'content': 'foo'
        })
        self.assertEqual(204, code)

        self.assertEqual([], Fake.sent)
        self.assertEqual([], OtherFake.sent)
        obj = Object.get_by_id('eefake:post#bridgy-fed-create')
        self.assertEqual([], obj.delivered)

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
        obj = self.store_object(id='fake:post', our_as1=post_as1,
                                source_protocol='fake')

        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))
        self.assertEqual(1, len(Fake.sent))
        self.assertEqual('fake:shared:target', Fake.sent[0][1])

    def test_update_post_wrong_actor_error(self):
        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')

        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:update',
                'objectType': 'activity',
                'verb': 'update',
                'actor': 'fake:other',
                'object': post_as1,
            }, authed_as='fake:eve')

    def test_update_post(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')

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
                                 delivered=['fake:shared:target'],
                                 type='update',
                                 users=[self.user.key],
                                 notify=[],
                                 )

        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

    def test_update_post_bare_object(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'first',
        }
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')
        existing = Object.get_by_id('fake:post')

        post_as1['content'] = 'second'
        _, code = Fake.receive_as1(post_as1)
        self.assertEqual(204, code)

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
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')

        frank = self.make_user('other:frank', cls=OtherFake, obj_id='other:frank')
        Follower.get_or_create(to=self.alice, from_=frank)

        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'author': 'other:eve',
        }
        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'other:post',
            'author': 'fake:alice',
        }
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:alice',
            'object': reply_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object(
            'fake:reply',
            our_as1=reply_as1,
            type='note',
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
        )
        obj = self.assert_object('fake:create',
                                 status='complete',
                                 our_as1=create_as1,
                                 delivered=['other:post:target'],
                                 delivered_protocol='other',
                                 type='post',
                                 users=[self.alice.key],
                                 notify=[eve.key],
                                 )

        # not a self reply, shouldn't deliver to follower frank
        self.assertEqual([(obj.key.id(), 'other:post:target')], OtherFake.sent)

    def test_create_reply_bare_object(self):
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'other:post',
            'author': 'fake:alice',
        }
        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'id': 'other:post',
            'author': 'other:eve',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object(
            'fake:reply',
            our_as1=reply_as1,
            type='note',
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
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
                                 delivered=['other:post:target'],
                                 delivered_protocol='other',
                                 type='post',
                                 users=[self.alice.key],
                                 notify=[eve.key],
                                 )

        self.assertEqual([(obj.key.id(), 'other:post:target')], OtherFake.sent)

    def test_create_reply_to_self_delivers_to_followers(self):
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        Follower.get_or_create(to=self.user, from_=eve)

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:user',
        }
        self.store_object(id='fake:post', source_protocol='fake',
                          copies=[Target(protocol='other', uri='other:post')],
                          our_as1={
                              'objectType': 'note',
                              'id': 'fake:post',
                              'author': 'fake:user',
                          })
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object(
            'fake:reply',
            our_as1=reply_as1,
            type='note',
            feed=[eve.key],
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
        )

        obj = Object.get_by_id(id='fake:reply#bridgy-fed-create')
        self.assertEqual([(obj.key.id(), 'fake:post:target')], Fake.sent)
        self.assertEqual([(obj.key.id(), 'other:eve:target'),
                          (obj.key.id(), 'other:post:target'),
                          ], OtherFake.sent)

    def test_create_reply_to_other_protocol(self):
        eve = self.make_user('fake:eve', cls=Fake, obj_id='fake:eve')
        self.store_object(id='fake:post', source_protocol='fake',
                          copies=[Target(protocol='other', uri='other:post')],
                          our_as1={
                              'objectType': 'note',
                              'id': 'fake:post',
                              'author': 'fake:eve',
                          })
        self.store_object(id='other:post', source_protocol='other',
                          our_as1={
                              'objectType': 'note',
                              'id': 'other:post',
                              'author': 'fake:eve',
                          })

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'fake:post',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        copy = Target(protocol='other', uri='other:o:fa:fake:reply')
        reply = self.assert_object('fake:reply', our_as1=reply_as1, type='note',
                                   copies=[copy])
        self.assertEqual([('fake:reply#bridgy-fed-create', 'other:post:target')],
                         OtherFake.sent)

    def test_create_reply_with_copy_on_not_enabled_protocol(self):
        self.store_object(id='fake:post', source_protocol='fake',
                          copies=[Target(protocol='eefake', uri='eefake:post')],
                          our_as1={
                              'objectType': 'note',
                              'id': 'fake:post',
                              'author': 'fake:alice',
                          })

        _, code = Fake.receive_as1({
            'objectType': 'note',
            'id': 'fake:reply',
            'author': 'fake:user',
            'inReplyTo': 'fake:post',
            'content': 'foo',
        })
        self.assertEqual(202, code)
        self.assertEqual([], ExplicitEnableFake.sent)

    def test_create_self_reply_to_same_protocol_bridge_if_original_is_bridged(self):
        # use eefake because Protocol.targets automatically adds fake and other
        # to to_protocols.
        # TODO: refactor tests to not do fake-to-fake delivery, then remove
        # these special cases
        user = self.make_user('eefake:user', cls=ExplicitEnableFake,
                              obj_id='eefake:user', enabled_protocols=['other'])

        # eve follows user
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        Follower.get_or_create(to=user, from_=eve)

        # user replies to themselves
        self.store_object(id='eefake:post', source_protocol='eefake',
                          copies=[Target(protocol='other', uri='other:post')],
                          our_as1={
                              'objectType': 'note',
                              'id': 'eefake:post',
                              'author': 'eefake:user',
                          })

        reply_as1 = {
            'id': 'eefake:reply',
            'objectType': 'note',
            'inReplyTo': 'eefake:post',
            'author': 'eefake:user',
        }
        self.assertEqual(('OK', 202), ExplicitEnableFake.receive_as1(reply_as1))

        copy = Target(protocol='other', uri='other:o:eefake:eefake:reply')
        reply = self.assert_object('eefake:reply',
                                   type='note',
                                   source_protocol='eefake',
                                   our_as1=reply_as1,
                                   copies=[copy],
                                   feed=[eve.key])
        self.assertEqual([('eefake:reply#bridgy-fed-create', 'other:eve:target'),
                          ('eefake:reply#bridgy-fed-create', 'other:post:target'),
                          ], OtherFake.sent)

    def test_update_reply(self):
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')

        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'author': 'other:eve',
        }
        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'other:post',
            'author': 'fake:user',
        }
        self.store_object(id='fake:reply', our_as1=reply_as1, source_protocol='fake')

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
                                 delivered=['other:post:target'],
                                 delivered_protocol='other',
                                 type='update',
                                 users=[self.user.key],
                                 notify=[eve.key],
                                 )
        self.assertEqual([(obj.key.id(), 'other:post:target')], OtherFake.sent)

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
                                 delivered=['fake:post:target', 'fake:shared:target'],
                                 type='share',
                                 users=[self.user.key],
                                 notify=[self.bob.key],
                                 feed=[self.alice.key, self.bob.key],
                                 )
        self.assertEqual([
            (obj.key.id(), 'fake:post:target'),
            (obj.key.id(), 'fake:shared:target'),
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
        _, code = Fake.receive_as1(repost_as1)
        self.assertEqual(204, code)

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
                                      )

        self.assertEqual([(like_obj.key.id(), 'fake:post:target')], Fake.sent)

    def test_like_no_object_error(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:like',
                'objectType': 'activity',
                'verb': 'like',
                'actor': 'fake:user',
                'object': None,
        })

    def test_share_no_object_error(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
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
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake')

        delete_as1 = {
            'id': 'fake:delete',
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        self.assertEqual(('OK', 202),
                         Fake.receive_as1(delete_as1, authed_as='fake:user'))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           deleted=True,
                           source_protocol='fake',
                           feed=[self.alice.key, self.bob.key],
                           )

        obj = self.assert_object('fake:delete',
                                 status='complete',
                                 our_as1=delete_as1,
                                 delivered=['fake:shared:target'],
                                 type='delete',
                                 users=[self.user.key],
                                 notify=[],
                                 )
        self.assertEqual([(obj.key.id(), 'fake:shared:target')], Fake.sent)

    def test_delete_no_followers_no_stored_object(self):
        delete_as1 = {
            'id': 'fake:delete',
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        _, code = Fake.receive_as1(delete_as1)
        self.assertEqual(204, code)

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

    def test_delete_not_authed_as_object_owner(self):
        self.make_followers()

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'id': 'fake:post',
            'author': 'fake:user',
        })

        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'objectType': 'activity',
                'verb': 'delete',
                'id': 'fake:delete',
                'actor': 'fake:user',
                'object': 'fake:post',
            }, authed_as='fake:eve')

        self.assertFalse(Object.get_by_id('fake:post').deleted)
        self.assertEqual([], Fake.sent)

    def test_delete_actor(self):
        follower = Follower.get_or_create(to=self.user, from_=self.alice)
        followee = Follower.get_or_create(to=self.alice, from_=self.bob)
        other = Follower.get_or_create(to=self.user, from_=self.bob)
        self.assertEqual(3, Follower.query().count())

        _, code = Fake.receive_as1({
            'objectType': 'activity',
            'verb': 'delete',
            'id': 'fake:delete',
            'actor': 'fake:alice',
            'object': 'fake:alice',
        })
        self.assertEqual(204, code)

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
            delivered=['fake:shared:target'],
            type='update',
        )

        self.assertEqual([(update_obj.key.id(), 'fake:shared:target')], Fake.sent)

    def test_update_profile_bare_object(self):
        self.make_followers()

        actor = self.user.obj.our_as1 = {
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Ms. ☕ Baz',
            'summary': 'first',
        }
        self.user.obj.put()

        # unchanged from what's already in the datastore. we should send update
        # anyway (instead of create) since it's an actor.
        Fake.receive_as1(actor)

        # profile object
        actor['updated'] = '2022-01-02T03:04:05+00:00'
        self.assert_object('fake:user', our_as1=actor, type='person')

        # update activity
        id = 'fake:user#bridgy-fed-update-2022-01-02T03:04:05+00:00'
        update_obj = self.assert_object(
            id,
            users=[self.user.key],
            status='complete',
            our_as1={
                'objectType': 'activity',
                'verb': 'update',
                'id': id,
                'actor': actor,
                'object': actor,
            },
            delivered=['fake:shared:target'],
            type='update',
        )
        self.assertEqual([(id, 'fake:shared:target')], Fake.sent)

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

        accept_id = 'fake:user/followers#accept-fake:follow'
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

    def test_follow_protocol_that_doesnt_support_accept(self, **extra):
        OtherFake.fetchable['other:eve'] = {}

        follow_as1 = {
            'id': 'other:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'other:eve',
            'object': 'fake:user',
        }
        self.assertEqual(('OK', 202), OtherFake.receive_as1(follow_as1))

        other = OtherFake.get_by_id('other:eve')
        self.assert_object(
            'other:follow',
            source_protocol='other',
            our_as1=follow_as1,
            copies=[Target(protocol='fake', uri='fake:o:other:other:follow')],
            status='complete',
            users=[OtherFake(id='other:eve').key],
            notify=[self.user.key],
            delivered=['fake:user:target'],
            delivered_protocol='fake',
        )

        self.assertEqual(0, Object.query(Object.type == 'accept').count())
        self.assertEqual([], OtherFake.sent)

    def test_follow_no_actor(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'object': 'fake:user',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_follow_no_object(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'fake:alice',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_follow_object_unknown_protocol(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
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

        with self.assertRaises(NoContent):
            _, status = OtherFake.receive_as1(accept_as1)

        self.assertEqual([], Fake.sent)
        self.assertEqual([], OtherFake.sent)

    def test_follow_accept(self, **extra):
        Fake.fetchable['fake:follow'] = {'id': 'fake:follow'}
        accept_as1 = {
            'id': 'fake:accept',
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'fake:alice',
            'object': 'fake:follow'
        }

        self.assertEqual(('OK', 202), Fake.receive_as1(accept_as1))
        self.assertEqual([
            ('fake:accept', 'fake:follow:target'),
        ], Fake.sent)

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

    def test_block(self):
        self.bob.obj.our_as1 = {'id': 'fake:bob'}
        self.bob.obj.put()

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'id': 'fake:block',
            'objectType': 'activity',
            'verb': 'block',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }))

        self.assertEqual([('fake:block', 'fake:bob:target')], Fake.sent)

    def test_undo_block(self):
        self.make_user(id='other:eve', cls=OtherFake, obj_as1={})
        self.make_followers()

        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'fake:block',
            'actor': 'fake:user',
            'object': 'other:eve',
        }
        self.store_object(id='fake:block', our_as1=block, source_protocol='fake')

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:user',
            'object': block,
        }))
        self.assertEqual([('fake:undo', 'fake:block:target')], Fake.sent)

    def test_undo_repost(self):
        self.make_followers()

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'id': 'fake:post',
            'actor': 'fake:user',
        })
        self.store_object(id='fake:repost', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:repost',
            'actor': 'fake:user',
            'object': 'fake:post',
        })

        self.assertEqual(('OK', 202), Fake.receive_as1({
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:user',
            'object': 'fake:repost',
        }))
        self.assertTrue(Object.get_by_id('fake:repost').deleted)
        self.assertEqual([
            ('fake:undo', 'fake:post:target'),
            ('fake:undo', 'fake:repost:target'),
            ('fake:undo', 'fake:shared:target'),
        ], Fake.sent)

    def test_undo_not_authed_as_object_owner(self):
        self.store_object(id='fake:repost', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:repost',
            'actor': 'fake:user',
            'object': 'fake:post',
        })

        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'objectType': 'activity',
                'verb': 'undo',
                'id': 'fake:undo',
                'actor': 'fake:user',
                'object': 'fake:repost',
            }, authed_as='fake:eve')

        self.assertFalse(Object.get_by_id('fake:repost').deleted)
        self.assertEqual([], Fake.sent)

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

        self.assertEqual(1, len(Fake.sent))
        self.assertEqual('other:follow', Fake.sent[0][0])

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual(self.alice.key, followers[0].to)

    def test_skip_bridged_user(self):
        """If the actor isn't from the source protocol, skip the activity.

        (It's probably from a bridged user, and we only want to handle source
        activities, not bridged activities.)
        """
        self.user.copies = [Target(uri='other:user', protocol='other')]
        self.user.put()

        with self.assertRaises(NoContent):
            OtherFake.receive_as1({
                'id': 'other:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'fake:user',
                'object': 'fake:alice',
            })
        self.assertEqual(0, len(OtherFake.sent))
        self.assertEqual(0, len(Fake.sent))
        self.assertIsNone(Object.get_by_id('other:follow'))

    @patch('requests.post')
    @patch('requests.get')
    def test_skip_web_same_domain(self, mock_get, mock_post):
        self.make_user('user.com', cls=Web)
        mock_get.side_effect = [
            ACTOR_HTML_RESP,
            NOTE_HTML_RESP,
            NOTE_HTML_RESP,
            NOTE_HTML_RESP,
            NOTE_HTML_RESP,
        ]

        follow_as1 = {
            'id': 'http://user.com/follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'http://user.com/',
            'object': ['http://user.com/bob', 'http://user.com/eve'],
        }

        _, code = Web.receive(Object(our_as1=follow_as1), authed_as='user.com')
        self.assertEqual(204, code)

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

    def test_activity_id_blocklisted(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'objectType': 'activity',
                'verb': 'delete',
                'id': 'fake:blocklisted:delete',
                'actor': 'fake:user',
                'object': 'fake:foo',
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
        self.assertEqual(('OK', 202), Fake.receive(obj, authed_as='fake:alice'))
        self.assert_equals(follow, obj.our_as1)

        # matching copy user
        self.make_user('other:bob', cls=OtherFake,
                       copies=[Target(uri='fake:bob', protocol='fake')])

        common.memcache.clear()
        models.get_originals.cache_clear()

        obj.new = True
        OtherFake.fetchable = {
            'other:bob': {},
        }

        self.assertEqual(('OK', 202), Fake.receive(obj, authed_as='fake:alice'))
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
        _, code = Fake.receive(obj, authed_as='fake:alice')
        self.assertEqual(204, code)
        self.assert_equals(share, obj.our_as1)

        # matching copy object
        self.store_object(id='other:post',
                          copies=[Target(uri='fake:post', protocol='fake')])

        common.memcache.clear()
        models.get_originals.cache_clear()
        obj.new = True

        _, code = Fake.receive(obj, authed_as='fake:alice')
        self.assertEqual(204, code)

        self.assert_equals({
            'id': 'fake:share',
            'objectType': 'activity',
            'actor': 'fake:alice',
            'verb': 'share',
            'object': 'other:post',
        }, obj.our_as1)

    def test_resolve_ids_reply_mentions(self):
        reply = {
            'id': 'other:reply',
            'author': 'other:eve',
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
        _, code = OtherFake.receive(obj, authed_as='other:eve')
        self.assertEqual(204, code)
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

        models.get_originals.cache_clear()

        obj.new = True
        self.assertEqual(('OK', 202),
                         OtherFake.receive(obj, authed_as='other:eve'))
        self.assertEqual({
            'id': 'other:reply',
            'objectType': 'note',
            'author': 'other:eve',
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

    def test_follow_and_block_protocol_user_sets_enabled_protocols(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        follow = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'eefake:follow',
            'actor': 'eefake:user',
            'object': 'fa.brid.gy',
        }
        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'eefake:block',
            'actor': 'eefake:user',
            'object': 'fa.brid.gy',
        }

        user = self.make_user('eefake:user', cls=ExplicitEnableFake)
        self.assertFalse(user.is_enabled(Fake))
        ExplicitEnableFake.fetchable = {'eefake:user': {'profile': 'info'}}

        # fake protocol isn't enabled yet, block should be a noop
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(block))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)

        # follow should add to enabled_protocols
        _, code = ExplicitEnableFake.receive_as1(follow)
        self.assertEqual(204, code)
        user = user.key.get()
        self.assertEqual({
            'id': 'eefake:user',
            'profile': 'info',
        }, user.obj.as1)

        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual(['eefake:user'], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))

        dm_id = 'https://fa.brid.gy/#welcome-dm-eefake:user-2022-01-02T03:04:05+00:00'
        follow_back_id = 'https://fa.brid.gy/#follow-back-eefake:user-2022-01-02T03:04:05+00:00'
        self.assertEqual([
            (dm_id, 'eefake:user:target'),
            # fa.brid.gy follows back
            (follow_back_id, 'eefake:user:target'),
            ('fa.brid.gy/followers#accept-eefake:follow', 'eefake:user:target'),
        ], ExplicitEnableFake.sent)

        # another follow should be a noop
        follow['id'] += '2'
        Fake.created_for = []
        _, code = ExplicitEnableFake.receive_as1(follow)
        self.assertEqual(204, code)
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual([], Fake.created_for)

        # block should remove from enabled_protocols
        Follower.get_or_create(to=user, from_=self.alice)
        block['id'] += '2'
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(block))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)
        self.assertFalse(user.is_enabled(Fake))

        # ...and delete copy actor
        self.assertEqual(
            [('eefake:user#delete-copy-fake-2022-01-02T03:04:05+00:00',
              'fake:shared:target')],
            Fake.sent)

        id = 'eefake:user#delete-copy-fake-2022-01-02T03:04:05+00:00'
        self.assert_object(id,
                           our_as1={
                               'objectType': 'activity',
                               'verb': 'delete',
                               'id': id,
                               'actor': 'eefake:user',
                               'object': 'eefake:user',
                           },
                           delivered=['fake:shared:target'],
                           source_protocol='eefake',
                           status='complete')

    def test_follow_bot_user_refreshes_profile(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        # store profile that's opted out
        user = self.make_user('eefake:user', cls=ExplicitEnableFake, obj_as1={
            'id': 'eefake:user',
            'summary': '#nobridge',
        })
        self.assertFalse(user.is_enabled(Fake))

        # updated profile isn't opted out
        ExplicitEnableFake.fetchable = {'eefake:user': {
            'id': 'eefake:user',
            'summary': 'never mind',
        }}

        # follow should refresh profile
        _, code = ExplicitEnableFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'eefake:follow',
            'actor': 'eefake:user',
            'object': 'fa.brid.gy',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['eefake:user'], ExplicitEnableFake.fetched)

    def test_follow_bot_user_copy_id_refreshes_profile(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web,
                       copies=[Target(uri='eefake:bot', protocol='eefake')])

        # profile that's opted out
        user = self.make_user('eefake:user', cls=ExplicitEnableFake, obj_as1={
            'id': 'eefake:user',
            'summary': '#nobridge',
        })
        self.assertFalse(user.is_enabled(Fake))

        # updated profile isn't opted out
        ExplicitEnableFake.fetchable = {'eefake:user': {
            'id': 'eefake:user',
            'summary': 'never mind',
        }}

        # follow should refresh profile
        _, code = ExplicitEnableFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'eefake:follow',
            'actor': 'eefake:user',
            'object': 'eefake:bot',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['eefake:user'], ExplicitEnableFake.fetched)

    def test_follow_bot_user_overrides_nobot(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web,
                       copies=[Target(uri='eefake:bot', protocol='eefake')])

        # profile that's opted out
        actor = {
            'id': 'eefake:user',
            'summary': '#nobot',
        }
        user = self.make_user('eefake:user', cls=ExplicitEnableFake, obj_as1=actor)
        self.assertFalse(user.is_enabled(Fake))
        ExplicitEnableFake.fetchable = {'eefake:user': actor}

        # follow should override #nobot
        _, code = ExplicitEnableFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'eefake:follow',
            'actor': 'eefake:user',
            'object': 'eefake:bot',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertIsNone(user.status)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['eefake:user'], ExplicitEnableFake.fetched)

    def test_receive_activity_lease(self):
        Follower.get_or_create(to=self.user, from_=self.alice)

        note = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'fake:post',
            'actor': 'fake:user',
            'object': {
                'id': 'fake:note',
                'objectType': 'note',
                'author': 'fake:user',
            },
        }

        orig_fake_send = Fake.send
        at_send = Condition()
        continue_send = Condition()
        def send(*args, **kwargs):
            with at_send:
                at_send.notify()
            with continue_send:
                continue_send.wait()
            return orig_fake_send(*args, **kwargs)

        def receive():
            with app.test_request_context('/'), \
                 ndb_client.context(
                     cache_policy=common.cache_policy,
                     global_cache=_InProcessGlobalCache(),
                     global_cache_timeout_policy=common.global_cache_timeout_policy):
                try:
                    Fake.receive_as1(note)
                except NoContent:  # raised by the second thread
                    pass

        first = Thread(target=receive)
        second = Thread(target=receive)

        with patch.object(Fake, 'send', side_effect=send):
            first.start()
            second.start()
            with at_send:
                at_send.wait()
            with continue_send:
                continue_send.notify(1)
            first.join()
            second.join()

        # only one receive call should try to send
        self.assertEqual([('fake:post', 'fake:shared:target')], Fake.sent)

    def test_dm_no_yes_sets_enabled_protocols(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        dm = {
            'objectType': 'note',
            'id': 'eefake:dm',
            'actor': 'eefake:user',
            'to': ['fa.brid.gy'],
            'content': 'no',
        }

        user = self.make_user('eefake:user', cls=ExplicitEnableFake)
        self.assertFalse(user.is_enabled(Fake))

        # fake protocol isn't enabled yet, no DM should be a noop
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(dm))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)

        # "yes" DM should add to enabled_protocols
        dm['id'] += '2'
        dm['content'] = '<p><a href="...">@bsky.brid.gy</a> yes</p>'
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(dm))
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual(['eefake:user'], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))

        # another "yes" DM should be a noop
        dm['id'] += '3'
        Fake.created_for = []
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(dm))
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual([], Fake.created_for)

        # "no" DM should remove from enabled_protocols
        Follower.get_or_create(to=user, from_=self.alice)
        dm['id'] += '4'
        dm['content'] = '<p><a href="...">@bsky.brid.gy</a>\n  NO \n</p>'
        self.assertEqual(('OK', 200), ExplicitEnableFake.receive_as1(dm))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)
        self.assertFalse(user.is_enabled(Fake))

        # ...and delete copy actor
        self.assertEqual(
            [('eefake:user#delete-copy-fake-2022-01-02T03:04:05+00:00',
              'fake:shared:target')],
            Fake.sent)

    @patch('protocol.LIMITED_DOMAINS', ['lim.it'])
    @patch('requests.get')
    def test_limited_domain_update_profile_without_follow(self, mock_get):
        actor = {
            **ACTOR,
            'id': 'https://lim.it/alice',
        }
        mock_get.side_effect = [
            self.as2_resp(actor),
        ]

        _, code = got = ActivityPub.receive(Object(our_as1={
            'id': 'https://lim.it/alice#update',
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'https://lim.it/alice',
            'object': actor,
        }), authed_as='https://lim.it/alice')
        self.assertEqual(204, code)

        self.assert_object('https://lim.it/alice',
                           source_protocol='activitypub',
                           our_as1=actor)

    @patch('protocol.LIMITED_DOMAINS', ['lim.it'])
    @patch.object(ATProto, 'send')
    @patch('requests.get')
    def test_inbox_limited_domain_create_without_follow_no_atproto(
            self, mock_get, mock_send):
        actor = 'https://lim.it/alice'
        user = self.make_user(id=actor, cls=ActivityPub, enabled_protocols=['atproto'])

        # follow by bot user shouldn't count
        Follower.get_or_create(to=user, from_=Web(id='https://bsky.brid.gy/'))

        _, code = ActivityPub.receive(Object(as2={
            **NOTE,
            'id': 'https://lim.it/note',
            'actor': actor,
        }), authed_as=actor)
        self.assertEqual(204, code)

        mock_send.assert_not_called()

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
            'actor': 'fake:other',
        }
        obj = self.store_object(id='fake:post#bridgy-fed-create',
                                source_protocol='fake', our_as1=create)

        resp = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'fake:other',
        })
        self.assertEqual(204, resp.status_code)
        obj = Object.get_by_id('fake:post#bridgy-fed-create')
        self.assertEqual('ignored', obj.status)

    def test_receive_task_handler_authed_as(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:alice',
        }
        obj = self.store_object(id='fake:post', our_as1=note,
                                source_protocol='fake')

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'fake:alice',
        })
        self.assertEqual(204, got.status_code)
        self.assertIsNotNone(Object.get_by_id('fake:post#bridgy-fed-create'))

    def test_receive_task_handler_authed_as_domain_vs_homepage(self):
        user = self.make_user('user.com', cls=Web, obj_id='https://user.com/')
        obj = self.store_object(id='https://user.com/c', source_protocol='web',
                                our_as1= {
                                    'id': 'https://user.com/c',
                                    'objectType': 'note',
                                    'author': 'https://user.com/',
                                })

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'user.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertIsNotNone(Object.get_by_id('https://user.com/c#bridgy-fed-create'))

    @patch('requests.get', return_value=requests_response('<html></html>'))
    def test_receive_task_handler_authed_as_www_subdomain(self, _):
        obj = self.store_object(id='http://www.foo.com/post', source_protocol='web',
                                our_as1={
                                    'id': 'http://www.foo.com/post',
                                    'objectType': 'note',
                                    'author': 'http://www.foo.com/bar',
                                })

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'foo.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertIsNotNone(Object.get_by_id(
            'http://www.foo.com/post#bridgy-fed-create'))

    @patch('requests.get', return_value=requests_response('<html></html>'))
    def test_receive_task_handler_authed_as_mixed_subdomains(self, _):
        user = self.make_user('user.com', cls=Web, obj_id='https://user.com/')
        obj = self.store_object(id='http://user.com/post', source_protocol='web',
                                our_as1={
                                    'objectType': 'note',
                                    'author': 'http://m.user.com/',
                                })

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'www.user.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertIsNotNone(Object.get_by_id(
            'http://user.com/post#bridgy-fed-create'))

    @patch('requests.get', return_value=requests_response('<html></html>'))
    def test_receive_task_handler_authed_as_wrong_domain(self, _):
        obj = self.store_object(id='http://bar.com/post', source_protocol='web',
                                our_as1={
                                    'id': 'http://bar.com/post',
                                    'objectType': 'note',
                                    'author': 'http://bar.com/',
                                })

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'foo.com',
        })
        self.assertEqual(299, got.status_code)
        self.assertIsNone(Object.get_by_id('http://bar.com/post#bridgy-fed-create'))

    def test_receive_task_handler_not_authed_as(self):
        obj = self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        })

        got = self.post('/queue/receive', data={
            'obj': obj.key.urlsafe(),
            'authed_as': 'fake:eve',
        })
        self.assertEqual(299, got.status_code)
        self.assertIsNone(Object.get_by_id('fake:post#bridgy-fed-create'))

    def test_like_not_authed_as_actor(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'fake:bob',
        }

        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:like',
                'objectType': 'activity',
                'verb': 'like',
                'actor': 'fake:user',
                'object': 'fake:post',
            }, authed_as='fake:other')

        self.assertIsNone(Object.get_by_id('fake:like'))

    def test_user_opted_out(self):
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

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_from_protocol_unsupported_types(self, mock_create_task):
        self.make_followers()

        event = {
            'id': 'fake:event',
            'objectType': 'event',
            'author': 'fake:user',
        }
        post_event = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'fake:post-event',
            'object': event,
        }
        add = {
            'objectType': 'activity',
            'verb': 'add',
            'id': 'fake:add',
            'actor': 'fake:user',
            'object': 'fake:thing',
        }

        for activity in event, post_event, add:
            with self.subTest(activity=activity):
                with self.assertRaises(NoContent):
                    Fake.receive_as1(activity)
                    self.assertEqual([], Fake.sent)
                    mock_create_task.assert_not_called()

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
        self.assert_task(mock_create_task, 'send', protocol='other',
                         obj=create_key, orig_obj='', url='other:eve:target',
                         user=self.user.key.urlsafe())
        self.assert_task(mock_create_task, 'send', protocol='fake',
                         obj=create_key, orig_obj='', url='fake:shared:target',
                         user=self.user.key.urlsafe())

        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_reply_send_tasks_orig_obj(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')

        reply_as1 = {
            'id': 'fake:reply',
            'objectType': 'note',
            'inReplyTo': 'other:post',
            'author': 'fake:user',
        }
        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'id': 'other:post',
            'author': 'other:eve',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(reply_as1))

        self.assert_object('fake:reply',
                           our_as1=reply_as1,
                           type='note',
                           )

        create_key = Object(id='fake:reply#bridgy-fed-create').key.urlsafe()
        orig_obj_key = Object(id='other:post').key.urlsafe()
        self.assert_task(mock_create_task, 'send', protocol='other',
                         obj=create_key, orig_obj=orig_obj_key,
                         url='other:post:target', user=self.user.key.urlsafe())

        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_send_task_handler(self):
        self.make_followers()

        note = self.store_object(id='fake:note', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
        })
        target = Target(uri='fake:shared:target', protocol='fake')
        create = self.store_object(id='fake:create', undelivered=[target], our_as1={
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': note.as1,
        })
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj': create.key.urlsafe(),
            'orig_obj': note.key.urlsafe(),
            'url': 'fake:shared:target',
            'user': self.user.key.urlsafe(),
        })
        self.assertEqual(200, resp.status_code)

    def test_send_task_missing_url(self):
        obj = self.store_object(id='fake:post')
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj': obj.key.urlsafe(),
            'url': None,
            'user': self.user.key.urlsafe(),
        })
        self.assertEqual(204, resp.status_code)

    @patch.object(Fake, 'send', return_value=False)
    def test_send_returns_false_task_returns_204(self, mock_send):
        target = Target(protocol='fake', uri='fake:target')
        obj = self.store_object(id='fake:post', undelivered=[target], our_as1={
            'objectType': 'note',
        })
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj': obj.key.urlsafe(),
            'url': 'fake:target',
        })
        self.assertEqual(204, resp.status_code)

        obj = obj.key.get()
        self.assertEqual([], obj.undelivered)
        self.assertEqual([], obj.delivered)
        self.assertEqual([], obj.failed)

    def test_send_unsupported_types(self):
        target = Target(protocol='fake', uri='fake:target')

        event = {
            'id': 'fake:event',
            'objectType': 'event',
            'author': 'fake:user',
        }
        post_event = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'fake:post-event',
            'object': event,
        }
        add = {
            'objectType': 'activity',
            'verb': 'add',
            'id': 'fake:add',
            'actor': 'fake:user',
            'object': 'fake:thing',
        }

        for activity in event, post_event, add:
            with self.subTest(activity=activity):
                obj = self.store_object(id=activity['id'], undelivered=[target],
                                        our_as1=activity)
                resp = self.post('/queue/send', data={
                    'protocol': 'fake',
                    'obj': obj.key.urlsafe(),
                    'url': 'fake:target',
                })
                self.assertEqual(204, resp.status_code)
                self.assertEqual([], Fake.sent)
