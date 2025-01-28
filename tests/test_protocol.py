"""Unit tests for protocol.py."""
import copy
from datetime import timedelta
import logging
from threading import Condition, Thread
from unittest import skip
from unittest.mock import ANY, patch

from arroba.tests.testutil import dns_answer
from google.cloud import ndb
from google.cloud.ndb.global_cache import _InProcessGlobalCache
from granary import as2
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY
from oauth_dropins.webutil import appengine_info, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil.util import json_dumps
import requests
from werkzeug.exceptions import BadRequest

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub
from app import app
from atproto import ATProto
import common
import memcache
import models
from models import DM, Follower, Object, PROTOCOLS, Target, User
import protocol
from protocol import ErrorButDoNotRetryTask, Protocol
from ui import UIProtocol
from web import Web

from .test_activitypub import ACTOR, NOTE
from .test_atproto import DID_DOC
from .test_dms import DmsTest
from .test_web import (
    ACTOR_HTML_RESP,
    ACTOR_AS1_UNWRAPPED_URLS,
    ACTOR_MF2_REL_URLS,
    NOTE as NOTE_HTML_RESP,
    web_user_gets,
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
    def test_for_id_web_fetch_not_html(self, mock_get):
        mock_get.return_value = requests_response('not html', content_type='text/abc')
        self.assertIsNone(Protocol.for_id('http://web.site/xyz'))
        self.assertIsNone(Object.get_by_id('http://web.site/xyz'))
        self.assertIn(self.req('http://web.site/xyz'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_web_fetch_no_mf2(self, mock_get):
        mock_get.return_value = requests_response('<html></html>')
        self.assertEqual(Web, Protocol.for_id('http://web.site/xyz'))

        obj = self.assert_object('http://web.site/xyz', source_protocol='web')
        self.assertIsNone(obj.mf2)
        self.assertIsNone(obj.as1)

        self.assertIn(self.req('http://web.site/xyz'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_web_remote_false(self, mock_get):
        self.assertIsNone(Protocol.for_id('http://web.site/', remote=False))
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_for_id_synthetic(self, mock_get):
        self.assertEqual(ATProto, Protocol.for_id('at://did/coll/rkey#bridgy-fed-xyz'))
        self.assertEqual(Fake, Protocol.for_id('fake:post#bridgy-fed-delete-abc'))

        Object(id='http://in.st/post', source_protocol='activitypub').put()
        self.assertEqual(ActivityPub,
                         Protocol.for_id('http://in.st/post#bridgy-fed-a'))

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
        Object(id='foo', our_as1={}).put()

        loaded = Fake.load('foo', remote=True)
        self.assertEqual({'id': 'foo', 'x': 'y'}, loaded.as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
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
            'type': ['h-card'],
            'properties': {
                'url': ['https://f.ooo'],
                'name': ['Ms. ☕ Baz'],
            },
            'rel-urls': {
                'https://f.ooo': {'rels': ['me'], 'text': 'Ms. ☕ Baz'},
                'https://user.com/webmention': {'rels': ['webmention'], 'text': ''},
            },
            'url': 'https://f.ooo',
        }

        loaded = Web.load('https://f.ooo', remote=True)
        self.assertEqual(expected_mf2, loaded.mf2)
        self.assertIsNone(loaded.our_as1)
        self.assertEqual({
            'objectType': 'person',
            'id': 'https://f.ooo',
            'url': 'https://f.ooo',
            'displayName': 'Ms. ☕ Baz',
            'urls': [{'value': 'https://f.ooo', 'displayName': 'Ms. ☕ Baz'}],
        }
, loaded.as1)
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
            obj = Object(id='foo', our_as1={'orig': 'y'})
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

    def test_bridged_web_url_for(self):
        self.assertIsNone(Protocol.bridged_web_url_for(self.user))
        self.assertEqual('https://foo.com/',
                         Protocol.bridged_web_url_for(self.user, fallback=True))

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

        self.store_object(id='fake:orig', our_as1={'id': 'fake:orig'},
                          copies=[Target(protocol='other', uri='other:orig')])

        share = {
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:share',
            'actor': 'fake:user',
            'object': 'fake:orig',
        }
        Fake.fetchable['fake:share'] = share

        obj = Object(id='fake:undo', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': share,
        })
        self.assertEqual({
            Target(protocol='other', uri='other:orig:target'),
        }, Fake.targets(obj, from_user=self.user).keys())

    def test_targets_composite_inreplyto(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
        }

        reply = Object(our_as1={
            'id': 'other:reply',
            'objectType': 'note',
            'inReplyTo': {
                'id': 'fake:post',
                'url': 'http://foo',
            },
        })
        create = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': reply.as1,
        })

        self.assertEqual(
            {Target(protocol='fake', uri='fake:post:target')},
            OtherFake.targets(create, crud_obj=reply, from_user=self.user).keys())

    def test_targets_link_tag_has_no_orig_obj(self):
        # https://github.com/snarfed/bridgy-fed/issues/1237
        Fake.fetchable['fake:linked-post'] = {
            'objectType': 'note',
        }

        note = Object(our_as1={
            'objectType': 'note',
            'id': 'fake:post',
            'tags': [{'url': 'fake:linked-post'}],
        })
        create = Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': note.as1,
        })
        self.assertEqual(
            {Target(protocol='fake', uri='fake:linked-post:target'): None},
            OtherFake.targets(create, crud_obj=note, from_user=self.user))

    @patch.object(Fake, 'fetch')
    def test_targets_continues_on_fetch_error(self, mock_fetch):
        def fetch(obj, **_):
            if obj.key.id() == 'fake:post-1':
                raise requests.ConnectionError('foo')
            elif obj.key.id() == 'fake:post-2':
                obj.our_as1 = {
                    'objectType': 'note',
                    'id': 'fake:post-2',
                    'author': 'fake:user',
                }
                return True

        mock_fetch.side_effect = fetch

        reply = Object(source_protocol='other', our_as1={
            'id': 'other:reply',
            'objectType': 'note',
            'author': 'other:user',
            'inReplyTo': [
                'fake:post-1',
                'fake:post-2',
            ],
        })
        create = Object(source_protocol='other', our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': reply.as1,
        })

        self.assertEqual(
            {Target(protocol='fake', uri='fake:post-2:target')},
            OtherFake.targets(create, crud_obj=reply, from_user=self.user).keys())

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
                    'url': 'uri:other:u:fake:bob',
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
                {'objectType': 'mention', 'url': 'uri:other:u:fake:alice'},
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

    def test_translate_ids_inner_object_object_id(self):
        # https://github.com/snarfed/bridgy-fed/issues/1492
        self.assert_equals({
            'object': {
                'verb': 'flag',
                'object': 'other:o:fa:fake:post',
            },
        }, OtherFake.translate_ids({
            'object': {
                'verb': 'flag',
                'object': 'fake:post',
            },
        }))

    def test_translate_ids_inner_object_actor_id(self):
        # https://github.com/snarfed/bridgy-fed/issues/1492
        self.assert_equals({
            'object': {
                'verb': 'follow',
                'object': 'other:u:fake:bob',
            },
        }, OtherFake.translate_ids({
            'object': {
                'verb': 'follow',
                'object': 'fake:bob',
            },
        }))

    def test_translate_ids_to_cc(self):
        self.assert_equals({
            'id': 'xyz',
            'to': ['other:u:fake:alice', 'other:bob'],
            'cc': ['other:u:efake:eve', as2.PUBLIC_AUDIENCE],
        }, OtherFake.translate_ids({
            'id': 'xyz',
            'to': ['fake:alice', 'other:bob'],
            'cc': ['efake:eve', as2.PUBLIC_AUDIENCE],
        }))

    def test_translate_ids_empty(self):
        self.assertEqual({}, Fake.translate_ids({}))

    def test_translate_ids_single_inReplyTo(self):
        obj = {'inReplyTo': 'foo'}
        self.assertEqual(obj, Fake.translate_ids(obj))

    def test_translate_ids_multiple_inReplyTo(self):
        obj = {'inReplyTo': ['foo', 'bar']}
        self.assertEqual(obj, Fake.translate_ids(obj))

    def test_convert_object_is_from_user_adds_source_links(self):
        alice = Fake(id='fake:alice')
        self.assertEqual({
            'objectType': 'person',
            'id': 'other:u:fake:alice',
            'url': 'http://unused',
            'summary': 'something about me<br><br>[<a href="https://fed.brid.gy/fa/fake:handle:alice">bridged</a> from <a href="web:fake:alice">fake:handle:alice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
        }, OtherFake.convert(Object(
            id='fake:profile:alice', source_protocol='fake', our_as1={
                'objectType': 'person',
                'id': 'fake:alice',
                'url': 'http://unused',
                'summary': 'something about me',
            }), from_user=alice))

    def test_convert_object_isnt_from_user_adds_source_links(self):
        bob = Fake(id='fake:bob')
        self.assertEqual({
            'objectType': 'person',
            'id': 'other:u:fake:alice',
            'url': 'http://al/ice',
            'summary': '[bridged from <a href="http://al/ice">al/ice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
        }, OtherFake.convert(Object(id='fake:alice', source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:alice',
            'url': 'http://al/ice',
        }), from_user=bob))

    def test_convert_actor_without_from_user_doesnt_add_source_links(self):
        self.assertEqual({
            'objectType': 'person',
            'id': 'other:u:fake:alice',
            'url': 'http://al/ice',
        }, OtherFake.convert(Object(id='fake:alice', source_protocol='fake', our_as1={
            'objectType': 'person',
            'id': 'fake:alice',
            'url': 'http://al/ice',
        })))

    def test_convert_doesnt_duplicate_source_links(self):
        alice = Fake(id='fake:alice')
        summary = 'something about me<br><br>[bridged from <a href="http://al/ice">someone else</a> by <a href="https://fed.brid.gy/">Bridgy Fed</a>]'
        self.assertEqual({
            'objectType': 'person',
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
                    'objectType': 'person',
                    'id': 'other:u:fake:profile:alice',
                    'summary': 'something about me<br><br>[<a href="https://fed.brid.gy/fa/fake:handle:alice">bridged</a> from <a href="web:fake:alice">fake:handle:alice</a> on fake-phrase by <a href="https://fed.brid.gy/">Bridgy Fed</a>]',
                },
            }, OtherFake.convert(
                Object(id='fake:profile:update', source_protocol='fake', our_as1={
                    'objectType': 'activity',
                    'verb': verb,
                    'object': {
                        'id': 'fake:profile:alice',
                        'objectType': 'person',
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

        # Fake doesn't support DMs, ExplicitFake does
        for author, recip in (
                ('ap.brid.gy', 'did:bob'),
                ('did:bob', 'ap.brid.gy'),
        ):
            bot_dm = Object(our_as1={
                'objectType': 'note',
                'author': author,
                'to': [recip],
                'content': 'hello world',
            })
            ExplicitFake.check_supported(bot_dm)
            with self.assertRaises(NoContent):
                Fake.check_supported(bot_dm)

        # not from or to a protocol bot user
        dm = Object(our_as1={
            'objectType': 'note',
            'author': 'did:alice',
            'to': ['did:bob'],
            'content': 'hello world',
        })
        for proto in Fake, ExplicitFake:
            with self.subTest(proto=proto), self.assertRaises(NoContent):
                proto.check_supported(dm)

        # from and to a copy id of a protocol bot user
        self.make_user(cls=Web, id='ap.brid.gy',
                       copies=[Target(protocol='fake', uri='fake:ap-bot')])
        common.protocol_user_copy_ids.cache_clear()
        dm.our_as1['author'] = 'fake:ap-bot'
        proto.check_supported(dm)

        dm.our_as1.update({
            'author': 'did:alice',
            'to': ['fake:ap-bot'],
        })
        proto.check_supported(dm)

    def test_bot_follow(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='fake:user', cls=Fake, obj_id='fake:user')
        Fake.bot_follow(user)

        self.assertEqual([('fake:user:target', {
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'https://fa.brid.gy/#follow-back-fake:user-2022-01-02T03:04:05+00:00',
            'actor': 'fa.brid.gy',
            'object': 'fake:user',
        })], Fake.sent)

    def test_bot_follow_user_missing_obj(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = Fake(id='fake:user')
        assert not user.obj
        Fake.bot_follow(user)
        self.assertEqual([], Fake.sent)


class ProtocolReceiveTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:user', cls=Fake, obj_id='fake:user')
        self.alice = self.make_user('other:alice', cls=OtherFake, obj_id='other:alice')
        self.bob = self.make_user('other:bob', cls=OtherFake, obj_id='other:bob')

    def assert_object(self, id, **props):
        props.setdefault('source_protocol', 'fake')
        return super().assert_object(id, **props)

    def make_followers(self):
        Follower.get_or_create(to=self.user, from_=self.alice)
        Follower.get_or_create(to=self.user, from_=self.bob)
        Follower.get_or_create(to=self.user, from_=OtherFake(id='other:eve'),
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
                           copies=[Target(protocol='other',
                                          uri='other:o:fa:fake:post')],
                           feed=[self.alice.key, self.bob.key],
                           users=[self.user.key],
                           )
        self.assertIsNone(Object.get_by_id('fake:create'))
        self.assertEqual([
            ('other:alice:target', create_as1),
            ('other:bob:target', create_as1),
        ], OtherFake.sent)

    def test_create_post_object_missing_id(self):
        self.make_followers()

        # got an activity like this from Pandacap
        # https://github.com/IsaacSchemm/Pandacap
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': [{
                'Item1': 'id',
                'Item2': 'https://pandacap.azurewebsites.net/#transient-abc-123',
            }],
        }
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1(create_as1)

        self.assertEqual([], OtherFake.sent)

    def test_create_post_bare_object(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(post_as1))

        self.assert_object(
            'fake:post',
            our_as1=post_as1,
            type='note',
            copies=[Target(protocol='other', uri='other:o:fa:fake:post')],
            feed=[self.alice.key, self.bob.key],
            users=[Fake(id='fake:user').key],
        )

        self.assertIsNone(Object.get_by_id('fake:post#bridgy-fed-create'))
        self.assertEqual('other:alice:target', OtherFake.sent[0][0])
        self.assertEqual('other:bob:target', OtherFake.sent[1][0])
        self.assertEqual('fake:post#bridgy-fed-create', OtherFake.sent[0][1]['id'])
        self.assertEqual('fake:post#bridgy-fed-create', OtherFake.sent[1][1]['id'])

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

    def test_post_not_public_ignored(self):
        self.assertEqual(('OK', 200), Fake.receive_as1({
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
            'to': ['fake:user/followers'],
        }))
        self.assertIsNone(Object.get_by_id('fake:post'))

    def test_post_unlisted_ignored(self):
        self.assertEqual(('OK', 200), Fake.receive_as1({
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
            'to': ['@unlisted'],
        }))
        self.assertIsNone(Object.get_by_id('fake:post'))

    @patch.object(ATProto, 'send')
    def test_reply_to_not_bridged_account_skips_atproto(self, mock_send):
        user = self.make_user('efake:user', cls=ExplicitFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('efake:eve', cls=ExplicitFake)
        self.store_object(id='efake:post', our_as1={
            'id': 'efake:post',
            'objectType': 'note',
            'author': 'efake:eve',
        })

        ExplicitFake.receive_as1({
            'id': 'efake:reply',
            'objectType': 'note',
            'author': 'efake:user',
            'inReplyTo': 'efake:post',
        })

        self.assertEqual(0, mock_send.call_count)

    @patch.object(ATProto, 'send')
    def test_reply_to_non_bridged_post_with_mention_skips_atproto(self, mock_send):
        self.user.enabled_protocols = ['atproto']
        self.user.put()

        self.store_object(id='fake:post', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'other:alice',
        })

        Fake.receive_as1({
            'id': 'fake:reply',
            'objectType': 'note',
            'actor': 'fake:user',
            'inReplyTo': 'fake:post',
            'tags': [{
                'objectType': 'mention',
                'url': 'other:bob'
            }],
        })

        self.assertEqual(0, mock_send.call_count)

    def test_reply_to_non_bridged_post_skips_enabled_protocol_with_followers(self):
        self.make_user(id='fa.brid.gy', cls=Web)

        # should skip even if it's enabled and we have followers there
        self.user.enabled_protocols = ['efake']
        self.user.put()

        eve = self.make_user('efake:eve', cls=ExplicitFake)
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
        self.assertEqual(204, code)
        self.assertEqual([], ExplicitFake.sent)
        self.assertEqual([], Fake.sent)

    def test_reply_from_non_bridged_post_isnt_bridged_but_gets_dm_prompt(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        self.user.enabled_protocols = ['efake']
        self.user.put()

        eve = self.make_user('efake:eve', cls=ExplicitFake, obj_as1={
            'id': 'efake:eve',
        })

        self.store_object(id='fake:post', source_protocol='fake', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        })

        _, code = ExplicitFake.receive_as1({
            'id': 'efake:reply',
            'objectType': 'note',
            'actor': 'efake:eve',
            'inReplyTo': 'fake:post',
        })
        self.assertEqual(204, code)

        self.assertEqual([], Fake.sent)
        DmsTest().assert_sent(Fake, eve, 'replied_to_bridged_user', """Hi! You <a href="efake:reply">recently replied</a> to <a class="h-card u-author" href="fake:user">fake:user</a>, who's bridged here from fake-phrase. If you want them to see your replies, you can bridge your account into fake-phrase by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.""")

        eve = eve.key.get()
        self.assertEqual([DM(protocol='fake', type='replied_to_bridged_user')],
                         eve.sent_dms)

    @patch.object(ATProto, 'send', return_value=True)
    def test_repost_of_non_bridged_account_skips_atproto(self, mock_send):
        user = self.make_user('efake:user', cls=ExplicitFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('efake:eve', cls=ExplicitFake)
        self.store_object(id='efake:post', our_as1={
            'id': 'efake:post',
            'objectType': 'note',
            'author': 'efake:eve',
        })

        _, code = ExplicitFake.receive_as1({
            'id': 'efake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'efake:user',
            'object': 'efake:post',
        })
        self.assertEqual(204, code)
        self.assertEqual(0, mock_send.call_count)

    @patch.object(ATProto, 'send', return_value=True)
    def test_repost_of_not_bridged_post_skips_atproto(self, mock_send):
        user = self.make_user('efake:user', cls=ExplicitFake,
                              enabled_protocols=['atproto'])

        self.eve = self.make_user('efake:eve', cls=ExplicitFake,
                              enabled_protocols=['atproto'])
        self.store_object(id='efake:post', our_as1={
            'id': 'efake:post',
            'objectType': 'note',
            'author': 'efake:eve',
        })

        _, code = ExplicitFake.receive_as1({
            'id': 'efake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'efake:user',
            'object': 'efake:post',
        })
        self.assertEqual(204, code)
        self.assertEqual(0, mock_send.call_count)

    def test_repost_of_not_bridged_post_skips_enabled_protocol_with_followers(self):
        # should skip even if it's enabled and we have followers there
        self.user.enabled_protocols = ['efake']
        self.user.put()

        eve = self.make_user('efake:eve', cls=ExplicitFake)
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
        self.assertEqual(204, code)
        self.assertEqual([], ExplicitFake.sent)
        self.assertEqual([], Fake.sent)

    def test_undo_repost(self):
        self.make_followers()

        self.store_object(id='other:orig', source_protocol='other', our_as1={
            'objectType': 'note',
            'id': 'other:orig',
            'actor': 'other:user',
        })
        self.store_object(id='fake:share', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:share',
            'actor': 'fake:user',
            'object': 'other:orig',
        })

        undo_as1 = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:user',
            'object': 'fake:share',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(undo_as1))
        self.assertTrue(Object.get_by_id('fake:share').deleted)
        self.assertEqual([
            ('other:alice:target', undo_as1),
            ('other:bob:target', undo_as1),
            ('other:orig:target', undo_as1),
        ], OtherFake.sent)

    @patch.object(ATProto, 'send', return_value=True)
    def test_follow_of_bridged_account_by_not_bridged_account_skips_atproto(
            self, mock_send):
        user = self.make_user('efake:user', cls=ExplicitFake)
        self.store_object(id='did:plc:eve', raw=DID_DOC)
        eve = self.make_user('did:plc:eve', cls=ATProto, enabled_protocols=['efake'],
                             copies=[Target(uri='efake:eve', protocol='efake')],
                             obj_bsky=ACTOR_PROFILE_BSKY)

        _, code = ExplicitFake.receive_as1({
            'id': 'efake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'efake:user',
            'object': 'efake:eve',
        })
        self.assertEqual(204, code)

        self.assert_entities_equal(Follower(from_=user.key, to=eve.key,
                                            follow=Object(id='efake:follow').key),
                                   Follower.query().fetch(),
                                   ignore=['created', 'updated'])
        self.assertEqual(0, mock_send.call_count)

    def test_targets_block(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'other:block',
            'actor': 'other:alice',
            'object': 'other:bob',
        }
        self.assertEqual(
            [Target(uri='other:bob:target', protocol='other')],
            list(Fake.targets(Object(our_as1=block), from_user=self.user).keys()))

    def test_targets_undo_composite_block(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        obj = Object(id='other:undo', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'other:undo',
            'actor': 'fake:user',
            'object': {
                'objectType': 'activity',
                'verb': 'block',
                'id': 'other:block',
                'actor': 'fake:user',
                'object': 'other:bob',
            },
        })
        self.assertEqual(
            [Target(uri='other:bob:target', protocol='other')],
            list(Fake.targets(obj, from_user=self.user).keys()))

    def test_targets_undo_block_id(self):
        self.bob.obj.our_as1 = {'foo': 'bar'}
        self.bob.obj.put()

        self.store_object(id='fake:block', our_as1={
            'objectType': 'activity',
            'verb': 'block',
            'id': 'fake:block',
            'actor': 'fake:user',
            'object': 'other:bob',
        })

        obj = Object(id='fake:undo', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:user',
            'object': 'fake:block',
        })
        self.assertEqual(
            [Target(uri='other:bob:target', protocol='other')],
            list(Fake.targets(obj, from_user=self.user).keys()))

    def test_targets_undo_share_composite(self):
        self.make_followers()

        OtherFake.fetchable['other:orig'] = {
            'objectType': 'note',
            'id': 'other:orig',
        }

        share = {
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:share',
            'actor': 'fake:user',
            'object': 'other:orig',
        }
        Fake.fetchable['fake:share'] = share

        obj = Object(id='fake:undo', our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'actor': 'fake:user',
            'object': share,
        })
        self.assertEqual({
            Target(protocol='other', uri='other:alice:target'),
            Target(protocol='other', uri='other:bob:target'),
            Target(protocol='other', uri='other:orig:target'),
        }, Fake.targets(obj, from_user=self.user).keys())

    def test_targets_repost_of_quote_with_article_tag_uses_quote_post_as_orig_obj(self):
        """https://github.com/snarfed/bridgy-fed/issues/1357"""
        self.make_followers()

        self.user.enabled_protocols=['web']
        self.user.put()

        eve = self.make_user('eve.com', cls=Web)
        web_link = self.store_object(id='http://eve.com/link', source_protocol='web',
                                     our_as1={'foo': 'bar'})

        quote_as1 = {
            'objectType': 'note',
            'id': 'fake:quote',
            'author': 'fake:user',
            'content': 'foo bar baz',
            'tags': [{
                'objectType': 'article',
                'url': 'http://eve.com/link',
                'displayName': 'bar',
                'startIndex': 4,
                'length': 3
            }],
            'attachments': [{
                'objectType': 'note',
                'id': 'fake:orig',
                'url': 'url:fake:orig',
            }]
        }
        quote_obj = self.store_object(
            id='fake:quote',
            source_protocol='fake',
            our_as1=quote_as1,
            copies=[Target(protocol='other', uri='other:quote')])

        repost_as1 = {
            'objectType': 'activity',
            'verb': 'share',
            'id': 'fake:repost',
            'actor': 'fake:user',
            'object': quote_as1,
        }
        targets = Fake.targets(Object(id='fake:repost', our_as1=repost_as1),
                               from_user=self.user)
        self.assertEqual({
            'other:quote:target': quote_obj.key.id(),
            'other:alice:target': quote_obj.key.id(),
            'other:bob:target': quote_obj.key.id(),
            'http://eve.com/link': None,
        }, {target.uri: obj.key.id() if obj else None for target, obj in targets.items()})

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

        note = Object(our_as1={
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        })
        create = Object(id='fake:post', our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': note.as1,
        })
        self.assertEqual({
            Target(uri='https://atproto.brid.gy', protocol='atproto'): None,
        }, Fake.targets(create, crud_obj=note, from_user=self.user))

    def test_create_post_dont_deliver_to_follower_if_protocol_isnt_enabled(self):
        # user who hasn't enabled either Fake or OtherFake, so we shouldn't
        # deliver to followers on those protocols
        user = self.make_user('efake:user', cls=ExplicitFake,
                              obj_id='efake:user')
        frank = self.make_user('other:frank', cls=OtherFake, obj_id='other:frank')
        Follower.get_or_create(to=user, from_=self.alice)
        Follower.get_or_create(to=user, from_=frank)

        _, code = ExplicitFake.receive_as1({
            'objectType': 'note',
            'id': 'efake:post',
            'author': 'efake:user',
            'content': 'foo'
        })
        self.assertEqual(204, code)

        self.assertEqual([], Fake.sent)
        self.assertEqual([], OtherFake.sent)
        obj = Object.get_by_id('efake:post#bridgy-fed-create')

    def test_create_post_use_instead(self):
        self.make_user('fake:not-this', cls=Fake, use_instead=self.user.key, obj_mf2={
            'type': ['h-card'],
            'properties': {
                # this is the key part to test; Object.as1 uses this as id
                'url': ['fake:user'],
            },
        })
        self.make_followers()

        note_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        obj = self.store_object(id='fake:post', our_as1=note_as1,
                                source_protocol='fake')

        self.assertEqual(('OK', 202), Fake.receive_as1(note_as1))
        self.assertEqual(2, len(OtherFake.sent))

        post_as1 = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'fake:post#bridgy-fed-create',
            'actor': 'fake:user',
            'object': note_as1,
            'published': '2022-01-02T03:04:05+00:00',
        }
        self.assertEqual([
            ('other:alice:target', post_as1),
            ('other:bob:target', post_as1),
        ], OtherFake.sent)

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
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake',
                             copies=[Target(uri='other:post', protocol='other')])

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
                           users=[self.user.key],
                           copies=[Target(uri='other:post', protocol='other')],
                           )
        self.assertIsNone(Object.get_by_id('fake:update'))

        self.assertEqual([
            ('other:alice:target', update_as1),
            ('other:bob:target', update_as1),
        ], OtherFake.sent)

    def test_update_post_bare_object(self):
        self.make_followers()

        post_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
            'content': 'first',
        }
        copy = Target(uri='other:post', protocol='other')
        self.store_object(id='fake:post', our_as1=post_as1,
                          source_protocol='fake',
                          copies=[copy])

        post_as1['content'] = 'second'
        _, code = Fake.receive_as1(post_as1, new=False, changed=True)
        self.assertEqual(202, code)

        self.assert_object('fake:post',
                           our_as1={
                               **post_as1,
                               'updated': '2022-01-02T03:04:05+00:00',
                           },
                           type='note',
                           feed=[self.bob.key, self.alice.key],
                           users=[self.user.key],
                           copies=[copy],
                           )

        self.assertIsNone(Object.get_by_id(
            'fake:post#bridgy-fed-update-2022-01-02T03:04:05+00:00'))
        self.assertEqual([], Fake.sent)

    def test_update_post_fetch_object(self):
        post = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        Fake.fetchable['fake:post'] = post

        self.store_object(id='fake:post', source_protocol='fake')

        update = {
            'id': 'fake:update',
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        _, status = Fake.receive_as1(update)
        self.assertEqual(204, status)

        self.assertEqual(['fake:profile:user', 'fake:post'], Fake.fetched)
        self.assert_object('fake:post',
                           our_as1=post,
                           type='note',
                           )
        self.assertIsNone(Object.get_by_id('fake:update'))

    def test_update_post_fetch_object_fails(self):
        self.store_object(id='fake:post', source_protocol='fake')

        update = {
            'id': 'fake:update',
            'objectType': 'activity',
            'verb': 'update',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1(update)

        self.assertEqual(['fake:profile:user', 'fake:post'], Fake.fetched)
        self.assertIsNone(Object.get_by_id('fake:update'))

    def test_create_reply(self):
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        frank = self.make_user('other:frank', cls=OtherFake, obj_id='other:frank')
        Follower.get_or_create(to=self.user, from_=frank)

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
        create_as1 = {
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': reply_as1,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object(
            'fake:reply',
            our_as1=reply_as1,
            type='note',
            users=[self.user.key],
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
            notify=[eve.key],
        )
        self.assertIsNone(Object.get_by_id('fake:create'))
        # not a self reply, shouldn't deliver to follower frank
        self.assertEqual([('other:post:target', create_as1)], OtherFake.sent)

    def test_create_reply_bare_object(self):
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

        self.assert_object(
            'fake:reply',
            our_as1=reply_as1,
            type='note',
            users=[self.user.key],
            notify=[eve.key],
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
        )

        create_as1 = {
            'id': 'fake:reply#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': reply_as1,
            'published': '2022-01-02T03:04:05+00:00',
        }
        self.assertIsNone(Object.get_by_id('fake:reply#bridgy-fed-create'))
        self.assertEqual([('other:post:target', create_as1)], OtherFake.sent)

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
            users=[self.user.key],
            copies=[Target(protocol='other', uri='other:o:fa:fake:reply')],
        )

        self.assertIsNone(Object.get_by_id('fake:reply#bridgy-fed-create'))
        self.assertEqual([], Fake.sent)

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
                                   users=[self.user.key], copies=[copy])
        self.assertEqual([('other:post:target', {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'fake:reply#bridgy-fed-create',
            'published': '2022-01-02T03:04:05+00:00',
            'actor': 'fake:user',
            'object': reply_as1,
        })], OtherFake.sent)

    def test_create_reply_with_copy_on_not_enabled_protocol(self):
        self.store_object(id='fake:post', source_protocol='fake',
                          copies=[Target(protocol='efake', uri='efake:post')],
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
        self.assertEqual(204, code)
        self.assertEqual([], ExplicitFake.sent)
        self.assertEqual([], Fake.sent)

    def test_create_self_reply_to_same_protocol_bridge_if_original_is_bridged(self):
        # use efake because Protocol.targets automatically adds fake and other
        # to to_protocols.
        # TODO: refactor tests to not do fake-to-fake delivery, then remove
        # these special cases
        user = self.make_user('efake:user', cls=ExplicitFake,
                              obj_id='efake:user', enabled_protocols=['other'])

        # eve follows user
        eve = self.make_user('other:eve', cls=OtherFake, obj_id='other:eve')
        Follower.get_or_create(to=user, from_=eve)

        # user replies to themselves
        self.store_object(id='efake:post', source_protocol='efake',
                          copies=[Target(protocol='other', uri='other:post')],
                          our_as1={
                              'objectType': 'note',
                              'id': 'efake:post',
                              'author': 'efake:user',
                          })

        reply_as1 = {
            'id': 'efake:reply',
            'objectType': 'note',
            'inReplyTo': 'efake:post',
            'author': 'efake:user',
        }
        self.assertEqual(('OK', 202), ExplicitFake.receive_as1(reply_as1))

        copy = Target(protocol='other', uri='other:o:efake:efake:reply')
        reply = self.assert_object('efake:reply',
                                   type='note',
                                   source_protocol='efake',
                                   our_as1=reply_as1,
                                   users=[user.key],
                                   copies=[copy],
                                   feed=[eve.key])
        expected_create = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'efake:reply#bridgy-fed-create',
            'published': '2022-01-02T03:04:05+00:00',
            'actor': 'efake:user',
            'object': reply_as1,
        }

        self.assertEqual([('other:eve:target', expected_create),
                          ('other:post:target', expected_create),
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
                           users=[self.user.key],
                           notify=[eve.key],
                           )
        self.assertIsNone(Object.get_by_id('fake:update'))
        self.assertEqual([('other:post:target', update_as1)], OtherFake.sent)

    def test_repost(self):
        self.make_followers()

        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'author': 'other:bob',
        }
        repost_as1 = {
            'id': 'fake:repost',
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:user',
            'object': 'other:post',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(repost_as1))

        obj = self.assert_object('fake:repost',
                                 our_as1=repost_as1,
                                 copies=[Target(protocol='other',
                                                uri='other:o:fa:fake:repost')],
                                 type='share',
                                 users=[self.user.key],
                                 notify=[self.bob.key],
                                 feed=[self.alice.key, self.bob.key],
                                 )
        self.assertEqual([
            ('other:alice:target', obj.as1),
            ('other:bob:target', obj.as1),
            ('other:post:target', obj.as1),
        ], OtherFake.sent)

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
                                 our_as1=repost_as1,
                                 type='share',
                                 users=[self.user.key],
                                 )
        self.assertEqual([], Fake.sent)

    def test_repost_no_object_error(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:share',
                'objectType': 'activity',
                'verb': 'share',
                'actor': 'fake:user',
                'object': None,
        })

    def test_like(self):
        OtherFake.fetchable['other:post'] = {
            'objectType': 'note',
            'author': 'other:bob',
        }

        like_as1 = {
            'id': 'fake:like',
            'objectType': 'activity',
            'verb': 'like',
            'actor': 'fake:user',
            'object': 'other:post',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(like_as1))

        like_obj = self.assert_object('fake:like',
                                      our_as1=like_as1,
                                      copies=[Target(protocol='other',
                                                     uri='other:o:fa:fake:like')],
                                      users=[self.user.key],
                                      notify=[self.bob.key],
                                      type='like',
                                      )

        self.assertEqual([('other:post:target', like_obj.as1)], OtherFake.sent)

    def test_like_no_object_error(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'fake:like',
                'objectType': 'activity',
                'verb': 'like',
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
        self.store_object(id='fake:post', our_as1=post_as1, source_protocol='fake',
                          copies=[Target(protocol='other', uri='other:post')])

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
                           copies=[Target(protocol='other', uri='other:post')],
                           )

        self.assertIsNone(Object.get_by_id('fake:delete'))
        self.assertEqual('other:alice:target', OtherFake.sent[0][0])
        self.assertEqual('other:bob:target', OtherFake.sent[1][0])
        self.assertEqual('fake:delete', OtherFake.sent[0][1]['id'])
        self.assertEqual('fake:delete', OtherFake.sent[1][1]['id'])

    def test_delete_doesnt_fetch_author(self):
        self.user.obj_key.delete()

        delete_as1 = {
            'id': 'fake:delete',
            'objectType': 'activity',
            'verb': 'delete',
            'actor': 'fake:user',
            'object': 'fake:post',
        }
        _, status = Fake.receive_as1(delete_as1, authed_as='fake:user')
        self.assertEqual(204, status)

        self.assertIsNone(Object.get_by_id('fake:delete'))
        self.assertEqual([], Fake.fetched)

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

        self.assertIsNone(Object.get_by_id('fake:post'))
        self.assertIsNone(Object.get_by_id('fake:delete'))
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
        self.alice.obj.copies = [Target(protocol='fake', uri='fa:profile:other:alice')]
        self.alice.obj.put()

        follower = Follower.get_or_create(to=self.user, from_=self.alice)
        followee = Follower.get_or_create(to=self.alice, from_=self.user)
        other = Follower.get_or_create(to=self.user, from_=self.bob)
        self.assertEqual(3, Follower.query().count())

        _, code = OtherFake.receive_as1({
            'objectType': 'activity',
            'verb': 'delete',
            'id': 'other:delete',
            'actor': 'other:alice',
            'object': 'other:alice',
        })
        self.assertEqual(202, code)

        self.assertEqual(3, Follower.query().count())
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)
        self.assert_object('other:alice', deleted=True, source_protocol='other',
                           ignore=['copies'])

    @patch.object(Fake, 'send')
    def test_send_error(self, mock_send):
        """Two targets. First send fails, second succeeds."""
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

        sent = []
        def send(obj, url, from_user=None, orig_obj_id=None):
            self.assertEqual(create_as1, obj.as1)
            if not sent:
                self.assertEqual('other:alice:target', url)
                sent.append('fail')
                raise BadRequest()
            else:
                self.assertEqual('other:bob:target', url)
                sent.append('sent')
                return True

        mock_send.side_effect = send

        self.assertEqual(('OK', 202), Fake.receive_as1(create_as1))

        self.assert_object('fake:post',
                           our_as1=post_as1,
                           type='note',
                           feed=[self.alice.key, self.bob.key],
                           users=[self.user.key],
                           )
        self.assertIsNone(Object.get_by_id('fake:create'))
        self.assertEqual(['fail', 'sent'], sent)

    def test_update_profile(self):
        self.user.obj = self.store_object(
            id='fake:profile:user',
            copies = [Target(protocol='other', uri='other:profile:fake:user')])
        self.user.put()

        self.make_followers()

        actor = {
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Ms. ☕ Baz',
            'urls': [{'displayName': 'Ms. ☕ Baz', 'value': 'https://user.com/'}],
            'updated': '2022-01-02T03:04:05+00:00',
        }
        id = 'fake:user#update-2022-01-02T03:04:05+00:00'
        update_as1 = {
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': actor,
            'object': {**actor, 'id': 'fake:profile:user'},
        }
        Fake.receive_as1(update_as1)

        # profile object
        self.assert_object('fake:profile:user',
                           our_as1=update_as1['object'],
                           copies=self.user.obj.copies,
                           users=[self.user.key],
                           )

        # update activity
        self.assertIsNone(Object.get_by_id(id))
        self.assertEqual([
            ('other:alice:target', update_as1),
            ('other:bob:target', update_as1),
        ], OtherFake.sent)

    def test_update_profile_bare_object(self):
        profile = {
            'objectType': 'person',
            'id': 'other:alice',
            'displayName': 'Ms. ☕ Baz',
            'summary': 'first',
        }
        self.alice.obj = self.store_object(
            id='other:alice',
            copies = [Target(protocol='fake', uri='fake:profile:other:alice')])
        self.alice.put()

        Follower.get_or_create(to=self.alice, from_=self.user)

        # unchanged from what's already in the datastore. we should send update
        # anyway (instead of create) since it's an actor.
        OtherFake.receive_as1(profile)

        # profile object
        profile['updated'] = '2022-01-02T03:04:05+00:00'
        self.assert_object('other:alice',
                           our_as1=profile,
                           users=[self.alice.key],
                           copies=[Target(protocol='fake',
                                          uri='fake:profile:other:alice')],
                           source_protocol='other',
                           )
        self.assertEqual([('fake:shared:target', {
            'objectType': 'activity',
            'verb': 'update',
            'id': 'other:alice#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            'actor': profile,
            'object': profile,
        })], Fake.sent)

    def test_update_profile_use_instead(self):
        user_instead = self.make_user('fake:user-instead', cls=Fake,
                                       use_instead=self.user.key)

        profile = {
            'objectType': 'person',
            'id': 'fake:profile:user-instead',
            'foo': 'bar',
        }
        obj = Object(id='fake:profile:user', source_protocol='fake', our_as1=profile)
        Fake.receive(obj)

        # profile object
        self.assert_object('fake:profile:user',
                           our_as1={
                               **profile,
                               'updated': '2022-01-02T03:04:05+00:00',
                           },
                           source_protocol='fake',
                           users=[self.user.key],
                           )
        self.assertIsNone(Object.get_by_id(
            'fake:profile:user#bridgy-fed-update-2022-01-02T03:04:05+00:00'))

    def test_mention_object(self, *mocks):
        self.alice.obj.our_as1 = {'id': 'other:alice', 'objectType': 'person'}
        self.alice.obj.put()
        self.bob.obj.our_as1 = {'id': 'other:bob', 'objectType': 'person'}
        self.bob.obj.put()

        mention_as1 = {
            'objectType': 'note',
            'id': 'fake:mention',
            'author': 'fake:user',
            'content': 'something',
            'tags': [{
                'objectType': 'mention',
                'url': 'other:alice',
            }, {
                'objectType': 'mention',
                'url': 'other:bob',
            }],
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(mention_as1))

        self.assert_object('fake:mention',
                           our_as1=mention_as1,
                           type='note',
                           users=[self.user.key],
                           notify=[self.alice.key, self.bob.key],
                           copies=[Target(protocol='other',
                                          uri='other:o:fa:fake:mention')],
                           )

        self.assertIsNone(Object.get_by_id('fake:post#bridgy-fed-create'))
        self.assertEqual('other:alice:target', OtherFake.sent[0][0])
        self.assertEqual('other:bob:target', OtherFake.sent[1][0])
        self.assertEqual('fake:mention#bridgy-fed-create', OtherFake.sent[0][1]['id'])
        self.assertEqual('fake:mention#bridgy-fed-create', OtherFake.sent[1][1]['id'])

    def test_follow(self):
        self._test_follow()

    def test_follow_existing_inactive(self):
        follower = Follower.get_or_create(to=self.alice, from_=self.user)
        self._test_follow()

    def test_follow_actor_object_composite_objects(self):
        self._test_follow(actor={'id': 'fake:user', 'objectType': 'person'},
                          object={'id': 'other:alice', 'objectType': 'person'})

    def _test_follow(self, **extra):
        OtherFake.fetchable['other:alice'] = {}

        follow_as1 = {
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:user',
            'object': 'other:alice',
            **extra,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(follow_as1))

        follow_obj = self.assert_object(
            'fake:follow',
            our_as1=follow_as1,
            copies=[Target(protocol='other', uri='other:o:fa:fake:follow')],
            users=[self.user.key],
            notify=[self.alice.key],
            feed=[],
        )

        accept_id = 'other:alice/followers#accept-fake:follow'
        accept_as1 = {
            'id': accept_id,
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'other:alice',
            'object': follow_as1,
        }
        self.assertEqual([('other:alice:target', follow_obj.as1)], OtherFake.sent)
        self.assertEqual([('fake:user:target', accept_as1)], Fake.sent)

        self.assert_entities_equal(
            Follower(to=self.alice.key, from_=self.user.key, status='active',
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
            users=[OtherFake(id='other:eve').key],
            notify=[self.user.key],
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
                'id': 'other:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'other:alice',
            })

        self.assertEqual([], Follower.query().fetch())
        self.assertEqual([], Fake.sent)

    def test_follow_object_unknown_protocol(self):
        with self.assertRaises(ErrorButDoNotRetryTask):
            Fake.receive_as1({
                'id': 'other:follow',
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'other:alice',
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

    @patch('dms.maybe_send')
    def test_follow_accept(self, _, **extra):
        self.user.enable_protocol(ExplicitFake)
        ExplicitFake.fetchable['efake:follow'] = {'id': 'efake:follow'}
        accept_as1 = {
            'id': 'fake:accept',
            'objectType': 'activity',
            'verb': 'accept',
            'actor': 'fake:user',
            'object': 'efake:follow'
        }

        self.assertEqual(('OK', 202), Fake.receive_as1(accept_as1))
        self.assertEqual([('efake:follow:target', accept_as1)], ExplicitFake.sent)

    def test_stop_following(self):
        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        follower = Follower.get_or_create(to=self.user, from_=self.alice)

        stop_as1 = {
            'id': 'other:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'other:alice',
            'object': 'fake:user',
        }
        _, code = OtherFake.receive_as1(stop_as1)
        self.assertEqual(202, code)

        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual([('fake:user:target', stop_as1)], Fake.sent)

    def test_stop_following_doesnt_exist(self):
        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        stop_following_as1 = {
            'id': 'other:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'other:alice',
            'object': 'fake:user',
        }
        self.assertEqual(('OK', 202), OtherFake.receive_as1(stop_following_as1))

        self.assertEqual(0, Follower.query().count())
        self.assertEqual([('fake:user:target', stop_following_as1)], Fake.sent)

    def test_stop_following_inactive(self):
        self.user.obj.our_as1 = {'id': 'fake:user'}
        self.user.obj.put()

        follower = Follower.get_or_create(to=self.user, from_=self.alice,
                                          status='inactive')

        stop_following_as1 = {
            'id': 'other:stop-following',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'other:alice',
            'object': 'fake:user',
        }
        self.assertEqual(('OK', 202), OtherFake.receive_as1(stop_following_as1))

        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual([('fake:user:target', stop_following_as1)], Fake.sent)

    def test_block(self):
        self.bob.obj.our_as1 = {'id': 'other:bob'}
        self.bob.obj.put()

        block_as1 = {
            'id': 'fake:block',
            'objectType': 'activity',
            'verb': 'block',
            'actor': 'fake:user',
            'object': 'other:bob',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(block_as1))
        self.assertEqual([('other:bob:target', block_as1)], OtherFake.sent)

    def test_undo_block(self):
        eve = self.make_user(id='other:eve', cls=OtherFake,
                             obj_as1={'id': 'other:eve'})
        self.make_followers()

        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'fake:block',
            'actor': 'fake:user',
            'object': 'other:eve',
        }
        self.store_object(id='fake:block', our_as1=block, source_protocol='fake')

        undo_as1 = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'fake:undo',
            'actor': 'fake:user',
            'object': block,
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(undo_as1))
        self.assertEqual([('other:eve:target', undo_as1)], OtherFake.sent)

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
            'object': ['other:dan', 'fake:user'],
        }

        self.assertEqual(('OK', 202), OtherFake.receive_as1(follow_as1))

        self.assertEqual(1, len(Fake.sent))
        self.assertEqual('other:follow', Fake.sent[0][1]['id'])

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual(self.user.key, followers[0].to)

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
                'object': 'other:alice',
            })
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)
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
            'actor': 'fake:user',
            'object': 'fake:alice',
        }

        # no matching copy users
        obj = Object(id='fake:follow', our_as1=follow, source_protocol='fake')
        _, code = Fake.receive(obj, authed_as='fake:user')
        self.assertEqual(204, code)
        self.assert_equals(follow, obj.our_as1)

        # matching copy user
        self.alice.copies = [Target(uri='fake:alice', protocol='fake')]
        self.alice.put()

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.memcache.clear()
        memcache.pickle_memcache.clear()

        obj.new = True
        Fake.fetchable = {
            'fake:alice': {},
        }

        self.assertEqual(('OK', 202), Fake.receive(obj, authed_as='fake:user'))
        self.assert_equals({
            **follow,
            'actor': 'fake:user',
            'object': 'other:alice',
        }, Object.get_by_id('fake:follow').our_as1)

    def test_resolve_ids_share(self):
        share = {
            'objectType': 'activity',
            'actor': 'fake:user',
            'verb': 'share',
            'object': 'fake:post',
        }

        # no matching copy object
        obj = Object(id='fake:share', our_as1=share, source_protocol='fake')
        _, code = Fake.receive(obj, authed_as='fake:user')
        self.assertEqual(204, code)
        self.assert_equals(share, obj.our_as1)

        # matching copy object
        self.store_object(id='other:post',
                          copies=[Target(uri='fake:post', protocol='fake')])

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.memcache.clear()
        memcache.pickle_memcache.clear()
        obj.new = True

        _, code = Fake.receive(obj, authed_as='fake:user')
        self.assertEqual(204, code)

        self.assert_equals({
            'id': 'fake:share',
            'objectType': 'activity',
            'actor': 'fake:user',
            'verb': 'share',
            'object': 'other:post',
        }, obj.our_as1)

    def test_resolve_ids_reply_mentions(self):
        reply = {
            'id': 'fake:reply',
            'author': 'fake:user',
            'objectType': 'note',
            'inReplyTo': [
                'fake:unknown-post',
                'fake:post',
            ],
            'tags': [{
                'objectType': 'mention',
                'url': 'fake:alice',
            }, {
                'objectType': 'mention',
                'url': 'fake:bob',
            }],
        }

        # no matching copies
        _, code = Fake.receive_as1(reply)
        self.assertEqual(204, code)
        self.assert_equals(reply, Object.get_by_id('fake:reply').our_as1)

        # matching copies
        self.alice.copies=[Target(uri='fake:alice', protocol='fake')]
        self.alice.put()
        self.alice.obj = Object(id='other:alice', our_as1={'a': 'b'})
        self.alice.obj.our_as1 = {'a': 'b'}

        self.bob.copies=[Target(uri='fake:bob', protocol='fake')]
        self.bob.put()
        self.bob.obj = Object(id='other:bob', our_as1={'x': 'y'})
        self.bob.obj.our_as1 = {'a': 'b'}
        self.bob.obj.put()

        models.get_original_user_key.cache_clear()
        models.get_original_object_key.cache_clear()
        memcache.pickle_memcache.clear()

        self.assertEqual(('OK', 202), Fake.receive_as1(reply, new=True))
        self.assertEqual({
            'id': 'fake:reply',
            'objectType': 'note',
            'author': 'fake:user',
            'inReplyTo': [
                'fake:unknown-post',
                'fake:post',
            ],
            'tags': [{
                'objectType': 'mention',
                'url': 'other:alice',
            }, {
                'objectType': 'mention',
                'url': 'other:bob',
            }],
        }, Object.get_by_id('fake:reply').our_as1)

    def test_follow_and_block_protocol_user_sets_enabled_protocols(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        follow = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'efake:follow',
            'actor': 'efake:user',
            'object': 'fa.brid.gy',
        }
        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'efake:block',
            'actor': 'efake:user',
            'object': 'fa.brid.gy',
        }

        user = self.make_user('efake:user', cls=ExplicitFake)
        self.assertFalse(user.is_enabled(Fake))
        ExplicitFake.fetchable = {'efake:user': {'profile': 'info'}}

        # fake protocol isn't enabled yet, block should be a noop
        self.assertEqual(('OK', 200), ExplicitFake.receive_as1(block))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)

        # follow should add to enabled_protocols
        _, code = ExplicitFake.receive_as1(follow)
        self.assertEqual(204, code)
        user = user.key.get()
        self.assertEqual({
            'id': 'efake:user',
            'profile': 'info',
        }, user.obj.as1)

        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual(['efake:user'], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))

        dm_id = 'https://fa.brid.gy/#welcome-dm-efake:user-2022-01-02T03:04:05+00:00-create'
        follow_back_id = 'https://fa.brid.gy/#follow-back-efake:user-2022-01-02T03:04:05+00:00'

        self.assertEqual([
            # fa.brid.gy follows back
            ('efake:user:target', {
                'objectType': 'activity',
                'verb': 'follow',
                'id': 'https://fa.brid.gy/#follow-back-efake:user-2022-01-02T03:04:05+00:00',
                'actor': 'fa.brid.gy',
                'object': 'efake:user',
            }),
            # accept follow
            ('efake:user:target', {
                'objectType': 'activity',
                'verb': 'accept',
                'id': 'fa.brid.gy/followers#accept-efake:follow',
                'actor': 'fa.brid.gy',
                'object': {
                    **follow,
                    'actor': {'id': 'efake:user', 'profile': 'info'},
                },
            }),
        ], ExplicitFake.sent[1:])

        ExplicitFake.sent = ExplicitFake.sent[:1]
        DmsTest().assert_sent(Fake, user, 'welcome', 'Welcome to Bridgy Fed! Your account will soon be bridged to fake-phrase at <a class="h-card u-author" rel="me" href="web:fake:efake:user" title="fake:handle:efake:handle:user">fake:handle:efake:handle:user</a>. <a href="https://fed.brid.gy/docs">See the docs</a> and <a href="https://fed.brid.gy/efake/efake:handle:user">your user page</a> for more information. To disable this and delete your bridged profile, block this account.')

        # another follow should be a noop
        follow['id'] += '2'
        Fake.created_for = []
        _, code = ExplicitFake.receive_as1(follow)
        self.assertEqual(204, code)
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['efake:user'], Fake.created_for)

        # block should remove from enabled_protocols
        Follower.get_or_create(to=user, from_=self.user)
        block['id'] += '2'
        self.assertEqual(('OK', 200), ExplicitFake.receive_as1(block))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertFalse(user.is_enabled(Fake))

        # ...and delete copy actor
        id = 'efake:user#bridgy-fed-delete-user-fake-2022-01-02T03:04:05+00:00'
        delete_efake = {
            'objectType': 'activity',
            'verb': 'delete',
            'id': id,
            'actor': 'efake:user',
            'object': 'efake:user',
        }
        self.assertEqual([('fake:shared:target', delete_efake)], Fake.sent)
        self.assertIsNone(Object.get_by_id(id))

    def test_follow_bot_user_refreshes_profile(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        # store profile that's opted out
        user = self.make_user('efake:user', cls=ExplicitFake, obj_as1={
            'id': 'efake:user',
            'summary': '#nobridge',
        })
        self.assertFalse(user.is_enabled(Fake))

        # updated profile isn't opted out
        ExplicitFake.fetchable = {'efake:user': {
            'id': 'efake:user',
            'summary': 'never mind',
        }}

        # follow should refresh profile
        _, code = ExplicitFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'efake:follow',
            'actor': 'efake:user',
            'object': 'fa.brid.gy',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['efake:user'], ExplicitFake.fetched)

    def test_follow_bot_user_copy_id_refreshes_profile(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web,
                       copies=[Target(uri='efake:bot', protocol='efake')])

        # profile that's opted out
        user = self.make_user('efake:user', cls=ExplicitFake, obj_as1={
            'id': 'efake:user',
            'summary': '#nobridge',
        })
        self.assertFalse(user.is_enabled(Fake))

        # updated profile isn't opted out
        ExplicitFake.fetchable = {'efake:user': {
            'id': 'efake:user',
            'summary': 'never mind',
        }}

        # follow should refresh profile
        _, code = ExplicitFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'efake:follow',
            'actor': 'efake:user',
            'object': 'efake:bot',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['efake:user'], ExplicitFake.fetched)

    def test_follow_bot_user_overrides_nobot(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web,
                       copies=[Target(uri='efake:bot', protocol='efake')])

        # profile that's opted out
        actor = {
            'id': 'efake:user',
            'summary': '#nobot',
        }
        user = self.make_user('efake:user', cls=ExplicitFake, obj_as1=actor)
        self.assertFalse(user.is_enabled(Fake))
        ExplicitFake.fetchable = {'efake:user': actor}

        # follow should override #nobot
        _, code = ExplicitFake.receive_as1({
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'efake:follow',
            'actor': 'efake:user',
            'object': 'efake:bot',
        })
        self.assertEqual(204, code)

        user = user.key.get()
        self.assertIsNone(user.status)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual(['efake:user'], ExplicitFake.fetched)

    @patch.object(ExplicitFake, 'REQUIRES_NAME', new=True)
    def test_follow_bot_user_spam_filter_doesnt_enable(self):
        self.make_user('fa.brid.gy', cls=Web,
                       copies=[Target(uri='efake:bot', protocol='efake')])

        user = self.make_user('efake:user', cls=ExplicitFake)
        ExplicitFake.fetchable = {'efake:user': {'id': 'efake:user'}}

        with self.assertRaises(NoContent):
            _, code = ExplicitFake.receive_as1({
                'objectType': 'activity',
                'verb': 'follow',
                'id': 'efake:follow',
                'actor': 'efake:user',
                'object': 'efake:bot',
            })

        user = user.key.get()
        self.assertEqual('blocked', user.status)
        self.assertFalse(user.is_enabled(Fake))
        self.assertEqual(['efake:user'], ExplicitFake.fetched)

    def test_block_then_follow_protocol_user_recreates_copy(self):
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        follow = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'efake:follow',
            'actor': 'efake:user',
            'object': 'fa.brid.gy',
        }
        block = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'efake:block',
            'actor': 'efake:user',
            'object': 'fa.brid.gy',
        }

        copy = Target(uri='fake:user', protocol='fake')
        user = self.make_user('efake:user', cls=ExplicitFake,
                              enabled_protocols=['fake'], copies=[copy])
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual([copy], user.copies)

        self.assertEqual(('OK', 200), ExplicitFake.receive_as1(block))
        user = user.key.get()
        self.assertFalse(user.is_enabled(Fake))
        self.assertEqual([copy], user.copies)

        # fake protocol isn't enabled yet, block should be a noop
        ExplicitFake.fetchable = {'efake:user': {'profile': 'info'}}
        _, code = ExplicitFake.receive_as1(follow)
        self.assertEqual(204, code)
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual(['efake:user'], Fake.created_for)

    def test_receive_activity_lease(self):
        Follower.get_or_create(to=self.user, from_=self.alice)

        post_as1 = {
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

        orig_send = OtherFake.send
        at_send = Condition()
        continue_send = Condition()
        def send(*args, **kwargs):
            with at_send:
                at_send.notify()
            with continue_send:
                continue_send.wait(10)  # timeout in seconds
            return orig_send(*args, **kwargs)

        def receive():
            with app.test_request_context('/'), \
                 ndb_client.context(
                     cache_policy=common.cache_policy,
                     global_cache=_InProcessGlobalCache(),
                     global_cache_timeout_policy=common.global_cache_timeout_policy):
                try:
                    Fake.receive_as1(post_as1)
                except NoContent:  # raised by the second thread
                    pass

        first = Thread(target=receive)
        second = Thread(target=receive)

        with patch.object(OtherFake, 'send', side_effect=send):
            first.start()
            second.start()
            with at_send:
                at_send.wait(10)  # timeout in seconds
            with continue_send:
                continue_send.notify(1)
            first.join()
            second.join()

        # only one receive call should try to send
        self.assertEqual([('other:alice:target', post_as1)], OtherFake.sent)

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
                           our_as1=actor,
                           users=[ActivityPub(id='https://lim.it/alice').key],
                           )

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

    def test_receive_task_handler_obj_id(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        }
        self.store_object(id='fake:post', our_as1=note, source_protocol='fake')

        create = {
            'id': 'fake:post#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'object': note,
            'actor': 'fake:other',
        }
        self.store_object(id='fake:post#bridgy-fed-create',
                          source_protocol='fake', our_as1=create)

        resp = self.post('/queue/receive', data={
            'obj_id': 'fake:post#bridgy-fed-create',
            'authed_as': 'fake:other',
        }, headers={'X-AppEngine-TaskRetryCount': '0'})
        self.assertEqual(204, resp.status_code)
        obj = Object.get_by_id('fake:post#bridgy-fed-create')

    def test_receive_task_handler_properties(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        }
        create = {
            'id': 'fake:post#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'object': note,
            'actor': 'fake:other',
        }

        resp = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'fake',
            'authed_as': 'fake:other',
        }, headers={'X-AppEngine-TaskRetryCount': '0'})
        self.assertEqual(204, resp.status_code)

        obj = Object.get_by_id('fake:post')
        self.assertEqual(note, obj.our_as1)
        self.assertIsNone(Object.get_by_id('fake:post#bridgy-fed-create'))

    @patch.object(Fake, 'receive', side_effect=requests.ConnectionError('foo'))
    def test_receive_task_handler_connection_error(self, _):
        orig_count = Object.query().count()
        got = self.post('/queue/receive', data={
            'our_as1': json_dumps({'id': 'fake:post'}),
            'source_protocol': 'fake',
        })
        self.assertEqual(304, got.status_code)
        self.assertEqual(orig_count, Object.query().count())

    def test_receive_task_handler_authed_as(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'fake',
            'authed_as': 'fake:user',
        })
        self.assertEqual(204, got.status_code)
        self.assertEqual(note, Object.get_by_id('fake:post').our_as1)

    def test_receive_task_handler_authed_as_domain_vs_homepage(self):
        user = self.make_user('user.com', cls=Web, obj_id='https://user.com/')
        note = {
            'id': 'https://user.com/c',
            'objectType': 'note',
            'author': 'https://user.com/',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'web',
            'authed_as': 'user.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertEqual({
            **note,
            'author': 'user.com',
        }, Object.get_by_id('https://user.com/c').our_as1)

    @patch('requests.get', side_effect=web_user_gets('foo.com') + [ACTOR_HTML_RESP])
    def test_receive_task_handler_authed_as_www_subdomain(self, _):
        note = {
            'id': 'http://www.foo.com/post',
            'objectType': 'note',
            'author': 'http://www.foo.com/bar',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'web',
            'authed_as': 'foo.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertEqual(note, Object.get_by_id('http://www.foo.com/post').our_as1)

    @patch('requests.get', return_value=requests_response('<html></html>'))
    def test_receive_task_handler_authed_as_mixed_subdomains(self, _):
        user = self.make_user('user.com', cls=Web, obj_id='https://user.com/')
        note = {
            'objectType': 'note',
            'id': 'http://user.com/post',
            'author': 'http://m.user.com/',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'web',
            'authed_as': 'www.user.com',
        })
        self.assertEqual(204, got.status_code)
        self.assertEqual(note, Object.get_by_id('http://user.com/post').our_as1)

    @patch('requests.get', return_value=requests_response('<html></html>'))
    def test_receive_task_handler_authed_as_wrong_domain(self, _):
        note = {
            'id': 'http://bar.com/post',
            'objectType': 'note',
            'author': 'http://bar.com/',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'web',
            'authed_as': 'foo.com',
        })
        self.assertEqual(299, got.status_code)
        self.assertIsNone(Object.get_by_id('https://bar.com/post'))

    def test_receive_task_handler_not_authed_as(self):
        note = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:other',
        }

        got = self.post('/queue/receive', data={
            'our_as1': json_dumps(note),
            'source_protocol': 'fake',
            'authed_as': 'fake:eve',
        })
        self.assertEqual(299, got.status_code)
        self.assertIsNone(Object.get_by_id('fake:post'))

    def test_like_not_authed_as_actor(self):
        Fake.fetchable['fake:post'] = {
            'objectType': 'note',
            'author': 'other:bob',
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
        common.RUN_TASKS_INLINE = False
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

        note_as1 = {
            'id': 'fake:post',
            'objectType': 'note',
            'author': 'fake:user',
        }
        self.assertEqual(('OK', 202), Fake.receive_as1(note_as1))

        create_as1 = {
            'id': 'fake:post#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': note_as1,
            'published': '2022-01-02T03:04:05+00:00',
        }
        self.assertEqual(2, mock_create_task.call_count)
        self.assert_task(mock_create_task, 'send', source_protocol='fake',
                         protocol='other', id='fake:post#bridgy-fed-create',
                         our_as1=create_as1, url='other:alice:target',
                         user=self.user.key.urlsafe())
        self.assert_task(mock_create_task, 'send', source_protocol='fake',
                         protocol='other', id='fake:post#bridgy-fed-create',
                         our_as1=create_as1, url='other:bob:target',
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
                           users=[self.user.key],
                           notify=[eve.key],
                           )

        create_as1 = {
            'id': 'fake:reply#bridgy-fed-create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': reply_as1,
            'published': '2022-01-02T03:04:05+00:00',
        }
        self.assert_task(mock_create_task, 'send', source_protocol='fake',
                         protocol='other', orig_obj_id='other:post',
                         id='fake:reply#bridgy-fed-create', our_as1=create_as1,
                         url='other:post:target', user=self.user.key.urlsafe())

        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_send_task_handler_obj_id(self):
        self.make_followers()

        note = self.store_object(id='fake:note', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
        })
        target = Target(uri='fake:shared:target', protocol='fake')
        create = self.store_object(id='fake:create', our_as1={
            'id': 'fake:create',
            'objectType': 'activity',
            'verb': 'post',
            'actor': 'fake:user',
            'object': note.as1,
        })
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj_id': 'fake:create',
            'orig_obj_id': 'fake:note',
            'url': 'fake:shared:target',
            'user': self.user.key.urlsafe(),
        }, headers={'X-AppEngine-TaskRetryCount': '0'})
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
        obj = self.store_object(id='fake:post', our_as1={
            'objectType': 'note',
        })
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj_id': 'fake:post',
            'url': 'fake:target',
        })
        self.assertEqual(204, resp.status_code)

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
                self.store_object(id=activity['id'], our_as1=activity)
                resp = self.post('/queue/send', data={
                    'protocol': 'fake',
                    'obj_id': activity['id'],
                    'url': 'fake:target',
                })
                self.assertEqual(204, resp.status_code)
                self.assertEqual([], Fake.sent)

    @patch.object(Fake, 'send', return_value=True)
    def test_send_task_follow_user_use_instead(self, mock_send):
        self.bob.use_instead = self.alice.key
        self.bob.put()

        target = Target(uri='fake:target', protocol='fake')
        self.store_object(id='fake:note', our_as1={
            'id': 'fake:post',
            'objectType': 'note',
        })
        resp = self.post('/queue/send', data={
            'protocol': 'fake',
            'obj_id': 'fake:note',
            'url': 'fake:target',
            'user': self.bob.key.urlsafe(),
        })

        _, kwargs = mock_send.call_args
        self.assertEqual('other:alice', kwargs['from_user'].key.id())
