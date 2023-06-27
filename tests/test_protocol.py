"""Unit tests for protocol.py."""
from unittest.mock import patch

from flask import g
from granary import as2
from oauth_dropins.webutil.testutil import requests_response
import requests

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from activitypub import ActivityPub
from app import app
from models import Follower, Object, PROTOCOLS, User
import protocol
from protocol import Protocol
from ui import UIProtocol
from web import Web
from werkzeug.exceptions import BadRequest

from .test_activitypub import ACTOR, REPLY, REPLY_OBJECT
from .test_web import ACTOR_HTML

REPLY = {
    **REPLY,
    'actor': ACTOR,
    'object': {
        **REPLY['object'],
        'attributedTo': ACTOR,
    },
}

UPDATE_PROFILE = {
    'objectType': 'activity',
    'verb': 'update',
    'id': 'fake:user#update-2022-01-02T03:04:05+00:00',
    'actor': 'fake:user',
    'object': {
        'objectType': 'person',
        'id': 'fake:user',
        'displayName': 'Ms. ☕ Baz',
        'urls': [{'displayName': 'Ms. ☕ Baz', 'value': 'https://user.com/'}],
        'updated': '2022-01-02T03:04:05+00:00',
    },
}


class ProtocolTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('foo.com', has_hcard=True)
        g.user = None

    def tearDown(self):
        PROTOCOLS.pop('greedy', None)
        super().tearDown()

    @staticmethod
    def store_object(**kwargs):
        obj = Object(**kwargs)
        obj.put()
        del protocol.objects_cache[obj.key.id()]
        return obj

    def test_protocols_global(self):
        self.assertEqual(Fake, PROTOCOLS['fake'])
        self.assertEqual(Web, PROTOCOLS['web'])
        self.assertEqual(Web, PROTOCOLS['webmention'])

    def test_for_domain_for_request(self):
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
                self.assertEqual(expected, Protocol.for_domain(domain))
                with app.test_request_context('/foo', base_url=f'https://{domain}/'):
                    self.assertEqual(expected, Protocol.for_request())

    def test_for_domain_for_request_fed(self):
        for url, expected in [
            ('https://fed.brid.gy/', Fake),
            ('http://localhost/foo', Fake),
            ('https://ap.brid.gy/bar', ActivityPub),
            ('https://baz/biff', None),
        ]:
            with self.subTest(url=url, expected=expected):
                self.assertEqual(expected, Protocol.for_domain(url, fed=Fake))
                with app.test_request_context('/foo', base_url=url):
                    self.assertEqual(expected, Protocol.for_request(fed=Fake))

    def test_subdomain_url(self):
        self.assertEqual('https://fa.brid.gy/', Fake.subdomain_url())
        self.assertEqual('https://fa.brid.gy/foo?bar', Fake.subdomain_url('foo?bar'))
        self.assertEqual('https://fed.brid.gy/', UIProtocol.subdomain_url())

    def test_receive_from_bridgy_fed_fails(self):
        with self.assertRaises(BadRequest):
            Fake.receive('https://fed.brid.gy/r/foo', as2=REPLY)

        self.assertIsNone(Object.get_by_id('https://fed.brid.gy/r/foo'))

        with self.assertRaises(BadRequest):
            Fake.receive('foo', as2={
                **REPLY,
                'id': 'https://web.brid.gy/r/foo',
            })

        self.assertIsNone(Object.get_by_id('foo'))
        self.assertIsNone(Object.get_by_id('https://web.brid.gy/r/foo'))

        with self.assertRaises(BadRequest):
            Fake.receive(REPLY['id'], as2={
                **REPLY,
                'actor': 'https://ap.brid.gy/user.com',
            })

        self.assertIsNone(Object.get_by_id(REPLY['id']))

    def test_for_id(self):
        for id, expected in [
                (None, None),
                ('', None),
                ('foo://bar', None),
                ('fake:foo', Fake),
                # TODO
                # ('at://foo', ATProto),
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
    def test_for_id_web_fetch(self, mock_get):
        mock_get.return_value = requests_response(ACTOR_HTML)
        self.assertEqual(Web, Protocol.for_id('http://web.site/'))
        self.assertIn(self.req('http://web.site/'), mock_get.mock_calls)

    @patch('requests.get')
    def test_for_id_web_fetch_no_mf2(self, mock_get):
        mock_get.return_value = requests_response('<html></html>')
        self.assertIsNone(Protocol.for_id('http://web.site/'))
        self.assertIn(self.req('http://web.site/'), mock_get.mock_calls)

    def test_load(self):
        Fake.fetchable['foo'] = {'x': 'y'}

        loaded = Fake.load('foo')
        self.assert_equals({'x': 'y'}, loaded.our_as1)
        self.assertFalse(loaded.changed)
        self.assertTrue(loaded.new)

        self.assertIsNotNone(Object.get_by_id('foo'))
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_existing(self):
        self.store_object(id='foo', our_as1={'x': 'y'})

        loaded = Fake.load('foo')
        self.assert_equals({'x': 'y'}, loaded.our_as1)
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
        obj = Object(id='foo', our_as1={'x': 'y'})
        protocol.objects_cache['foo'] = obj
        loaded = Fake.load('foo')
        self.assert_entities_equal(obj, loaded)

        # check that it's a separate copy of the entity in the cache
        # https://github.com/snarfed/bridgy-fed/issues/558#issuecomment-1603203927
        loaded.our_as1 = {'a': 'b'}
        self.assertEqual({'x': 'y'}, Protocol.load('foo').our_as1)

    def test_load_remote_true_existing_empty(self):
        Fake.fetchable['foo'] = {'x': 'y'}
        Object(id='foo').put()

        loaded = Fake.load('foo', remote=True)
        self.assertEqual({'x': 'y'}, loaded.as1)
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
        obj = self.store_object(id='foo', our_as1={'x': 'stored'},
                                source_protocol='fake')
        Fake.fetchable['foo'] = {'x': 'stored'}

        loaded = Fake.load('foo', remote=True)
        self.assert_entities_equal(obj, loaded,
                                   ignore=['expire', 'created', 'updated'])
        self.assertFalse(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_true_changed(self):
        self.store_object(id='foo', our_as1={'content': 'stored'})
        Fake.fetchable['foo'] = {'content': 'new'}

        loaded = Fake.load('foo', remote=True)
        self.assert_equals({'content': 'new'}, loaded.our_as1)
        self.assertTrue(loaded.changed)
        self.assertFalse(loaded.new)
        self.assertEqual(['foo'], Fake.fetched)

    def test_load_remote_false(self):
        self.assertIsNone(Fake.load('nope', remote=False))
        self.assertEqual([], Fake.fetched)

        obj = self.store_object(id='foo', our_as1={'content': 'stored'})
        self.assert_entities_equal(obj, Fake.load('foo', remote=False))
        self.assertEqual([], Fake.fetched)

    def test_Protocol_load_remote_false_existing_object_empty(self):
        obj = self.store_object(id='foo')
        self.assert_entities_equal(obj, Protocol.load('foo', remote=False))

    def test_local_false_missing(self):
        with self.assertRaises(requests.HTTPError) as e:
            Fake.load('foo', local=False)
            self.assertEqual(410, e.response.status_code)

        self.assertEqual(['foo'], Fake.fetched)

    def test_local_false_existing(self):
        self.store_object(id='foo', our_as1={'content': 'stored'}, source_protocol='ui')

        Fake.fetchable['foo'] = {'foo': 'bar'}
        Fake.load('foo', local=False)
        self.assert_object('foo', source_protocol='fake', our_as1={'foo': 'bar'})
        self.assertEqual(['foo'], Fake.fetched)

    def test_remote_false_local_false_assert(self):
        with self.assertRaises(AssertionError):
            Fake.load('nope', local=False, remote=False)


class ProtocolReceiveTest(TestCase):

    def setUp(self):
        super().setUp()
        g.user = self.make_user('fake:user', cls=Fake, obj_id='fake:user')
        self.alice = self.make_user('fake:alice', cls=Fake, obj_id='fake:alice')
        self.bob = self.make_user('fake:bob', cls=Fake, obj_id='fake:bob')

    def assert_object(self, id, **props):
        return super().assert_object(id, delivered_protocol='fake', **props)

    def make_followers(self):
        from_ = self.make_user(id, cls=ActivityPub, obj_as2=actor)
        Follower.get_or_create(to=g.user, from_=from_, **kwargs)

        for id, kwargs, actor in [
            ('fake:a', {}, None),
            ('fake:b', {}, None),
            ('https://mastodon/bbb', {}, {
                'publicInbox': 'https://public/inbox',
                'inbox': 'https://unused',
            }),
            ('https://mastodon/ccc', {}, {
                'endpoints': {
                    'sharedInbox': 'https://shared/inbox',
                },
            }),
            ('https://mastodon/ddd', {}, {
               'inbox': 'https://inbox',
            }),
            ('https://mastodon/ggg', {'status': 'inactive'}, {
                'inbox': 'https://unused/2',
            }),
            ('https://mastodon/hhh', {}, {
                # dupe of ddd; should be de-duped
                'inbox': 'https://inbox',
            }),
        ]:
            from_ = self.make_user(id, cls=ActivityPub, obj_as2=actor)
            Follower.get_or_create(to=g.user, from_=from_, **kwargs)

#     def test_create_post(self):
#         mock_get.side_effect = [NOTE, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')
#         self.make_followers()

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/post'),
#         ))
#         inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
#         self.assert_deliveries(mock_post, inboxes, CREATE_AS2)

#         self.assert_object('https://user.com/post',
#                            users=[g.user.key],
#                            mf2=NOTE_MF2,
#                            type='note',
#                            source_protocol='web',
#                            )
#         self.assert_object('https://user.com/post#bridgy-fed-create',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            status='complete',
#                            mf2=NOTE_MF2,
#                            our_as1=CREATE_AS1,
#                            delivered=inboxes,
#                            type='post',
#                            labels=['user', 'activity'],
#                            )

#     def test_update_post(self):
#         mock_get.side_effect = [NOTE, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')

#         mf2 = copy.deepcopy(NOTE_MF2)
#         mf2['properties']['content'] = 'different'
#         Object(id='https://user.com/post', users=[g.user.key], mf2=mf2).put()

#         self.make_followers()

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/post'),
#         ))
#         inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
#         self.assert_deliveries(mock_post, inboxes, UPDATE_AS2)

#         update_as1 = {
#             'objectType': 'activity',
#             'verb': 'update',
#             'id': 'https://user.com/post#bridgy-fed-update-2022-01-02T03:04:05+00:00',
#             'actor': 'http://localhost/user.com',
#             'object': {
#                 **NOTE_AS1,
#                 'updated': '2022-01-02T03:04:05+00:00',
#             },
#         }
#         self.assert_object(
#             f'https://user.com/post#bridgy-fed-update-2022-01-02T03:04:05+00:00',
#             users=[g.user.key],
#             source_protocol='web',
#             status='complete',
#             mf2=NOTE_MF2,
#             our_as1=update_as1,
#             delivered=inboxes,
#             type='update',
#             labels=['user', 'activity'],
#         )

#     def test_update_skip_if_content_unchanged(self):
#         """https://github.com/snarfed/bridgy-fed/issues/78"""
#         Object(id='https://user.com/reply', mf2=REPLY_MF2).put()

#         mock_get.side_effect = ACTIVITYPUB_GETS

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/reply',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(204, got.status_code)
#         mock_post.assert_not_called()

#     def test_create_with_image(self):
#         create_html = NOTE_HTML.replace(
#             '</body>', '<img class="u-photo" src="http://im/age" />\n</body>')
#         mock_get.side_effect = [
#             requests_response(create_html, url='https://user.com/post',
#                               content_type=CONTENT_TYPE_HTML),
#             ACTOR,
#         ]
#         mock_post.return_value = requests_response('abc xyz ')

#         Follower.get_or_create(
#             to=g.user,
#             from_=self.make_user('http://a', cls=ActivityPub,
#                                  obj_as2={'inbox': 'https://inbox'}))
#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         self.assertEqual(('https://inbox',), mock_post.call_args[0])
#         create = copy.deepcopy(CREATE_AS2)
#         create['object'].update({
#             'image': {'url': 'http://im/age', 'type': 'Image'},
#             'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
#         })
#         self.assert_equals(create, json_loads(mock_post.call_args[1]['data']))

#     def test_create_reply(self):
#         mock_get.side_effect = ACTIVITYPUB_GETS
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/reply',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/reply'),
#             self.as2_req('http://not/fediverse'),
#             self.req('http://not/fediverse'),
#             self.as2_req('https://mas.to/toot'),
#             self.as2_req('https://mas.to/author'),
#         ))

#         self.assert_deliveries(mock_post, ['https://mas.to/inbox'], AS2_CREATE)

#         self.assert_object('https://user.com/reply',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            mf2=REPLY_MF2,
#                            as1=REPLY_AS1,
#                            type='comment',
#                            )
#         self.assert_object('https://user.com/reply#bridgy-fed-create',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            status='complete',
#                            mf2=REPLY_MF2,
#                            our_as1=CREATE_REPLY_AS1,
#                            delivered=['https://mas.to/inbox'],
#                            type='post',
#                            labels=['user', 'activity'],
#                            )

#     def test_update_reply(self):
#         self.make_followers()

#         mf2 = {
#             'properties': {
#                 'content': ['other'],
#             },
#         }
#         Object(id='https://user.com/reply', status='complete', mf2=mf2).put()

#         mock_get.side_effect = ACTIVITYPUB_GETS
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/reply',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)
#         self.assertEqual((AS2_UPDATE, 'https://mas.to/inbox'), Fake.sent)

    @patch('requests.get')
    def test_receive_reply_not_feed_not_notification(self, mock_get):
        Follower.get_or_create(to=Fake.get_or_create(id=ACTOR['id']),
                               from_=Fake.get_or_create(id='foo.com'))
        other_user = self.make_user('user.com', cls=Web)

        # user.com webmention discovery
        mock_get.return_value = requests_response('<html></html>')

        Fake.receive(REPLY['id'], as2=REPLY)

        self.assert_object(REPLY['id'],
                           as2=REPLY,
                           type='post',
                           users=[other_user.key],
                           # not feed since it's a reply
                           # not notification since it doesn't involve the user
                           labels=['activity'],
                           status='complete',
                           source_protocol='fake',
                           )
        self.assert_object(REPLY['object']['id'],
                           our_as1=as2.to_as1(REPLY['object']),
                           type='comment',
                           source_protocol='fake',
                           )

#     def test_follow(self):
#         mock_get.side_effect = [FOLLOW, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/follow',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/follow'),
#             self.as2_req('https://mas.to/mrs-foo'),
#         ))

#         self.assert_deliveries(mock_post, ['https://mas.to/inbox'], FOLLOW_AS2)

#         obj = self.assert_object('https://user.com/follow',
#                                  users=[g.user.key],
#                                  source_protocol='web',
#                                  status='complete',
#                                  mf2=FOLLOW_MF2,
#                                  as1=FOLLOW_AS1,
#                                  delivered=['https://mas.to/inbox'],
#                                  type='follow',
#                                  object_ids=['https://mas.to/mrs-foo'],
#                                  labels=['user', 'activity'],
#                                  )

#         to = self.assert_user(ActivityPub, 'https://mas.to/mrs-foo', obj_as2={
#             'name': 'Mrs. ☕ Foo',
#             'id': 'https://mas.to/mrs-foo',
#             'inbox': 'https://mas.to/inbox',
#             'type': 'Person',
#         })

#         followers = Follower.query().fetch()
#         self.assertEqual(1, len(followers))
#         self.assertEqual(g.user.key, followers[0].from_)
#         self.assertEqual(to.key, followers[0].to)
#         self.assert_equals(obj.key, followers[0].follow)

#     def test_follow_no_actor(self):
#         g.user.obj_key = Object(id='a', as2=ACTOR_AS2).put()
#         g.user.put()

#         html = FOLLOW_HTML.replace(
#             '<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>', '')
#         follow = requests_response(html, url='https://user.com/follow',
#                                    content_type=CONTENT_TYPE_HTML)

#         mock_get.side_effect = [follow, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/follow',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         args, kwargs = mock_post.call_args
#         self.assertEqual(('https://mas.to/inbox',), args)
#         self.assert_equals(FOLLOW_AS2, json_loads(kwargs['data']))

#     def test_follow_no_target(self):
#         self.make_followers()

#         html = FOLLOW_HTML.replace(
#             '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>',
#             '<a class="u-follow-of"></a>')
#         follow = requests_response(html, url='https://user.com/follow',
#                                    content_type=CONTENT_TYPE_HTML)

#         mock_get.side_effect = [follow, ACTOR]

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/follow',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(400, got.status_code)
#         mock_post.assert_not_called()

    def test_follow_no_g_user(self):
        """No user from request, eg delivered to our ActivityPub shared inbox."""
        g.user = None

        follow_as1 = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': 'fake:follow',
            'actor': 'fake:alice',
            'object': 'fake:bob',
        }
        self.assertEqual('OK', Fake.receive('fake:follow', our_as1=follow_as1))

        obj = self.assert_object('fake:follow',
                                 our_as1=follow_as1,
                                 type='follow',
                                 source_protocol='fake',
                                 labels=['activity'],
                                 status='ignored',
                                 )
        self.assert_entities_equal(
            Follower(to=self.bob.key, from_=self.alice.key, status='active',
                     follow=obj.key),
            Follower.query().get(),
            ignore=['created', 'updated'])

#     def test_follow_multiple(self):
#         html = FOLLOW_HTML.replace(
#             '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>',
#             '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a> '
#             '<a class="u-follow-of" href="https://mas.to/mr-biff"></a>')

#         mock_get.side_effect = [
#             requests_response(
#                 html, url='https://user.com/follow',
#                 content_type=CONTENT_TYPE_HTML),
#             self.as2_resp({
#                 'objectType': 'Person',
#                 'displayName': 'Mr. ☕ Biff',
#                 'id': 'https://mas.to/mr-biff',
#                 'inbox': 'https://mas.to/inbox/biff',
#             }),
#             ACTOR,
#         ]
#         mock_post.return_value = requests_response('unused')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/follow',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/follow'),
#             self.as2_req('https://mas.to/mr-biff'),
#             self.as2_req('https://mas.to/mrs-foo'),
#         ))

#         calls = mock_post.call_args_list
#         self.assertEqual('https://mas.to/inbox', calls[0][0][0])
#         self.assertEqual(FOLLOW_AS2, json_loads(calls[0][1]['data']))
#         self.assertEqual('https://mas.to/inbox/biff', calls[1][0][0])
#         self.assertEqual({
#             **FOLLOW_AS2,
#             'object': 'https://mas.to/mr-biff',
#         }, json_loads(calls[1][1]['data']))

#         mf2 = util.parse_mf2(html)['items'][0]
#         as1 = microformats2.json_to_object(mf2)
#         obj = self.assert_object('https://user.com/follow',
#                                  users=[g.user.key],
#                                  source_protocol='web',
#                                  status='complete',
#                                  mf2=mf2,
#                                  as1=as1,
#                                  delivered=['https://mas.to/inbox',
#                                             'https://mas.to/inbox/biff'],
#                                  type='follow',
#                                  object_ids=['https://mas.to/mrs-foo',
#                                              'https://mas.to/mr-biff'],
#                                  labels=['user', 'activity'],
#                                  )

#         followers = Follower.query().fetch()
#         self.assertEqual(2, len(followers))

#         self.assertEqual(g.user.key, followers[0].from_)
#         self.assertEqual(ActivityPub(id='https://mas.to/mr-biff').key,
#                          followers[0].to)
#         self.assert_equals(obj.key, followers[0].follow)

#         self.assertEqual(g.user.key, followers[1].from_)
#         self.assertEqual(ActivityPub(id='https://mas.to/mrs-foo').key,
#                          followers[1].to)
#         self.assert_equals(obj.key, followers[1].follow)

#     def test_repost(self):
#         self._test_repost(REPOST_HTML, REPOST_AS2)

#     def test_repost_composite_hcite(self):
#         self._test_repost(REPOST_HCITE_HTML, REPOST_AS2)

#     def _test_repost(self, html, expected_as2):
#         self.make_followers()

#         mock_get.side_effect = [
#             requests_response(html, content_type=CONTENT_TYPE_HTML,
#                               url='https://user.com/repost'),
#             TOOT_AS2,
#             ACTOR,
#         ]
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/repost',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/repost'),
#             self.as2_req('https://mas.to/toot/id'),
#             self.as2_req('https://mas.to/author'),
#         ))

#         inboxes = ('https://inbox', 'https://public/inbox',
#                    'https://shared/inbox', 'https://mas.to/inbox')
#         self.assert_deliveries(mock_post, inboxes, expected_as2, ignore=['cc'])

#         for args, kwargs in mock_get.call_args_list[1:]:
#             with self.subTest(url=args[0]):
#                 rsa_key = kwargs['auth'].header_signer._rsa._key
#                 self.assertEqual(g.user.private_pem(), rsa_key.exportKey())

#         mf2 = util.parse_mf2(html)['items'][0]
#         self.assert_object('https://user.com/repost',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            status='complete',
#                            mf2=mf2,
#                            as1=microformats2.json_to_object(mf2),
#                            delivered=inboxes,
#                            type='share',
#                            object_ids=['https://mas.to/toot/id'],
#                            labels=['user', 'activity'],
#                            )

#     def test_redo_repost_isnt_update(self):
#         """Like and Announce shouldn't use Update, they should just resend as is."""
#         Object(id='https://user.com/repost', mf2={}, status='complete').put()

#         mock_get.side_effect = [REPOST, TOOT_AS2, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/repost',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)
#         self.assert_deliveries(mock_post, ['https://mas.to/inbox'], REPOST_AS2,
#                                ignore=['cc'])

    # def test_inbox_like(self):
    #     # Fake.fetchable['fake:post'] = {
    #     #     'objectType': 'note',
    #     # }

    #     like_as1 = {
    #         # 'id': 'http://mas.to/like#ok',
    #         'objectType': 'activity',
    #         'verb': 'like',
    #         'actor': 'fake:user',
    #         'object': 'fake:post',
    #     }
    #     self.assertEqual('OK', Fake.receive('fake:like', our_as1=like_as1))
    #     self.assertEqual({'fake:post:target': like_as1}, Fake.sent)

    #     self.assert_object('fake:like',
    #                        users=[g.user.key],
    #                        source_protocol='fake',
    #                        status='complete',
    #                        our_as1=like_as1,
    #                        delivered=['fake:post:target'],
    #                        type='like',
    #                        labels=['notification', 'activity'],
    #                        object_ids=['fake:post'])

#     def test_like_stored_object_without_as2(self):
#         Object(id='https://mas.to/toot', mf2=NOTE_MF2, source_protocol='ap').put()
#         Object(id='https://user.com/', mf2=ACTOR_MF2).put()
#         mock_get.side_effect = [
#             LIKE,
#         ]

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/like',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(204, got.status_code)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/like'),
#         ))
#         mock_post.assert_not_called()

#         self.assert_object('https://user.com/like',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            mf2=LIKE_MF2,
#                            as1=microformats2.json_to_object(LIKE_MF2),
#                            type='like',
#                            labels=['user', 'activity'],
#                            status='ignored',
#                            )

#     def test_create_author_only_url(self):
#         """Mf2 author property is just a URL. We should run full authorship.

#         https://indieweb.org/authorship
#         """
#         repost = requests_response("""\
# <html>
# <body class="h-entry">
# <a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
# <a class="u-author" href="https://user.com/"></a>
# <a href="http://localhost/"></a>
# </body>
# </html>
# """, url='https://user.com/repost', content_type=CONTENT_TYPE_HTML)
#         mock_get.side_effect = [repost, ACTOR, TOOT_AS2, ACTOR]
#         mock_post.return_value = requests_response('abc xyz')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/repost',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code)

#         args, kwargs = mock_post.call_args
#         self.assertEqual(('https://mas.to/inbox',), args)
#         self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

#     def test_delete(self):
#         mock_get.return_value = requests_response('"unused"', status=410,
#                                                   url='http://final/delete')
#         mock_post.return_value = requests_response('unused', status=200)
#         Object(id='https://user.com/post#bridgy-fed-create',
#                mf2=NOTE_MF2, status='complete').put()

#         self.make_followers()

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(200, got.status_code, got.text)

#         inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
#         self.assert_deliveries(mock_post, inboxes, DELETE_AS2)

#         self.assert_object('https://user.com/post#bridgy-fed-delete',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            status='complete',
#                            our_as1=DELETE_AS1,
#                            delivered=inboxes,
#                            type='delete',
#                            object_ids=['https://user.com/post'],
#                            labels=['user', 'activity'],
#                            )

#     def test_delete_no_object(self):
#         mock_get.side_effect = [
#             requests_response('"unused"', status=410, url='http://final/delete'),
#         ]
#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(304, got.status_code, got.text)
#         mock_post.assert_not_called()

#     def test_delete_incomplete_response(self):
#         mock_get.return_value = requests_response('"unused"', status=410,
#                                                   url='http://final/delete')

#         Object(id='https://user.com/post#bridgy-fed-create',
#                mf2=NOTE_MF2, status='in progress')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/post',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(304, got.status_code, got.text)
#         mock_post.assert_not_called()

#     def test_send_error(self):
#         mock_get.side_effect = [FOLLOW, ACTOR]
#         mock_post.return_value = requests_response(
#             'abc xyz', status=405, url='https://mas.to/inbox')

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/follow',
#             'target': 'https://fed.brid.gy/',
#         })
#         body = got.get_data(as_text=True)
#         self.assertEqual(502, got.status_code, body)
#         self.assertIn(
#             '405 Client Error: None for url: https://mas.to/inbox ; abc xyz',
#             body)

#         mock_get.assert_has_calls((
#             self.req('https://user.com/follow'),
#             self.as2_req('https://mas.to/mrs-foo'),
#         ))

#         self.assert_deliveries(mock_post, ['https://mas.to/inbox'], FOLLOW_AS2)

#         self.assert_object('https://user.com/follow',
#                            users=[g.user.key],
#                            source_protocol='web',
#                            status='failed',
#                            mf2=FOLLOW_MF2,
#                            as1=FOLLOW_AS1,
#                            failed=['https://mas.to/inbox'],
#                            type='follow',
#                            object_ids=['https://mas.to/mrs-foo'],
#                            labels=['user', 'activity'],
#                            )

#     def test_repost_twitter_blocklisted(self):
#         self._test_repost_blocklisted_error('https://twitter.com/foo')

#     def test_repost_bridgy_fed_blocklisted(self):
#         self._test_repost_blocklisted_error('https://fed.brid.gy/foo')

#     def _test_repost_blocklisted_error(self, orig_url):
#         """Reposts of non-fediverse (ie blocklisted) sites aren't yet supported."""
#         repost_html = REPOST_HTML.replace('https://mas.to/toot', orig_url)
#         repost_resp = requests_response(repost_html, content_type=CONTENT_TYPE_HTML,
#                                         url='https://user.com/repost')
#         mock_get.side_effect = [repost_resp]

#         got = self.client.post('/_ah/queue/webmention', data={
#             'source': 'https://user.com/repost',
#             'target': 'https://fed.brid.gy/',
#         })
#         self.assertEqual(204, got.status_code)
#         mock_post.assert_not_called()

#     def test_update_profile(self):
#         Follower.get_or_create(to=g.user, from_=self.alice)
#         Follower.get_or_create(to=g.user, from_=self.bob)

#         id = UPDATE_PROFILE['id']
#         Fake.receive(id, our_as1=UPDATE_PROFILE)
#         # self.assertEqual([(UPDATE_PROFILE, 'shared:target')], Fake.sent)

#         # profile object
#         self.assert_object('fake:user',
#                            source_protocol='fake',
#                            our_as1=UPDATE_PROFILE,
#                            type='person',
#                            )

#         # update activity
#         self.assert_object(id,
#                            users=[g.user.key],
#                            source_protocol='fake',
#                            status='complete',
#                            our_as1=UPDATE_PROFILE,
#                            delivered=['shared:target'],
#                            type='update',
#                            object_ids=['fake:user'],
#                            labels=['user', 'activity'],
#                            )

 #    def test_mention_object(self, *mocks):
 #        self._test_mention(
 #            MENTION_OBJECT,
 #            {
 #                'type': 'note',  # not mention (?)
 #                'labels': ['notification'],
 #            },
 #            *mocks,
 #        )

 #    def test_mention_create_activity(self, *mocks):
 #        self._test_mention(
 #            MENTION,
 #            {
 #                'type': 'post',  # not mention (?)
 #                'object_ids': [MENTION_OBJECT['id']],
 #                'labels': ['notification', 'activity'],
 #            },
 #            *mocks,
 #        )

 #        # redirect unwrap
 #        expected_as2 = copy.deepcopy(MENTION_OBJECT)
 #        expected_as2['tag'][1]['href'] = 'https://tar.get/'
 #        self.assert_object(MENTION_OBJECT['id'],
 #                           source_protocol='activitypub',
 #                           as2=expected_as2,
 #                           type='note')

 #    def _test_mention(self, mention, expected_props):
 #        self.make_user('tar.get')

 #        mock_get.side_effect = [
 #            self.as2_resp(ACTOR),
 #            requests_response(test_web.NOTE_HTML),
 #            requests_response(test_web.NOTE_HTML),
 #            WEBMENTION_DISCOVERY,
 #        ]
 #        mock_post.return_value = requests_response()

 #        got = self.post('/user.com/inbox', json=mention)
 #        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
 #        self.assert_req(mock_get, 'https://tar.get/')
 #        convert_id = mention['id'].replace('://', ':/')
 #        self.assert_req(
 #            mock_post,
 #            'https://tar.get/webmention',
 #            headers={'Accept': '*/*'},
 #            allow_redirects=False,
 #            data={
 #                'source': f'http://localhost/convert/activitypub/web/{convert_id}',
 #                'target': 'https://tar.get/',
 #            },
 #        )

 #        expected_as2 = common.redirect_unwrap(mention)
 #        self.assert_object(mention['id'],
 #                           users=[Web(id='tar.get').key],
 #                           source_protocol='activitypub',
 #                           status='complete',
 #                           as2=expected_as2,
 #                           delivered=['https://tar.get/'],
 #                           **expected_props)

 #    def test_follow_accept_with_id(self):
 #        eve_as1 = Fake.fetchable['fake:eve'] = {
 #            'id': 'fake:eve',
 #            'displayName': 'Eve',
 #        }

 #        # this should makes us make the follower ActivityPub as direct=True
 #        g.user.direct = False
 #        g.user.put()

 #        follow_as1 = {
 #            'id': 'fake:follow',
 #            'objectType': 'activity',
 #            'verb': 'follow',
 #            'actor': 'fake:eve',
 #            'object': 'fake:user',
 #        }
 #        self.assertEqual('OK', Fake.receive('fake:follow', our_as1=follow_as1))

 #        # check that we replied with accept and sent the follow
 #        accept_id = 'http://localhost/fa/fake:user/followers#accept-fake:follow'
 #        accept_as1 = {
 #            'id': accept_id,
 #            'objectType': 'activity',
 #            'verb': 'accept',
 #            'actor': 'fake:user',
 #            'object': {
 #                **follow_as1,
 #                'actor': {
 #                    'id': 'fake:eve',
 #                    'displayName': 'Eve',
 #                },
 #            },
 #        }

 #        [(sent_accept, accept_target)] = Fake.sent
 # #, (sent_follow, follow_target)
 #        self.assertEqual(accept_as1, sent_accept.as1)
 #        self.assertEqual('fake:eve:target', accept_target)
 #        # self.assertEqual(follow_as1, sent_follow.as1)
 #        # self.assertEqual('fake:user:target', follow_target)

 #        obj = self.assert_object('fake:follow',
 #                                 users=[g.user.key],
 #                                 source_protocol='fake',
 #                                 status='complete',
 #                                 our_as1=follow_as1,
 #                                 delivered=['fake:user'],
 #                                 type='follow',
 #                                 labels=['notification', 'activity'],
 #                                 object_ids=['fake:user'])

 #        # check that we stored new User and Follower
 #        eve = self.assert_user(Fake, 'fake:eve', obj_as1=eve_as1, direct=True)
 #        self.assert_entities_equal(
 #            Follower(to=g.user.key, from_=eve.key, follow=obj.key, status='active'),
 #            Follower.query().fetch(),
 #            ignore=['created', 'updated'])

 #    def test_follow_accept_with_object(self):
 #        unwrapped_user = {
 #            'id': FOLLOW['object'],
 #            'url': FOLLOW['object'],
 #        }
 #        follow = {
 #            **FOLLOW,
 #            'object': unwrapped_user,
 #        }
 #        accept = copy.deepcopy(ACCEPT)
 #        accept['object']['object'] = unwrapped_user

 #        # this should makes us make the follower ActivityPub as direct=True
 #        g.user.direct = False
 #        g.user.put()

 #        mock_head.return_value = requests_response(url='https://user.com/')
 #        mock_get.side_effect = [
 #            # source actor
 #            self.as2_resp(ACTOR),
 #            WEBMENTION_DISCOVERY,
 #        ]
 #        if not mock_post.return_value and not mock_post.side_effect:
 #            mock_post.return_value = requests_response()

 #        got = self.post('/user.com/inbox', json=follow)
 #        self.assertEqual(200, got.status_code)

 #        mock_get.assert_has_calls((
 #            self.as2_req(FOLLOW['actor']),
 #        ))

 #        # check AP Accept
 #        self.assertEqual(2, len(mock_post.call_args_list))
 #        args, kwargs = mock_post.call_args_list[0]
 #        self.assertEqual(('http://mas.to/inbox',), args)

 #        accept['object']['actor']['@context'] = 'https://www.w3.org/ns/activitystreams'
 #        self.assertEqual(accept, json_loads(kwargs['data']))

 #        # check webmention
 #        args, kwargs = mock_post.call_args_list[1]
 #        self.assertEqual(('https://user.com/webmention',), args)
 #        self.assertEqual({
 #            'source': 'http://localhost/convert/activitypub/web/https:/mas.to/6d1a',
 #            'target': 'https://user.com/',
 #        }, kwargs['data'])

 #        # check that we stored Follower and ActivityPub user for the follower
 #        self.assert_entities_equal(
 #            Follower(to=g.user.key,
 #                     from_=ActivityPub(id=ACTOR['id']).key,
 #                     status='active',
 #                     follow=Object(id=FOLLOW['id']).key),
 #            Follower.query().fetch(),
 #            ignore=['created', 'updated'])

 #        self.assert_user(ActivityPub, ACTOR['id'],
 #                         obj_as2=ACCEPT_FOLLOW['actor'],
 #                         direct=True)

 #        follow.update({
 #            'actor': ACTOR,
 #            'url': 'https://mas.to/users/swentel#followed-https://user.com/',
 #        })
 #        self.assert_object('https://mas.to/6d1a',
 #                           users=[g.user.key],
 #                           source_protocol='activitypub',
 #                           status='complete',
 #                           as2=follow,
 #                           delivered=['https://user.com/'],
 #                           type='follow',
 #                           labels=['notification', 'activity'],
 #                           object_ids=[FOLLOW['object']])

    def test_follow_inactive(self):
        follower = Follower.get_or_create(to=g.user, from_=self.alice,
                                          status='inactive')
        Fake.fetchable['fake:alice'] = {}

        self.assertEqual('OK', Fake.receive('fake:follow', our_as1={
            'id': 'fake:follow',
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))

        # check that the Follower is now active
        self.assertEqual('active', follower.key.get().status)

    def test_undo_follow(self):
        follower = Follower.get_or_create(to=g.user, from_=self.alice)
        Fake.fetchable['fake:alice'] = {}

        self.assertEqual('OK', Fake.receive('fake:undo-follow', our_as1={
            'id': 'fake:undo-follow',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))

        self.assertEqual('inactive', follower.key.get().status)

    def test_undo_follow_doesnt_exist(self):
        self.assertEqual('OK', Fake.receive('fake:undo-follow', our_as1={
            'id': 'fake:undo-follow',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))
        # it's a noop
        self.assertEqual(0, Follower.query().count())

    def test_undo_follow_inactive(self):
        follower = Follower.get_or_create(to=g.user, from_=self.alice,
                                          status='inactive')
        Fake.fetchable['fake:alice'] = {}

        self.assertEqual('OK', Fake.receive('fake:undo-follow', our_as1={
            'id': 'fake:undo-follow',
            'objectType': 'activity',
            'verb': 'stop-following',
            'actor': 'fake:alice',
            'object': 'fake:user',
        }))
        self.assertEqual('inactive', follower.key.get().status)

    def test_delete_actor(self):
        follower = Follower.get_or_create(to=g.user, from_=self.alice)
        followee = Follower.get_or_create(to=self.alice, from_=self.bob)
        other = Follower.get_or_create(to=g.user, from_=self.bob)
        self.assertEqual(3, Follower.query().count())

        self.assertEqual('OK', Fake.receive('fake:delete', our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'id': 'fake:delete',
            'object': 'fake:alice',
        }))

        self.assertEqual(3, Follower.query().count())
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)
