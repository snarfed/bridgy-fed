"""Unit tests for pages.py."""
from unittest import skip
from unittest.mock import patch

import arroba.server
import copy
from flask import get_flashed_messages
from google.cloud import ndb
from google.cloud.tasks_v2.types import Task
from granary import atom, microformats2, rss
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import requests_response
from requests import ConnectionError

# import first so that Fake is defined before URL routes are registered
from .testutil import (
    Fake,
    ExplicitFake,
    OtherFake,
    TestCase,
    ACTOR,
    COMMENT,
    MENTION,
    NOTE,
)

from activitypub import ActivityPub
from atproto import ATProto
import common
from models import Object, Follower, Target
from web import Web

from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_BSKY
from .test_atproto import DID_DOC
from .test_web import (
    ACTOR_AS1_UNWRAPPED_URLS,
    ACTOR_AS2,
    ACTOR_HTML,
    ACTOR_HTML_RESP,
    ACTOR_MF2_REL_URLS,
    REPOST_AS2,
)

ACTOR_WITH_PREFERRED_USERNAME = {
    'objectType': 'person',
    'displayName': 'Me',
    'username': 'me',
    'url': 'https://plus.google.com/bob',
    'image': 'http://pic',
}


def contents(activities):
    return [
        ' '.join(util.parse_html((a.get('object') or a)['content']).get_text().split())
        for a in activities]


class PagesTest(TestCase):
    EXPECTED = contents([COMMENT, MENTION, NOTE])
    EXPECTED_SNIPPETS = [
        'Dr. Eve replied a comment',
        'tag:fake.com:44... posted a mention',
        '🌐 user.com posted my note',
    ]

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com', cls=Web, has_redirects=True)

    def test_user(self):
        got = self.client.get('/web/user.com', base_url='https://fed.brid.gy/')
        self.assert_equals(200, got.status_code)

    def test_user_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo')
        self.assert_equals(200, got.status_code)

    def test_user_page_handle_activitypub(self):
        user = self.make_user('http://fo/o', cls=ActivityPub,
                              enabled_protocols=['fake'],
                              obj_as1=ACTOR_WITH_PREFERRED_USERNAME)
        self.assertEqual('@me@fo', user.handle_as(ActivityPub))

        got = self.client.get('/ap/@me@fo')
        self.assert_equals(200, got.status_code)

        # TODO: can't handle slashes in id segment of path. is that ok?
        # got = self.client.get('/ap/http%3A//foo')
        # self.assert_equals(302, got.status_code)
        # self.assert_equals('/ap/@me@plus.google.com', got.headers['Location'])

    def test_user_page_handle_atproto(self):
        self.store_object(id='did:plc:user', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://han.dull'],
        })
        user = self.make_user('did:plc:user', cls=ATProto, enabled_protocols=['fake'])

        got = self.client.get('/bsky/@han.dull')
        self.assert_equals(200, got.status_code)

        got = self.client.get('/bsky/han.dull')
        self.assert_equals(200, got.status_code)

    def test_user_web_custom_username_doesnt_redirect(self):
        """https://github.com/snarfed/bridgy-fed/issues/534"""
        self.user.obj = Object(id='a', as2={
            **ACTOR_AS2,
            'url': 'acct:baz@user.com',
        })
        self.user.obj.put()
        self.user.put()
        self.assertEqual('baz', self.user.username())

        got = self.client.get('/web/@baz@user.com')
        self.assert_equals(404, got.status_code)

        got = self.client.get('/web/baz')
        self.assert_equals(404, got.status_code)

        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)
        self.assertIn('@baz@user.com', got.get_data(as_text=True))

    def test_user_www_domain_special_case(self):
        """https://github.com/snarfed/bridgy-fed/issues/1244"""
        www = self.make_user('www.jvt.me', cls=Web)

        got = self.client.get('/web/www.jvt.me')
        self.assert_equals(200, got.status_code)

    def test_user_objects(self):
        self.add_objects()
        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_not_found(self):
        got = self.client.get('/web/bar.com')
        self.assert_equals(404, got.status_code)

    def test_user_opted_out(self):
        self.user.obj.our_as1 = {'summary': '#nobridge'}
        self.user.obj.put()
        got = self.client.get('/web/user.com')
        self.assert_equals(404, got.status_code)

    def test_user_handle_opted_out(self):
        user = self.make_user('fake:user', cls=Fake, manual_opt_out=True)
        got = self.client.get('/fa/fake:handle:user')
        self.assert_equals(404, got.status_code)

    def test_user_default_serve_false_no_enabled_protocols(self):
        self.make_user('other:foo', cls=OtherFake)
        got = self.client.get('/other/other:foo')
        self.assert_equals(404, got.status_code)

    def test_user_default_serve_false_enabled_protocols(self):
        self.make_user('other:foo', cls=OtherFake, enabled_protocols=['fake'])
        got = self.client.get('/other/other:foo')
        self.assert_equals(200, got.status_code)

    def test_user_web_redirect(self):
        got = self.client.get('/user/user.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

    def test_user_use_instead(self):
        self.make_user('bar.com', cls=Web, use_instead=self.user.key)

        got = self.client.get('/web/bar.com')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_object_bare_string_id(self):
        Object(id='a', users=[self.user.key], labels=['notification'],
               as2=REPOST_AS2).put()

        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_object_url_object(self):
        with self.request_context:
            Object(id='a', users=[self.user.key], labels=['notification'], our_as1={
                **REPOST_AS2,
                'object': {
                    'id': 'https://mas.to/toot/id',
                    'url': {'value': 'http://foo', 'displayName': 'bar'},
                },
            }).put()

        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_before(self):
        self.add_objects()
        got = self.client.get(f'/web/user.com?before={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_user_after(self):
        self.add_objects()
        got = self.client.get(f'/web/user.com?after={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_user_before_bad(self):
        self.add_objects()
        got = self.client.get('/web/user.com?before=nope')
        self.assert_equals(400, got.status_code)

    def test_user_before_and_after(self):
        self.add_objects()
        got = self.client.get('/web/user.com?before=2024-01-01+01:01:01&after=2023-01-01+01:01:01')
        self.assert_equals(400, got.status_code)

    def test_user_protocol_bot_user(self):
        bot = self.make_user(id='fa.brid.gy', cls=Web)
        got = self.client.get(f'/web/fa.brid.gy')
        self.assert_equals(404, got.status_code)

    def test_update_profile(self):
        self.make_user('fake:user', cls=Fake)

        actor = {
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Ms User',
        }
        Fake.fetchable = {'fake:profile:user': actor}
        got = self.client.post('/fa/fake:user/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/fa/fake:handle:user', got.headers['Location'])
        self.assertEqual(
            ['Updating profile from <a href="web:fake:user">fake:handle:user</a>...'],
            get_flashed_messages())

        self.assertEqual(['fake:profile:user'], Fake.fetched)

        actor['updated'] = '2022-01-02T03:04:05+00:00'
        self.assert_object('fake:user', source_protocol='fake', our_as1=actor)

    @patch.object(Fake, 'fetch', side_effect=ConnectionError('foo'))
    def test_update_profile_load_fails(self, _):
        self.make_user('fake:user', cls=Fake)

        got = self.client.post('/fa/fake:user/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/fa/fake:handle:user', got.headers['Location'])
        self.assertEqual(
            ['Couldn\'t update profile for <a href="web:fake:user">fake:handle:user</a>: foo'],
            get_flashed_messages())

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_update_profile_receive_task(self, mock_create_task):
        common.RUN_TASKS_INLINE = False

        user = self.make_user('fake:user', cls=Fake)

        Fake.fetchable = {'fake:profile:user': {
            'objectType': 'person',
            'id': 'fake:user',
            'displayName': 'Ms User',
        }}

        # use handle in URL to check that we use key id as authed_as below
        got = self.client.post('/fa/fake:handle:user/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/fa/fake:handle:user', got.headers['Location'])

        self.assert_equals(['fake:profile:user'], Fake.fetched)
        self.assert_task(mock_create_task, 'receive', obj_id='fake:profile:user',
                         authed_as='fake:user')

    @patch('requests.get', return_value=ACTOR_HTML_RESP)
    def test_update_profile_web(self, mock_get):
        self.user.obj.copies = [
            Target(protocol='fake', uri='fa:profile:web:user.com'),
            Target(protocol='other', uri='other:profile:web:user.com'),
        ]
        self.user.enabled_protocols = ['other']
        self.user.obj.put()
        Follower.get_or_create(from_=self.make_user('fake:user', cls=Fake),
                               to=self.user)

        got = self.client.post('/web/user.com/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

        user = self.user.key.get()
        self.assertIsNone(user.status)
        expected_mf2 = copy.deepcopy(ACTOR_MF2_REL_URLS)
        expected_mf2['rel-urls']['https://user.com/webmention'] = {
            'rels': ['webmention'],
            'text': '',
        }
        self.assertEqual(expected_mf2, user.obj.mf2)

        actor_as1 = {
            **ACTOR_AS1_UNWRAPPED_URLS,
            'updated': '2022-01-02T03:04:05+00:00',
        }
        self.assertEqual([('fake:shared:target', {
            'objectType': 'activity',
            'verb': 'update',
            'id': 'https://user.com/#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            'actor': actor_as1,
            'object': actor_as1,
        })], Fake.sent)

        self.assertEqual({'user.com': 'user.com'}, OtherFake.usernames)

    @patch('requests.get', return_value=requests_response(
        ACTOR_HTML, url='https://www.user.com/'))
    def test_update_profile_web_www(self, mock_get):
        self.user.obj.copies = [
            Target(protocol='fake', uri='fa:profile:web:user.com'),
        ]
        self.user.obj.put()
        Follower.get_or_create(from_=self.make_user('fake:user', cls=Fake),
                               to=self.user)

        got = self.client.post('/web/user.com/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

        actor_as1 = {
            **ACTOR_AS1_UNWRAPPED_URLS,
            'updated': '2022-01-02T03:04:05+00:00',
        }
        self.assertEqual([('fake:shared:target', {
            'objectType': 'activity',
            'verb': 'update',
            'id': 'https://user.com/#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            'actor': actor_as1,
            'object': actor_as1,
        })], Fake.sent)

    @patch('requests.get', return_value=requests_response(
        ACTOR_HTML.replace('Ms. ☕ Baz', 'Ms. ☕ Baz #nobridge'),
        url='https://user.com/'))
    def test_update_profile_web_delete(self, mock_get):
        self.user.obj.copies = [Target(protocol='fake', uri='fa:profile:web:user.com')]
        self.user.obj.put()
        Follower.get_or_create(from_=self.make_user('fake:user', cls=Fake),
                               to=self.user)

        got = self.client.post('/web/user.com/update-profile')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

        user = self.user.key.get()
        self.assertEqual('opt-out', user.status)
        self.assertEqual([('fake:shared:target', {
            'objectType': 'activity',
            'verb': 'delete',
            'id': 'https://user.com/#bridgy-fed-delete-user-all-2022-01-02T03:04:05+00:00',
            'actor': 'user.com',
            'object': 'user.com',
        })], Fake.sent)

    def test_followers(self):
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://un/used', cls=ActivityPub, obj_as1={
                **ACTOR,
                'id': 'http://un/used',
                'url': 'http://stored/users/follow',
            }))
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://masto/user', cls=ActivityPub,
                                 obj_as1=ACTOR_WITH_PREFERRED_USERNAME))

        from models import PROTOCOLS
        got = self.client.get('/web/user.com/followers')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('@follow@stored', body)
        self.assertIn('@me@masto', body)

    def test_home_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo/home')
        self.assert_equals(200, got.status_code)

    def test_home_objects(self):
        self.add_objects()
        got = self.client.get('/web/user.com/home')
        self.assert_equals(200, got.status_code)

    def test_notifications_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo/notifications')
        self.assert_equals(200, got.status_code)

    def test_notifications_objects(self):
        self.add_objects()
        got = self.client.get('/web/user.com/notifications')
        self.assert_equals(200, got.status_code)

    def test_notifications_rss(self):
        self.add_objects()
        got = self.client.get('/web/user.com/notifications?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(rss.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals(self.EXPECTED_SNIPPETS,
                           contents(rss.to_activities(got.text)))

    def test_notifications_atom(self):
        self.add_objects()
        got = self.client.get('/web/user.com/notifications?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(atom.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals(self.EXPECTED_SNIPPETS,
                           contents(atom.atom_to_activities(got.text)))

    def test_notifications_html(self):
        self.add_objects()
        got = self.client.get('/web/user.com/notifications?format=html')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED_SNIPPETS,
                           contents(microformats2.html_to_activities(got.text)))

    def test_followers_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo/followers')
        self.assert_equals(200, got.status_code)

    def test_followers_activitypub(self):
        user = self.make_user('https://inst/user', cls=ActivityPub,
                              enabled_protocols=['fake'],
                              obj_as1=ACTOR_WITH_PREFERRED_USERNAME)

        got = self.client.get('/ap/@me@inst/followers')
        self.assert_equals(200, got.status_code)
        self.assert_equals('text/html', got.headers['Content-Type'].split(';')[0])

    def test_followers_empty(self):
        got = self.client.get('/web/user.com/followers')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_followers_user_not_found(self):
        got = self.client.get('/web/nope.com/followers')
        self.assert_equals(404, got.status_code)

    def test_followers_redirect(self):
        got = self.client.get('/user/user.com/followers')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/followers', got.headers['Location'])

    def test_following(self):
        Follower.get_or_create(
            from_=self.user,
            to=self.make_user('http://un/used', cls=ActivityPub, obj_as1={
                **ACTOR,
                'id': 'http://un/used',
                'url': 'http://stored/users/follow',
            }))
        Follower.get_or_create(
            from_=self.user,
            to=self.make_user('http://masto/user', cls=ActivityPub,
                              obj_as1=ACTOR_WITH_PREFERRED_USERNAME))

        got = self.client.get('/web/user.com/following')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('@follow@stored', body)
        self.assertIn('@me@masto', body)

    def test_following_empty(self):
        got = self.client.get('/web/user.com/following')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_following_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo/following')
        self.assert_equals(200, got.status_code)

    def test_following_user_not_found(self):
        got = self.client.get('/web/nope.com/following')
        self.assert_equals(404, got.status_code)

    def test_following_redirect(self):
        got = self.client.get('/user/user.com/following')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/following', got.headers['Location'])

    def test_following_before_empty(self):
        got = self.client.get(f'/web/user.com/following?before={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_following_after_empty(self):
        got = self.client.get(f'/web/user.com/following?after={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_feed_user_not_found(self):
        got = self.client.get('/web/nope.com/feed')
        self.assert_equals(404, got.status_code)

    def test_feed_web_redirect(self):
        got = self.client.get('/user/user.com/feed')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/feed', got.headers['Location'])

    def test_feed_fake(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.get('/fake/fake:foo/feed')
        self.assert_equals(200, got.status_code)

    def test_feed_html_empty(self):
        got = self.client.get('/web/user.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], microformats2.html_to_activities(got.text))

    def test_feed_html(self):
        self.add_objects()

        # repost with object (original post) in separate Object
        repost = {
            'objectType': 'activity',
            'verb': 'share',
            'object': 'fake:orig',
        }
        orig = {
            'objectType': 'note',
            'content': 'biff',
        }
        self.store_object(id='fake:repost', feed=[self.user.key], our_as1=repost)
        self.store_object(id='fake:orig', our_as1=orig)

        got = self.client.get('/web/user.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals(['biff'] + self.EXPECTED,
                           contents(microformats2.html_to_activities(got.text)))

        # NOTE's and MENTION's authors; check for two instances
        bob = '<a class="p-name u-url" href="https://plus.google.com/bob">Bob</a>'
        assert got.text.index(bob) != got.text.rindex(bob)

    def test_feed_atom_empty(self):
        got = self.client.get('/web/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(atom.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom_empty_g_user_without_obj(self):
        self.user.obj_key = None
        self.user.put()
        self.test_feed_atom_empty()

    def test_feed_atom(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(atom.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals(self.EXPECTED, contents(atom.atom_to_activities(got.text)))

        # NOTE's and MENTION's authors; check for two instances
        bob = """
 <uri>https://plus.google.com/bob</uri>
 
 <name>Bob</name>
"""
        assert got.text.index(bob) != got.text.rindex(bob)
        # COMMENT's author
        self.assertIn('Dr. Eve', got.text)

    def test_feed_rss_empty(self):
        got = self.client.get('/web/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(rss.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(rss.CONTENT_TYPE, got.headers['Content-Type'])
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))

        # NOTE's and MENTION's authors; check for two instances
        bob = '<author>_@_._ (Bob)</author>'
        self.assertIn(bob, got.text)
        self.assertNotEqual(got.text.index(bob), got.text.rindex(bob), got.text)
        # COMMENT's author
        self.assertIn('<author>_@_._ (Dr. Eve)</author>', got.text, got.text)

    def test_nodeinfo(self):
        # just check that it doesn't crash
        self.client.get('/nodeinfo.json')

    def test_instance_info(self):
        # just check that it doesn't crash
        self.client.get('/api/v1/instance')

    def test_canonicalize_domain(self):
        got = self.client.get('/', base_url='https://ap.brid.gy/')
        self.assert_equals(301, got.status_code)
        self.assert_equals('https://fed.brid.gy/', got.headers['Location'])

    def test_find_user_page_web_domain(self):
        got = self.client.post('/user-page', data={'id': 'user.com'})
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

    def test_find_user_page_fake_id(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.post('/user-page', data={'id': 'fake:foo'})
        self.assert_equals(302, got.status_code)
        self.assert_equals('/fa/fake:handle:foo', got.headers['Location'])

    def test_find_user_page_fake_handle(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.post('/user-page', data={'id': 'fake:handle:foo'})
        self.assert_equals(302, got.status_code)
        self.assert_equals('/fa/fake:handle:foo', got.headers['Location'])

    def test_find_user_page_unknown_protocol(self):
        self.make_user('fake:foo', cls=Fake)
        got = self.client.post('/user-page', data={'id': 'un:kn:own'})
        self.assert_equals(404, got.status_code)
        self.assertEqual(["Couldn't determine network for un:kn:own."],
                         get_flashed_messages())

    def test_find_user_page_fake_not_found(self):
        got = self.client.post('/user-page', data={'id': 'fake:foo'})
        self.assert_equals(404, got.status_code)
        self.assertEqual(["User fake:foo on fake-phrase isn't signed up."],
                         get_flashed_messages())

    def test_find_user_page_other_not_enabled(self):
        self.make_user('other:foo', cls=OtherFake)
        got = self.client.post('/user-page', data={'id': 'other:foo'})
        self.assert_equals(404, got.status_code)
        self.assertEqual(["User other:foo on other-phrase isn't signed up."],
                         get_flashed_messages())
