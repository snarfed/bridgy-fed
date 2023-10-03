"""Unit tests for pages.py."""
from unittest.mock import patch

import arroba.server
from flask import get_flashed_messages
from google.cloud import ndb
from google.cloud.tasks_v2.types import Task
from granary import atom, microformats2, rss
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase, ACTOR, COMMENT, MENTION, NOTE

from activitypub import ActivityPub
from models import Object, Follower, Target
from web import Web

from granary.tests.test_bluesky import ACTOR_AS, ACTOR_PROFILE_BSKY
from .test_web import ACTOR_AS2, REPOST_AS2

ACTOR_WITH_PREFERRED_USERNAME = {
    **ACTOR,
    'preferredUsername': 'me',
}


def contents(activities):
    return [util.parse_html((a.get('object') or a)['content'].splitlines()[0]
                            ).get_text().strip()
            for a in activities]


class PagesTest(TestCase):
    EXPECTED = contents([COMMENT, NOTE, NOTE])

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com')

    def test_user(self):
        got = self.client.get('/web/user.com', base_url='https://fed.brid.gy/')
        self.assert_equals(200, got.status_code)

    def test_user_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fa/foo.com')
        self.assert_equals(200, got.status_code)

    def test_user_page_handle(self):
        user = self.make_user('http://foo', cls=ActivityPub,
                              obj_as2=ACTOR_WITH_PREFERRED_USERNAME)
        self.assertEqual('@me@plus.google.com', user.ap_address())

        got = self.client.get('/ap/@me@plus.google.com')
        self.assert_equals(200, got.status_code)

        # TODO: can't handle slashes in id segment of path. is that ok?
        # got = self.client.get('/ap/http%3A//foo')
        # self.assert_equals(302, got.status_code)
        # self.assert_equals('/ap/@me@plus.google.com', got.headers['Location'])

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

    def test_user_objects(self):
        self.add_objects()
        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_not_found(self):
        got = self.client.get('/web/bar.com')
        self.assert_equals(404, got.status_code)

    def test_user_not_direct(self):
        self.user.direct = False
        self.user.put()
        got = self.client.get('/web/user.com')
        self.assert_equals(404, got.status_code)

    def test_user_web_redirect(self):
        got = self.client.get('/user/user.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

    def test_user_use_instead(self):
        self.make_user('bar.com', use_instead=self.user.key)

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

    def test_followers(self):
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('unused', cls=Fake, obj_as2={
                **ACTOR,
                'id': 'unused',
                'url': 'http://stored/users/follow',
            }))
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('masto/user', cls=Fake,
                                 obj_as2=ACTOR_WITH_PREFERRED_USERNAME))

        got = self.client.get('/web/user.com/followers')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('@follow@stored', body)
        self.assertIn('@me@plus.google.com', body)

    def test_followers_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fa/foo.com/followers')
        self.assert_equals(200, got.status_code)

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
            to=self.make_user('unused', cls=Fake, obj_as2={
                **ACTOR,
                'id': 'unused',
                'url': 'http://stored/users/follow',
            }))
        Follower.get_or_create(
            from_=self.user,
            to=self.make_user('masto/user', cls=Fake,
                              obj_as2=ACTOR_WITH_PREFERRED_USERNAME))

        got = self.client.get('/web/user.com/following')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('@follow@stored', body)
        self.assertIn('masto/user', body)

    def test_following_empty(self):
        got = self.client.get('/web/user.com/following')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_following_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fa/foo.com/following')
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
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fa/foo.com/feed')
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
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
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
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))

        # NOTE's and MENTION's authors; check for two instances
        bob = '<author>- (Bob)</author>'
        assert got.text.index(bob) != got.text.rindex(bob)
        # COMMENT's author
        self.assertIn('Dr. Eve', got.text)

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    @patch('requests.post',
           return_value=requests_response('OK'))  # create DID on PLC
    def test_bridge_user(self, mock_post, mock_create_task):
        Fake.fetchable = {'fake:user': ACTOR_AS}

        got = self.client.post('/bridge-user', data={'handle': 'fake:handle:user'})
        self.assertEqual(200, got.status_code)
        self.assertEqual(
            ['Bridging fake:handle:user into Bluesky. <a href="https://bsky.app/search">Try searching for them</a> in a minute!'],
            get_flashed_messages())

        # check user, repo
        user = Fake.get_by_id('fake:user')
        self.assertEqual('fake:handle:user', user.handle)
        self.assertEqual([Target(uri=user.atproto_did, protocol='atproto')],
                         user.copies)
        repo = arroba.server.storage.load_repo(user.atproto_did)

        # check profile
        profile = repo.get_record('app.bsky.actor.profile', 'self')
        self.assertEqual({
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
            'description': 'hi there',
        }, profile)

        at_uri = f'at://{user.atproto_did}/app.bsky.actor.profile/self'
        self.assertEqual([Target(uri=at_uri, protocol='atproto')],
                         Object.get_by_id(id='fake:user').copies)

        mock_create_task.assert_called()

    def test_bridge_user_bad_handle(self):
        got = self.client.post('/bridge-user', data={'handle': 'bad xyz'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(["Couldn't determine protocol for bad xyz"],
                         get_flashed_messages())

    def test_nodeinfo(self):
        # just check that it doesn't crash
        self.client.get('/nodeinfo.json')
