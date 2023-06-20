"""Unit tests for pages.py."""
from granary import atom, microformats2, rss
from granary.tests.test_as1 import (
    ACTOR,
    COMMENT,
    NOTE,
)
from oauth_dropins.webutil import util

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from activitypub import ActivityPub
from models import Object, Follower

from .test_web import ACTOR_AS2, REPOST_AS2

ACTOR_WITH_PREFERRED_USERNAME = {
    **ACTOR,
    'preferredUsername': 'me',
}


def contents(activities):
    return [(a.get('object') or a)['content'] for a in activities]


class PagesTest(TestCase):
    EXPECTED = contents([COMMENT, NOTE])

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com')

    def test_user(self):
        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fa/foo.com')
        self.assert_equals(200, got.status_code)

    def test_user_readable_id_activitypub_address(self):
        user = self.make_user('foo', cls=ActivityPub,
                              obj_as2=ACTOR_WITH_PREFERRED_USERNAME)
        self.assertEqual('@me@plus.google.com', user.ap_address())

        got = self.client.get('/ap/@me@plus.google.com')
        self.assert_equals(200, got.status_code)

        got = self.client.get('/ap/foo')
        self.assert_equals(302, got.status_code)
        self.assert_equals('/ap/@me@plus.google.com', got.headers['Location'])

    def test_user_web_custom_username_doesnt_redirect(self):
        """https://github.com/snarfed/bridgy-fed/issues/534"""
        self.user.obj = Object(id='a', as2={
            **ACTOR_AS2,
            'url': 'acct:baz@user.com',
        })
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
        got = self.client.get('/web/user.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED,
                           contents(microformats2.html_to_activities(got.text)))

    def test_feed_atom_empty(self):
        got = self.client.get('/web/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(atom.atom_to_activities(got.text)))

    def test_feed_rss_empty(self):
        got = self.client.get('/web/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_objects()
        got = self.client.get('/web/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))

    def test_nodeinfo(self):
        # just check that it doesn't crash
        self.client.get('/nodeinfo.json')
