"""Unit tests for pages.py."""
from granary import as2, atom, microformats2, rss
from granary.tests.test_bluesky import REPLY_BSKY
from granary.tests.test_as1 import (
    ACTOR,
    COMMENT,
    FOLLOW_WITH_ACTOR,
    FOLLOW_WITH_OBJECT,
    LIKE,
    NOTE,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from activitypub import ActivityPub
import common
from models import Object, Follower, User
from web import Web

from .test_web import ACTOR_AS2, ACTOR_HTML, ACTOR_MF2, REPOST_AS2

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
        got = self.client.get('/fake/foo.com')
        self.assert_equals(200, got.status_code)

    def test_user_activitypub_address(self):
        user = self.make_user('foo', cls=ActivityPub,
                              actor_as2=ACTOR_WITH_PREFERRED_USERNAME)
        self.assertEqual('@me@plus.google.com', user.address)

        got = self.client.get('/activitypub/@me@plus.google.com')
        self.assert_equals(200, got.status_code)

        got = self.client.get('/activitypub/foo')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/activitypub/@me@plus.google.com', got.headers['Location'])

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

    def test_user_redirect(self):
        got = self.client.get('/user/user.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

    def test_user_use_instead(self):
        bar = self.make_user('bar.com')
        bar.use_instead = self.user.key
        bar.put()

        got = self.client.get('/web/bar.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

    def test_user_object_bare_string_id(self):
        with self.request_context:
            Object(id='a', domains=['user.com'], labels=['notification'],
                   as2=REPOST_AS2).put()

        got = self.client.get('/web/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_object_url_object(self):
        with self.request_context:
            Object(id='a', domains=['user.com'], labels=['notification'], our_as1={
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
        self.make_user('bar.com')
        Follower.get_or_create('bar.com', 'https://no.stored/users/follow')
        Follower.get_or_create('bar.com', 'https://masto/user', last_follow={
            **FOLLOW_WITH_ACTOR,
            'actor': ACTOR_WITH_PREFERRED_USERNAME,
        })
        got = self.client.get('/web/bar.com/followers')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('@follow@no.stored', body)
        self.assertIn('@me@plus.google.com', body)

    def test_followers_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fake/foo.com/followers')
        self.assert_equals(200, got.status_code)

    def test_followers_empty(self):
        self.make_user('bar.com')
        got = self.client.get('/web/bar.com/followers')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_followers_user_not_found(self):
        got = self.client.get('/web/bar.com/followers')
        self.assert_equals(404, got.status_code)

    def test_followers_redirect(self):
        got = self.client.get('/user/user.com/followers')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/followers', got.headers['Location'])

    def test_following(self):
        Follower.get_or_create('https://no/stored/follow', 'bar.com')
        Follower.get_or_create('https://masto/user', 'bar.com',
                               last_follow=FOLLOW_WITH_OBJECT)
        self.make_user('bar.com')
        got = self.client.get('/web/bar.com/following')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('no/stored/follow', body)
        self.assertIn('masto/user', body)

    def test_following_empty(self):
        self.make_user('bar.com')
        got = self.client.get('/web/bar.com/following')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_following_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fake/foo.com/following')
        self.assert_equals(200, got.status_code)

    def test_following_user_not_found(self):
        got = self.client.get('/web/bar.com/following')
        self.assert_equals(404, got.status_code)

    def test_following_redirect(self):
        got = self.client.get('/user/user.com/following')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/following', got.headers['Location'])

    def test_following_before_empty(self):
        self.make_user('bar.com')
        got = self.client.get(f'/web/bar.com/following?before={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_following_after_empty(self):
        self.make_user('bar.com')
        got = self.client.get(f'/web/bar.com/following?after={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_feed_user_not_found(self):
        got = self.client.get('/web/bar.com/feed')
        self.assert_equals(404, got.status_code)

    def test_feed_web_redirect(self):
        got = self.client.get('/user/user.com/feed')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/web/user.com/feed', got.headers['Location'])

    def test_feed_fake(self):
        self.make_user('foo.com', cls=Fake)
        got = self.client.get('/fake/foo.com/feed')
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
