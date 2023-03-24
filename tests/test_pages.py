"""Unit tests for pages.py."""
from unittest.mock import patch

from flask import get_flashed_messages
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

from app import app
import common
from models import Object, Follower, User
from . import testutil
from .test_webmention import ACTOR_AS2, ACTOR_HTML, ACTOR_MF2, REPOST_AS2


def contents(activities):
    return [(a.get('object') or a)['content'] for a in activities]


class PagesTest(testutil.TestCase):
    EXPECTED = contents([COMMENT, NOTE])

    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com')

    def test_user(self):
        got = self.client.get('/user/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_objects(self):
        self.add_objects()
        got = self.client.get('/user/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_not_found(self):
        got = self.client.get('/user/bar.com')
        self.assert_equals(404, got.status_code)

    def test_user_use_instead(self):
        bar = self.make_user('bar.com')
        bar.use_instead = self.user.key
        bar.put()

        got = self.client.get('/user/bar.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/user/user.com', got.headers['Location'])

    def test_user_object_bare_string_id(self):
        with app.test_request_context('/'):
            Object(id='a', domains=['user.com'], labels=['notification'],
                   as2=REPOST_AS2).put()

        got = self.client.get('/user/user.com')
        self.assert_equals(200, got.status_code)

    def test_user_object_url_object(self):
        with app.test_request_context('/'):
            Object(id='a', domains=['user.com'], labels=['notification'], our_as1={
                **REPOST_AS2,
                'object': {
                    'id': 'https://mas.to/toot/id',
                    'url': {'value': 'http://foo', 'displayName': 'bar'},
                },
            }).put()

        got = self.client.get('/user/user.com')
        self.assert_equals(200, got.status_code)

    @patch('requests.get')
    def test_check_web_site(self, mock_get):
        redir = 'http://localhost/.well-known/webfinger?resource=acct:orig@orig'
        mock_get.side_effect = (
            requests_response('', status=302, redirected_url=redir),
            requests_response(ACTOR_HTML, url='https://orig/',
                              content_type=common.CONTENT_TYPE_HTML),
        )

        got = self.client.post('/web-site', data={'url': 'https://orig/'})
        self.assert_equals(302, got.status_code)
        self.assert_equals('/user/orig', got.headers['Location'])

        user = User.get_by_id('orig')
        self.assertTrue(user.has_hcard)
        self.assertEqual('Person', user.actor_as2['type'])
        self.assertEqual('http://localhost/orig', user.actor_as2['id'])

    def test_check_web_site_bad_url(self):
        got = self.client.post('/web-site', data={'url': '!!!'})
        self.assert_equals(200, got.status_code)
        self.assertEqual(['No domain found in !!!'], get_flashed_messages())
        self.assertEqual(1, User.query().count())

    @patch('requests.get')
    def test_check_web_site_fetch_fails(self, mock_get):
        redir = 'http://localhost/.well-known/webfinger?resource=acct:orig@orig'
        mock_get.side_effect = (
            requests_response('', status=302, redirected_url=redir),
            requests_response('', status=503),
        )

        got = self.client.post('/web-site', data={'url': 'https://orig/'})
        self.assert_equals(200, got.status_code)
        self.assertTrue(get_flashed_messages()[0].startswith(
            "Couldn't connect to https://orig/: "))

    def test_followers(self):
        self.make_user('bar.com')
        Follower.get_or_create('bar.com', 'https://no/stored/follow')
        Follower.get_or_create('bar.com', 'https://masto/user',
                               last_follow=FOLLOW_WITH_ACTOR)
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('no/stored/follow', body)
        self.assertIn('masto/user', body)

    def test_followers_empty(self):
        self.make_user('bar.com')
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_followers_user_not_found(self):
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(404, got.status_code)

    def test_following(self):
        Follower.get_or_create('https://no/stored/follow', 'bar.com')
        Follower.get_or_create('https://masto/user', 'bar.com',
                               last_follow=FOLLOW_WITH_OBJECT)
        self.make_user('bar.com')
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('no/stored/follow', body)
        self.assertIn('masto/user', body)

    def test_following_empty(self):
        self.make_user('bar.com')
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_following_user_not_found(self):
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(404, got.status_code)

    def test_following_before_empty(self):
        self.make_user('bar.com')
        got = self.client.get(f'/user/bar.com/following?before={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_following_after_empty(self):
        self.make_user('bar.com')
        got = self.client.get(f'/user/bar.com/following?after={util.now().isoformat()}')
        self.assert_equals(200, got.status_code)

    def test_feed_user_not_found(self):
        got = self.client.get('/user/bar.com/feed')
        self.assert_equals(404, got.status_code)

    def test_feed_html_empty(self):
        got = self.client.get('/user/user.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], microformats2.html_to_activities(got.text))

    def test_feed_html(self):
        self.add_objects()
        got = self.client.get('/user/user.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED,
                           contents(microformats2.html_to_activities(got.text)))

    def test_feed_atom_empty(self):
        got = self.client.get('/user/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom(self):
        self.add_objects()
        got = self.client.get('/user/user.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(atom.atom_to_activities(got.text)))

    def test_feed_rss_empty(self):
        got = self.client.get('/user/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_objects()
        got = self.client.get('/user/user.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))
