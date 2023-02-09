"""Unit tests for pages.py."""
from flask import get_flashed_messages
from unittest.mock import patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
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

import common
from models import Object, Follower, User
from . import testutil
from .test_webmention import ACTOR_AS2, ACTOR_HTML, ACTOR_MF2


def contents(activities):
    return [(a.get('object') or a)['content'] for a in activities]


class PagesTest(testutil.TestCase):
    EXPECTED = contents([COMMENT, NOTE])

    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('foo.com')

    def test_user(self):
        got = self.client.get('/user/foo.com')
        self.assert_equals(200, got.status_code)

    def test_user_objects(self):
        self.add_objects()
        got = self.client.get('/user/foo.com')
        self.assert_equals(200, got.status_code)

    def test_user_not_found(self):
        got = self.client.get('/user/bar.com')
        self.assert_equals(404, got.status_code)

    def test_user_use_instead(self):
        bar = User.get_or_create('bar.com')
        bar.use_instead = self.user.key
        bar.put()

        got = self.client.get('/user/bar.com')
        self.assert_equals(301, got.status_code)
        self.assert_equals('/user/foo.com', got.headers['Location'])

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
        actor_as2 = json_loads(user.actor_as2)
        self.assertEqual('Person', actor_as2['type'])
        self.assertEqual('http://localhost/orig', actor_as2['id'])

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
        User.get_or_create('bar.com')
        Follower.get_or_create('bar.com', 'https://no/stored/follow')
        Follower.get_or_create('bar.com', 'https://masto/user',
                               last_follow=json_dumps(FOLLOW_WITH_ACTOR))
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('no/stored/follow', body)
        self.assertIn('masto/user', body)

    def test_followers_empty(self):
        User.get_or_create('bar.com')
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_followers_user_not_found(self):
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(404, got.status_code)

    def test_following(self):
        Follower.get_or_create('https://no/stored/follow', 'bar.com')
        Follower.get_or_create('https://masto/user', 'bar.com',
                               last_follow=json_dumps(FOLLOW_WITH_OBJECT))
        User.get_or_create('bar.com')
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(200, got.status_code)

        body = got.get_data(as_text=True)
        self.assertIn('no/stored/follow', body)
        self.assertIn('masto/user', body)

    def test_following_empty(self):
        User.get_or_create('bar.com')
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(200, got.status_code)
        self.assertNotIn('class="follower', got.get_data(as_text=True))

    def test_following_user_not_found(self):
        got = self.client.get('/user/bar.com/following')
        self.assert_equals(404, got.status_code)

    def test_feed_user_not_found(self):
        got = self.client.get('/user/bar.com/feed')
        self.assert_equals(404, got.status_code)

    def test_feed_html_empty(self):
        got = self.client.get('/user/foo.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], microformats2.html_to_activities(got.text))

    def test_feed_html(self):
        self.add_objects()
        got = self.client.get('/user/foo.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED,
                           contents(microformats2.html_to_activities(got.text)))

    def test_feed_atom_empty(self):
        got = self.client.get('/user/foo.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom(self):
        self.add_objects()
        got = self.client.get('/user/foo.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(atom.atom_to_activities(got.text)))

    def test_feed_rss_empty(self):
        got = self.client.get('/user/foo.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_objects()
        got = self.client.get('/user/foo.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))
