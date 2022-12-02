"""Unit tests for pages.py."""
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
from granary import as2, atom, microformats2, rss

from models import Activity, Follower, User
from . import testutil
from .test_activitypub import LIKE, MENTION, NOTE, REPLY


def contents(activities):
    return [a['object']['content'] for a in activities]


class PagesTest(testutil.TestCase):
    EXPECTED = contents([as2.to_as1(REPLY), as2.to_as1(NOTE)])

    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('foo.com')

    @staticmethod
    def add_activities():
        Activity(id='a', domain=['foo.com'], direction='in',
                 source_as2=json_dumps(NOTE)).put()
        # different domain
        Activity(id='b', domain=['bar.org'], direction='in',
                 source_as2=json_dumps(MENTION)).put()
        # empty, should be skipped
        Activity(id='c', domain=['foo.com'], direction='in').put()
        Activity(id='d', domain=['foo.com'], direction='in',
                 source_as2=json_dumps(REPLY)).put()
        # wrong direction
        Activity(id='e', domain=['foo.com'], direction='out',
                 source_as2=json_dumps(NOTE)).put()
        # skip Likes
        Activity(id='f', domain=['foo.com'], direction='in',
                 source_as2=json_dumps(LIKE)).put()

    def test_user(self):
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

    def test_followers_user_not_found(self):
        got = self.client.get('/user/bar.com/followers')
        self.assert_equals(404, got.status_code)

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
        self.add_activities()
        got = self.client.get('/user/foo.com/feed')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED,
                           contents(microformats2.html_to_activities(got.text)))

    def test_feed_atom_empty(self):
        got = self.client.get('/user/foo.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], atom.atom_to_activities(got.text))

    def test_feed_atom(self):
        self.add_activities()
        got = self.client.get('/user/foo.com/feed?format=atom')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(atom.atom_to_activities(got.text)))

    def test_feed_rss_empty(self):
        got = self.client.get('/user/foo.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals([], rss.to_activities(got.text))

    def test_feed_rss(self):
        self.add_activities()
        got = self.client.get('/user/foo.com/feed?format=rss')
        self.assert_equals(200, got.status_code)
        self.assert_equals(self.EXPECTED, contents(rss.to_activities(got.text)))
