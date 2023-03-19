# coding=utf-8
"""Unit tests for webfinger.py."""
import html
import urllib.parse

import common
from models import User
from . import testutil


class HostMetaTest(testutil.TestCase):
    def test_host_meta_xrd(self):
        got = self.client.get('/.well-known/host-meta')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/xrd+xml; charset=utf-8',
                          got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('<?xml'), body)

    def test_host_meta_xrds(self):
        got = self.client.get('/.well-known/host-meta.xrds')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/xrds+xml', got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('<XRDS'), body)

    def test_host_meta_jrd(self):
        got = self.client.get('/.well-known/host-meta.json')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('{'), body)


class WebfingerTest(testutil.TestCase):

    def setUp(self):
        super().setUp()

        self.actor_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'url': 'https://user.com/about-me',
            'name': 'Mrs. ☕ Foo',
            'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
        }
        self.user = self.make_user('user.com', has_hcard=True, actor_as2=self.actor_as2)
        self.user.put()
        self.expected_webfinger = {
            'subject': 'acct:user.com@user.com',
            'aliases': [
                'https://user.com/about-me',
                'https://user.com/',
            ],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://user.com/about-me',
            }, {
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://user.com/',
            }, {
                'rel': 'http://webfinger.net/rel/avatar',
                'href': 'https://user.com/me.jpg',
            }, {
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': 'https://user.com/about-me',
            }, {
                'rel': 'self',
                'type': 'application/activity+json',
                'href': 'http://localhost/user.com',
            }, {
                'rel': 'inbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/user.com/inbox'
            }, {
                'rel': 'sharedInbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/inbox',
            }, {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                'template': 'http://localhost/user/user.com?url={uri}',
            }],
        }

    def test_user(self):
        got = self.client.get('/acct:user.com', headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(self.expected_webfinger, got.json)

    def test_user_no_hcard(self):
        self.user.has_hcard = False
        self.user.actor_as2 = None
        self.user.put()

        got = self.client.get('/acct:user.com')
        self.assertEqual(200, got.status_code)
        self.assert_equals({
            'subject': 'acct:user.com@user.com',
            'aliases': ['https://user.com/'],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://user.com/'
            }, {
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': 'https://user.com/'
            }, {
                'rel': 'self',
                'type': 'application/activity+json',
                'href': 'http://localhost/user.com'
            }, {
                'rel': 'inbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/user.com/inbox'
            }, {
                'rel': 'sharedInbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/inbox'
            }, {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                'template': 'http://localhost/user/user.com?url={uri}',
            }]
        }, got.json)

    def test_user_bad_tld(self):
        got = self.client.get('/acct:foo.json')
        self.assertEqual(404, got.status_code)
        self.assertIn("doesn't look like a domain",
                      html.unescape(got.get_data(as_text=True)))

    def test_user_not_found(self):
        got = self.client.get('/acct:nope.com', headers={'Accept': 'application/json'})
        self.assertEqual(404, got.status_code)

    def test_webfinger(self):
        for resource in ('user.com@user.com', 'acct:user.com@user.com', 'xyz@user.com',
                         'user.com', 'http://user.com/', 'https://user.com/',
                         'http://localhost/user.com'):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assert_equals(self.expected_webfinger, got.json)

    def test_webfinger_custom_username(self):
        self.user.actor_as2 = {
            **self.actor_as2,
            'url': [
                'https://user.com/about-me',
                'acct:notthisuser@boop.org',
                'acct:customuser@user.com',
            ],
        }
        self.user.put()

        self.expected_webfinger.update({
            'subject': 'acct:customuser@user.com',
            'aliases': [
                'https://user.com/about-me',
                'acct:notthisuser@boop.org',
                'acct:customuser@user.com',
                'https://user.com/',
            ],
        })

        for resource in (
                'customuser@user.com',
                'acct:customuser@user.com',
                'user.com',
                'http://user.com/',
                'https://user.com/',
                # Mastodon requires this as of 3.3.0
                # https://github.com/snarfed/bridgy-fed/issues/73
                'acct:user.com@fed.brid.gy',
                'acct:user.com@bridgy-federated.appspot.com',
                'acct:user.com@localhost',
        ):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assert_equals(self.expected_webfinger, got.json)

    def test_webfinger_fed_brid_gy(self):
        got = self.client.get('/.well-known/webfinger?resource=http://localhost/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get('/.well-known/webfinger?resource=acct%3A%40localhost')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))
