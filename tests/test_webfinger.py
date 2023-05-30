# coding=utf-8
"""Unit tests for webfinger.py."""
import copy
import html
from unittest.mock import patch
import urllib.parse

from oauth_dropins.webutil.testutil import requests_response

import common
from . import testutil
from .test_web import ACTOR_HTML

WEBFINGER = {
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
WEBFINGER_NO_HCARD = {
    'subject': 'acct:user.com@user.com',
    'aliases': ['https://user.com/'],
    'links': [{
        'rel': 'http://webfinger.net/rel/profile-page',
        'type': 'text/html',
        'href': 'https://user.com/',
    }, {
        'rel': 'canonical_uri',
        'type': 'text/html',
        'href': 'https://user.com/',
    }, {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com',
    }, {
        'rel': 'inbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com/inbox',
    }, {
        'rel': 'sharedInbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/inbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'http://localhost/user/user.com?url={uri}',
    }],
}


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

    def test_user(self):
        got = self.client.get('/acct:user.com', headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER, got.json)

    def test_user_no_hcard(self):
        self.user.has_hcard = False
        self.user.actor_as2 = None
        self.user.put()

        got = self.client.get('/acct:user.com')
        self.assertEqual(200, got.status_code)
        self.assert_equals(WEBFINGER_NO_HCARD, got.json)

    def test_user_bad_tld(self):
        got = self.client.get('/acct:foo.json')
        self.assertEqual(404, got.status_code)
        self.assertIn("doesn't look like a domain",
                      html.unescape(got.get_data(as_text=True)))

    def test_missing_user(self):
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
                self.assert_equals(WEBFINGER, got.json)

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

        for resource in (
                'customuser@user.com',
                'acct:customuser@user.com',
                'user.com',
                'user.com@user.com',
                'http://user.com/',
                'https://user.com/',
                'acct:user.com@user.com',
                'acct:@user.com@user.com',
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
                self.assert_equals({
                    **WEBFINGER,
                    'subject': 'acct:customuser@user.com',
                    'aliases': [
                        'https://user.com/about-me',
                        'acct:notthisuser@boop.org',
                        'acct:customuser@user.com',
                        'https://user.com/',
                    ],
                }, got.json)

    def test_webfinger_missing_user(self):
        got = self.client.get('/acct:nope.com', headers={'Accept': 'application/json'})
        self.assertEqual(404, got.status_code)

    @patch('requests.get')
    def test_webfinger_external_user_fetch_creates_user(self, mock_get):
        self.user.key.delete()
        mock_get.return_value = requests_response(ACTOR_HTML)

        expected = copy.deepcopy(WEBFINGER_NO_HCARD)
        expected['subject'] = 'acct:user.com@localhost'
        expected['links'][2]['href'] = 'http://localhost/r/https://user.com/'

        got = self.client.get('/.well-known/webfinger?resource=acct:user.com@fed.brid.gy',
                              headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual(expected, got.json)

    def test_webfinger_fed_brid_gy(self):
        got = self.client.get('/.well-known/webfinger?resource=http://localhost/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get('/.well-known/webfinger?resource=acct%3A%40localhost')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))
