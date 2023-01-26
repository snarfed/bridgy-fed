# coding=utf-8
"""Unit tests for webfinger.py.

to test:
* user URL that redirects
* error handling
"""
import html
from unittest import mock
import urllib.parse

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_loads
import requests

import common
import models
from . import testutil


class WebfingerTest(testutil.TestCase):

    def setUp(self):
        super().setUp()

        self.html = """
<body class="h-card">
<a class="u-url" rel="me" href="/about-me">
  <img class="u-photo" src="/me.jpg" />
  Mrs. ☕ Foo
</a>
</body>
"""
        self.key = models.User.get_or_create('foo.com')
        self.expected_webfinger = {
            'subject': 'acct:foo.com@foo.com',
            'aliases': [
                'https://foo.com/about-me',
                'https://foo.com/',
            ],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://foo.com/about-me'
            }, {
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://foo.com/'
            }, {
                'rel': 'http://webfinger.net/rel/avatar',
                'href': 'https://foo.com/me.jpg'
            }, {
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': 'https://foo.com/about-me'
            }, {
                'rel': 'self',
                'type': 'application/activity+json',
                'href': 'http://localhost/foo.com'
            }, {
                'rel': 'inbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/foo.com/inbox'
            }, {
                'rel': 'sharedInbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/inbox'
            }, {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                'template': 'http://localhost/user/foo.com?url={uri}',
            }],
        }

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

    @mock.patch('requests.get')
    def test_user(self, mock_get):
        mock_get.return_value = requests_response(self.html, url='https://foo.com/')

        got = self.client.get('/acct:foo.com', headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_req(mock_get, 'https://foo.com/')

        self.assertEqual(self.expected_webfinger, got.json)

    @mock.patch('requests.get')
    def test_user_no_hcard(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
""", url='https://foo.com/')
        got = self.client.get('/acct:foo.com')
        self.assert_req(mock_get, 'https://foo.com/')
        self.assertEqual(200, got.status_code)
        self.assert_equals({
            'subject': 'acct:foo.com@foo.com',
            'aliases': ['https://foo.com/'],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://foo.com/'
            }, {
                'rel': 'canonical_uri',
                'type': 'text/html',
                'href': 'https://foo.com/'
            }, {
                'rel': 'self',
                'type': 'application/activity+json',
                'href': 'http://localhost/foo.com'
            }, {
                'rel': 'inbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/foo.com/inbox'
            }, {
                'rel': 'sharedInbox',
                'type': 'application/activity+json',
                'href': 'http://localhost/inbox'
            }, {
                'rel': 'http://ostatus.org/schema/1.0/subscribe',
                'template': 'http://localhost/user/foo.com?url={uri}',
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

    @mock.patch('requests.get')
    def test_webfinger(self, mock_get):
        mock_get.return_value = requests_response(self.html, url='https://foo.com/')

        for resource in ('foo.com@foo.com', 'acct:foo.com@foo.com', 'xyz@foo.com',
                         'foo.com', 'http://foo.com/', 'https://foo.com/',
                         'http://localhost/foo.com'):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assertEqual(self.expected_webfinger, got.json)

    @mock.patch('requests.get')
    def test_webfinger_custom_username(self, mock_get):
        self.html = """
<body class="h-card">
<a class="u-url" rel="me" href="/about-me">
  <img class="u-photo" src="/me.jpg" />
  Mrs. ☕ Foo
</a>
<a class="u-url" href="acct:notthisuser@boop.org"></a>
<a class="u-url" href="acct:customuser@foo.com"></a>
</body>
"""
        self.expected_webfinger.update({
            'subject': 'acct:customuser@foo.com',
            'aliases': [
                'https://foo.com/about-me',
                'acct:notthisuser@boop.org',
                'acct:customuser@foo.com',
                'https://foo.com/',
            ],
        })
        mock_get.return_value = requests_response(self.html, url='https://foo.com/')

        for resource in (
                'customuser@foo.com',
                'acct:customuser@foo.com',
                'foo.com',
                'http://foo.com/',
                'https://foo.com/',
                # Mastodon requires this as of 3.3.0
                # https://github.com/snarfed/bridgy-fed/issues/73
                'acct:foo.com@fed.brid.gy',
                'acct:foo.com@bridgy-federated.appspot.com',
                'acct:foo.com@localhost',
        ):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assertEqual(self.expected_webfinger, got.json)

    def test_webfinger_fed_brid_gy(self):
        got = self.client.get('/.well-known/webfinger?resource=http://localhost/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get('/.well-known/webfinger?resource=acct%3A%40localhost')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))
