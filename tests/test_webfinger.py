# coding=utf-8
"""Unit tests for webfinger.py.

TODO: test error handling
"""
from unittest import mock
import urllib.parse

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_loads
import requests

from app import application
import common
import models
from webfinger import UserHandler, WebfingerHandler
from . import testutil

USER = 'foo.com@foo.com'


class WebfingerTest(testutil.TestCase):

    def setUp(self):
        super(WebfingerTest, self).setUp()
        UserHandler.get.cache_clear()
        WebfingerHandler.get.cache_clear()
        self.html = """
<body class="h-card">
<a class="u-url" rel="me" href="/about-me">
  <img class="u-photo" src="/me.jpg" />
  Mrs. ☕ Foo
</a>
</body>
"""
        self.key = models.MagicKey.get_or_create('foo.com')
        self.expected_webfinger = {
            'subject': 'acct:' + USER,
            'aliases': [
                'https://foo.com/about-me',
                'https://foo.com/',
            ],
            'magic_keys': [{'value': self.key.href()}],
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
                'rel': 'http://schemas.google.com/g/2010#updates-from',
                'type': 'application/atom+xml',
                'href': 'https://granary.io/url?input=html&output=atom&url=https%3A%2F%2Ffoo.com%2F&hub=https%3A%2F%2Ffoo.com%2F',
            }, {
                'rel': 'hub',
                'href': 'https://bridgy-fed.superfeedr.com/'
            }, {
                'rel': 'magic-public-key',
                'href': self.key.href(),
            }, {
                'rel': 'salmon',
                'href': 'http://localhost/foo.com/salmon'
            # }, {
            #     'rel': 'http://ostatus.org/schema/1.0/subscribe',
            #     'template': 'https://mastodon.technology/authorize_follow?acct={uri}'
            }]
        }

    def test_host_meta_handler_xrd(self):
        got = application.get_response('/.well-known/host-meta')
        self.assertEqual(200, got.status_int)
        self.assertEqual('application/xrd+xml; charset=utf-8',
                          got.headers['Content-Type'])
        body = got.body.decode()
        self.assertTrue(body.startswith('<?xml'), body)

    def test_host_meta_handler_xrds(self):
        got = application.get_response('/.well-known/host-meta.xrds')
        self.assertEqual(200, got.status_int)
        self.assertEqual('application/xrds+xml; charset=utf-8',
                          got.headers['Content-Type'])
        body = got.body.decode()
        self.assertTrue(body.startswith('<XRDS'), body)

    def test_host_meta_handler_jrd(self):
        got = application.get_response('/.well-known/host-meta.json')
        self.assertEqual(200, got.status_int)
        self.assertEqual('application/json; charset=utf-8',
                          got.headers['Content-Type'])
        body = got.body.decode()
        self.assertTrue(body.startswith('{'), body)

    @mock.patch('requests.get')
    def test_user_handler(self, mock_get):
        mock_get.return_value = requests_response(self.html, url = 'https://foo.com/')

        got = application.get_response('/acct:foo.com',
                                       headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_int)
        self.assertEqual('application/json; charset=utf-8',
                          got.headers['Content-Type'])
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         stream=True, timeout=util.HTTP_TIMEOUT)

        self.assertEqual(self.expected_webfinger, json_loads(got.body.decode()))

        # check that magic key is persistent
        again = json_loads(application.get_response(
            '/acct:foo.com', headers={'Accept': 'application/json'}).body.decode())
        self.assertEqual(self.key.href(), again['magic_keys'][0]['value'])

        links = {l['rel']: l['href'] for l in again['links']}
        self.assertEqual(self.key.href(), links['magic-public-key'])

    @mock.patch('requests.get')
    def test_user_handler_with_atom_feed(self, mock_get):
        html = """\
<html>
<head>
<link rel="feed" href="/dont-use">
<link rel="alternate" type="application/rss+xml" href="/dont-use-either">
<link rel="alternate" type="application/atom+xml" href="/use-this">
</head>
""" + self.html
        mock_get.return_value = requests_response(html, url = 'https://foo.com/')

        got = application.get_response('/acct:foo.com',
                                       headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_int)
        self.assertIn({
            'rel': 'http://schemas.google.com/g/2010#updates-from',
            'type': 'application/atom+xml',
            'href': 'https://foo.com/use-this',
        }, json_loads(got.body.decode())['links'])

    @mock.patch('requests.get')
    def test_user_handler_with_push_header(self, mock_get):
        mock_get.return_value = requests_response(
            self.html, url = 'https://foo.com/', headers={
                'Link': 'badly formatted, '
                        "<xyz>; rel='foo',"
                        '<http://a.custom.hub/>; rel="hub"',
            })

        got = application.get_response('/acct:foo.com',
                                       headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_int)
        self.assertIn({
            'rel': 'hub',
            'href': 'http://a.custom.hub/',
        }, json_loads(got.body.decode())['links'])

    @mock.patch('requests.get')
    def test_user_handler_no_hcard(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
""")
        got = application.get_response('/acct:foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         stream=True, timeout=util.HTTP_TIMEOUT)
        self.assertEqual(400, got.status_int)
        self.assertIn('representative h-card', got.body.decode())

    def test_user_handler_bad_tld(self):
        got = application.get_response('/acct:foo.json')
        self.assertEqual(404, got.status_int)
        self.assertIn("doesn't look like a domain", got.body.decode())

    @mock.patch('requests.get')
    def test_webfinger_handler(self, mock_get):
        mock_get.return_value = requests_response(self.html, url='https://foo.com/')

        for resource in ('foo.com@foo.com', 'acct:foo.com@foo.com', 'xyz@foo.com',
                         'foo.com', 'http://foo.com/', 'https://foo.com/'):
            url = '/.well-known/webfinger?%s' % urllib.parse.urlencode(
                {'resource': resource})
            got = application.get_response(url, headers={'Accept': 'application/json'})
            body = got.body.decode()
            self.assertEqual(200, got.status_int, body)
            self.assertEqual('application/json; charset=utf-8',
                              got.headers['Content-Type'])
            self.assertEqual(self.expected_webfinger, json_loads(body))

    @mock.patch('requests.get')
    def test_webfinger_handler_custom_username(self, mock_get):
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
                # 'acct:foo.com@fed.brid.gy',
                'acct:foo.com@fed.brid.gy',
                'acct:foo.com@bridgy-federated.appspot.com',
                'acct:foo.com@localhost',
        ):
            url = '/.well-known/webfinger?%s' % urllib.parse.urlencode(
                {'resource': resource})
            got = application.get_response(url, headers={'Accept': 'application/json'})
            body = got.body.decode()
            self.assertEqual(200, got.status_int, body)
            self.assertEqual('application/json; charset=utf-8',
                              got.headers['Content-Type'])
            self.assertEqual(self.expected_webfinger, json_loads(body))
