# coding=utf-8
"""Unit tests for webfinger.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import json
import urllib

import mock
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

import common
import models
import testutil
from webfinger import app

USER = '%s@foo.com' % common.USERNAME


class WebFingerTest(testutil.TestCase):

    def setUp(self):
        super(WebFingerTest, self).setUp()
        self.html = """
<body>
<a class="h-card" rel="me" href="/about-me">
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
                'rel': 'http://schemas.google.com/g/2010#updates-from',
                'type': 'application/atom+xml',
                'href': 'https://granary-demo.appspot.com/url?input=html&output=atom&url=https://foo.com/&hub=https://foo.com/'
            }, {
                'rel': 'magic-public-key',
                'href': self.key.href(),
            }, {
                'rel': 'salmon',
                'href': 'http://localhost/foo.com/salmon'
            # TODO
            # }, {
            #     'rel': 'self',
            #     'type': 'application/activity+json',
            #     'href': 'https://mastodon.technology/users/snarfed'
            # }, {
            #     'rel': 'http://ostatus.org/schema/1.0/subscribe',
            #     'template': 'https://mastodon.technology/authorize_follow?acct={uri}'
            }]
        }

    def test_host_meta_handler_xrd(self):
        got = app.get_response('/.well-known/host-meta')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/xrd+xml; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('<?xml'), got.body)

    def test_host_meta_handler_xrds(self):
        got = app.get_response('/.well-known/host-meta.xrds')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/xrds+xml; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('<XRDS'), got.body)

    def test_host_meta_handler_jrd(self):
        got = app.get_response('/.well-known/host-meta.json')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/json; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('{'), got.body)

    @mock.patch('requests.get')
    def test_user_handler(self, mock_get):
        mock_get.return_value = requests_response(self.html, url = 'https://foo.com/')

        got = app.get_response('/foo.com', headers={'Accept': 'application/json'})
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/json; charset=utf-8',
                          got.headers['Content-Type'])
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         timeout=util.HTTP_TIMEOUT)

        self.assertEquals(self.expected_webfinger, json.loads(got.body))

        # check that magic key is persistent
        again = json.loads(app.get_response(
            '/foo.com', headers={'Accept': 'application/json'}).body)
        self.assertEquals(self.key.href(), again['magic_keys'][0]['value'])

        links = {l['rel']: l['href'] for l in again['links']}
        self.assertEquals(self.key.href(), links['magic-public-key'])

    @mock.patch('requests.get')
    def test_user_handler_no_hcard(self, mock_get):
        mock_get.return_value = requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
""")
        got = app.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         timeout=util.HTTP_TIMEOUT)
        self.assertEquals(400, got.status_int)
        self.assertIn('representative h-card', got.body)

    @mock.patch('requests.get')
    def test_webfinger_handler(self, mock_get):
        mock_get.return_value = requests_response(self.html, url='https://foo.com/')

        for resource in ('me@foo.com', 'acct:me@foo.com', 'xyz@foo.com',
                         'foo.com', 'http://foo.com/', 'https://foo.com/'):
            url = '/.well-known/webfinger?%s' % urllib.urlencode(
                {'resource': resource})
            got = app.get_response(url, headers={'Accept': 'application/json'})
            self.assertEquals(200, got.status_int, got.body)
            self.assertEquals('application/json; charset=utf-8',
                              got.headers['Content-Type'])
            self.assertEquals(self.expected_webfinger, json.loads(got.body))
