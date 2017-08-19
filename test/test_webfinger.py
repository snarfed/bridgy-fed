# coding=utf-8
"""Unit tests for webfinger.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import json
import unittest

from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import testbed

import mock
import requests

import common
import models
from webfinger import app


class WebFingerTest(unittest.TestCase):

    maxDiff = None

    # TODO: unify with test_models
    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        hrd_policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=.5)
        self.testbed.init_datastore_v3_stub(consistency_policy=hrd_policy)
        self.testbed.init_memcache_stub()

    def tearDown(self):
        self.testbed.deactivate()

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
        html = u"""
<body>
<a class="h-card" rel="me" href="/about-me">
  <img class="u-photo" src="/me.jpg" />
  Mrs. ☕ Foo
</a>
</body>
"""
        resp = requests.Response()
        resp.status_code = 200
        resp._text = html
        resp._content = html.encode('utf-8')
        resp.encoding = 'utf-8'
        resp.url = 'https://foo.com/'
        mock_get.return_value = resp

        got = app.get_response('/@foo.com', headers={'Accept': 'application/json'})
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS)
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/json; charset=utf-8',
                          got.headers['Content-Type'])

        key = models.MagicKey.get_by_id('@foo.com')

        self.assertEquals({
            'subject': 'acct:@foo.com',
            'aliases': [
                'https://foo.com/',
                'https://foo.com/about-me',
            ],
            'magic_keys': [{'value': key.href()}],
            'links': [{
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://foo.com/'
            }, {
                'rel': 'http://webfinger.net/rel/profile-page',
                'type': 'text/html',
                'href': 'https://foo.com/about-me'
            }, {
                'rel': 'magic-public-key',
                'href': key.href(),
            # TODO
            # }, {
            #     'rel': 'http://webfinger.net/rel/avatar',
            #     'href': 'https://foo.com/me.jpg'
            # }, {
            #     'rel': 'salmon',
            #     'href': 'http://localhost/salmon/23507'
            # }, {
            #     'rel': 'http://schemas.google.com/g/2010#updates-from',
            #     'type': 'application/atom+xml',
            #     'href': 'https://mastodon.technology/users/snarfed.atom'
            # }, {
            #     'rel': 'self',
            #     'type': 'application/activity+json',
            #     'href': 'https://mastodon.technology/users/snarfed'
            # }, {
            #     'rel': 'http://ostatus.org/schema/1.0/subscribe',
            #     'template': 'https://mastodon.technology/authorize_follow?acct={uri}'
            }]
        }, json.loads(got.body))
