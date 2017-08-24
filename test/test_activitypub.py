# coding=utf-8
"""Unit tests for activitypub.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import json
import unittest
import urllib

import mock
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

import activitypub
from activitypub import app
import common


@mock.patch('requests.post')
@mock.patch('requests.get')
class ActivityPubTest(unittest.TestCase):

    def test_actor_handler(self, mock_get, _):
        mock_get.return_value = requests_response("""
<body>
<a class="h-card" rel="me" href="/about-me">Mrs. ☕ Foo</a>
</body>
""", url='https://foo.com/')

        got = app.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         timeout=util.HTTP_TIMEOUT)
        self.assertEquals(200, got.status_int)
        self.assertEquals(activitypub.CONTENT_TYPE_AS2, got.headers['Content-Type'])
        self.assertEquals({
            'objectType' : 'person',
            'displayName': u'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'http://localhost/foo.com/inbox',
        }, json.loads(got.body))

    def test_actor_handler_no_hcard(self, mock_get, _):
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
        # TODO
        # self.assertEquals('text/html', got.headers['Content-Type'])

    def test_inbox_reply(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = app.get_response('/foo.com/inbox', method='POST',
                               body=json.dumps({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Note',
            'content': u'A ☕ reply',
            'url': 'http://this/reply',
            'inReplyTo': 'http://orig/post',
            'cc': ['https://www.w3.org/ns/activitystreams#Public'],
        }))
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS, verify=False)
        self.assertEquals(200, got.status_int)

        expected_headers = copy.deepcopy(common.HEADERS)
        expected_headers['Accept'] = '*/*'
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'http://this/reply',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers=expected_headers,
            verify=False)
