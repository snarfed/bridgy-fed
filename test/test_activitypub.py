# coding=utf-8
"""Unit tests for activitypub.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import json
import unittest
import urllib

import mock
import requests

import activitypub
from activitypub import app
import common


@mock.patch('requests.post')
@mock.patch('requests.get')
class ActivityPubTest(unittest.TestCase):

    def test_actor_handler(self, mock_get, _):
        html = u"""
<body>
<a class="h-card" rel="me" href="/about-me">Mrs. ☕ Foo</a>
</body>
"""
        resp = requests.Response()
        resp.status_code = 200
        resp._text = html
        resp._content = html.encode('utf-8')
        resp.encoding = 'utf-8'
        resp.url = 'https://foo.com/'
        mock_get.return_value = resp

        got = app.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS)
        self.assertEquals(200, got.status_int)
        self.assertEquals(activitypub.CONTENT_TYPE_AS2, got.headers['Content-Type'])
        self.assertEquals({
            'objectType' : 'person',
            'displayName': u'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'http://localhost/foo.com/inbox',
        }, json.loads(got.body))

    def test_inbox_reply(self, mock_get, mock_post):
        html = '<html><head><link rel="webmention" href="/webmention"></html>'
        resp = requests.Response()
        resp.status_code = 200
        resp._text = html
        resp._content = html.encode('utf-8')
        mock_get.return_value = resp

        resp = requests.Response()
        resp.status_code = 200
        mock_post.return_value = resp

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

        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'http://this/reply',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers=common.HEADERS,
            verify=False)
