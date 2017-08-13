# coding=utf-8
"""Unit tests for activitypub.py.
"""
import json
import unittest

import mock
import requests

import activitypub


@mock.patch('requests.get')
class ActivityPubTest(unittest.TestCase):

    def test_actor_handler(self, mock_get):
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

        got = activitypub.app.get_response('/foo.com')
        self.assertEquals(200, got.status_int)
        self.assertEquals(activitypub.CONTENT_TYPE, got.headers['Content-Type'])
        self.assertEquals({
            'objectType' : 'person',
            'displayName': u'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'http://localhost/foo.com/inbox',
        }, json.loads(got.body))
