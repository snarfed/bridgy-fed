# coding=utf-8
"""Unit tests for add_webmention.py.
"""
from __future__ import unicode_literals

import mock
from oauth_dropins.webutil.testutil import requests_response
import requests

from add_webmention import app
import testutil


@mock.patch('requests.get')
class AddWebmentionTest(testutil.TestCase):

    def setUp(self):
        super(AddWebmentionTest, self).setUp()
        self.resp = requests_response('asdf ☕ qwert', headers={
            'Link': 'first',
            'Foo': 'bar',
        })

    def test_get(self, mock_get):
        self.resp.status_code = 202
        mock_get.return_value = self.resp

        got = app.get_response('/wm/http://url')
        self.assertEqual(202, got.status_int)
        self.assertEqual(self.resp._content, got.body)
        self.assertEqual(['bar'], got.headers.getall('Foo'))
        self.assertEqual(['first', '<http://localhost/webmention>; rel="webmention"'],
                         got.headers.getall('Link'))

    def test_endpoint_param(self, mock_get):
        mock_get.return_value = self.resp

        got = app.get_response('/wm/http://url?endpoint=https://end/point')
        self.assertEqual(200, got.status_int)
        self.assertEqual('<https://end/point>; rel="webmention"', got.headers['Link'])
