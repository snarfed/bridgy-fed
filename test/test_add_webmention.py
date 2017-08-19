# coding=utf-8
"""Unit tests for add_webmention.py.
"""
from __future__ import unicode_literals
import unittest

import mock
import requests

from add_webmention import app


@mock.patch('requests.get')
class AddWebmentionTest(unittest.TestCase):

    def setUp(self):
        self.resp = requests.Response()
        self.resp.status_code = 200
        self.resp._content = u'asdf ☕ qwert'.encode('utf-8')
        self.resp.headers = {
            'Link': 'first',
            'Foo': 'bar',
        }

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
