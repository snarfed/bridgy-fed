# coding=utf-8
"""Unit tests for add_webmention.py.
"""
import unittest

import mock
import requests

from add_webmention import app


@mock.patch('requests.get')
class AddWebmentionTest(unittest.TestCase):

    def setUp(self):
        self.resp = requests.Response()
        self.resp._content = 'asdf ☕ qwert'
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
