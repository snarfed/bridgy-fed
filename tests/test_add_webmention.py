# coding=utf-8
"""Unit tests for add_webmention.py.
"""
from unittest import mock

from oauth_dropins.webutil.testutil import requests_response
import requests
from . import testutil


@mock.patch('requests.get')
class AddWebmentionTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.resp = requests_response('asdf ☕ qwert', headers={
            'Link': 'first',
            'Foo': 'bar',
        })

    def test_get(self, mock_get):
        self.resp.status_code = 202
        mock_get.return_value = self.resp

        got = self.client.get('/wm/http://url')
        self.assertEqual(202, got.status_code)
        self.assertEqual(self.resp._content, got.data)
        self.assertEqual(['bar'], got.headers.getlist('Foo'))
        self.assertEqual(['first', '<http://localhost/webmention>; rel="webmention"'],
                         got.headers.getlist('Link'))

    def test_endpoint_param(self, mock_get):
        mock_get.return_value = self.resp

        got = self.client.get('/wm/http://url?endpoint=https://end/point')
        self.assertEqual(200, got.status_code)
        self.assertEqual(['first', '<https://end/point>; rel="webmention"'],
                         got.headers.getlist('Link'))
