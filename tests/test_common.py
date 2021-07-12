# coding=utf-8
"""Unit tests for common.py."""
import logging
import os
from unittest import mock

from flask import Flask, request
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests
from webob import exc

from app import app
import common
from . import testutil

HTML = requests_response('<html></html>', headers={
    'Content-Type': common.CONTENT_TYPE_HTML,
})
HTML_WITH_AS2 = requests_response("""\
<html><meta>
<link href='http://as2' rel='alternate' type='application/activity+json'>
</meta></html>
""", headers={
    'Content-Type': common.CONTENT_TYPE_HTML,
})
AS2_OBJ = {'foo': ['bar']}
AS2 = requests_response(AS2_OBJ, headers={
    'Content-Type': common.CONTENT_TYPE_AS2,
})
NOT_ACCEPTABLE = requests_response(status=406)


class CommonTest(testutil.TestCase):
    @mock.patch('requests.get', return_value=AS2)
    def test_get_as2_direct(self, mock_get):
        resp = common.get_as2('http://orig')
        self.assertEqual(AS2, resp)
        mock_get.assert_has_calls((
            self.req('http://orig', headers=common.CONNEG_HEADERS_AS2_HTML),
        ))

    @mock.patch('requests.get', side_effect=[HTML_WITH_AS2, AS2])
    def test_get_as2_via_html(self, mock_get):
        resp = common.get_as2('http://orig')
        self.assertEqual(AS2, resp)
        mock_get.assert_has_calls((
            self.req('http://orig', headers=common.CONNEG_HEADERS_AS2_HTML),
            self.req('http://as2', headers=common.CONNEG_HEADERS_AS2),
        ))

    @mock.patch('requests.get', return_value=HTML)
    def test_get_as2_only_html(self, mock_get):
        with self.assertRaises(exc.HTTPBadGateway):
            resp = common.get_as2('http://orig')

    @mock.patch('requests.get', return_value=NOT_ACCEPTABLE)
    def test_get_as2_not_acceptable(self, mock_get):
        with self.assertRaises(exc.HTTPBadGateway):
            resp = common.get_as2('http://orig')

    @mock.patch('requests.get', side_effect=requests.exceptions.SSLError)
    def test_get_ssl_error(self, mock_get):
        with self.assertRaises(exc.HTTPBadGateway):
            resp = common.get_as2('http://orig')

    def test_redirect_wrap_empty(self):
        self.assertIsNone(common.redirect_wrap(None))
        self.assertEqual('', common.redirect_wrap(''))

    def test_postprocess_as2_multiple_in_reply_tos(self):
        with app.test_request_context('/'):
            self.assertEqual({
                'id': 'http://localhost/r/xyz',
                'inReplyTo': 'foo',
            }, common.postprocess_as2({
                'id': 'xyz',
                'inReplyTo': ['foo', 'bar'],
            }))

    def test_regex_converter(self):
        app = Flask('test_regex_converter')
        app.url_map.converters['regex'] = common.RegexConverter

        @app.route('/<regex("abc|def"):letters>')
        def fn(letters):
            return ''

        with app.test_client() as client:
            resp = client.get('/def')
            self.assertEqual(200, resp.status_code)
            self.assertEqual('def', request.view_args['letters'])

            resp = client.get('/xyz')
            self.assertEqual(404, resp.status_code)


class XrdOrJrdTest(testutil.TestCase):
    def setUp(self):
        super().setUp()

        class View(common.XrdOrJrd):
            def template_prefix(self):
                return 'test_template'

            def template_vars(self, **kwargs):
                return {'foo': 'bar'}

        self.View = View

        self.app = Flask('XrdOrJrdTest')
        self.app.template_folder = os.path.dirname(__file__)

        view_func = View.as_view('XrdOrJrdTest')
        self.app.add_url_rule('/', view_func=view_func)
        self.app.add_url_rule('/<path>', view_func=view_func)

        self.client = self.app.test_client()

    def assert_jrd(self, resp, expected={'foo': 'bar'}):
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/jrd+json', resp.headers['Content-Type'])
        self.assertEqual(expected, resp.json)

    def assert_xrd(self, resp, expected='<XRD><Foo>bar</Foo></XRD>'):
        self.assertEqual(200, resp.status_code)
        self.assertEqual('application/xrd+xml; charset=utf-8',
                         resp.headers['Content-Type'])
        self.assertEqual(expected, resp.get_data(as_text=True))

    def test_xrd_or_jrd_handler_default_jrd(self):
        self.assert_jrd(self.client.get('/'))
        for resp in (self.client.get('/x.xrd'),
                     self.client.get('/x.xml'),
                     self.client.get('/?format=xrd'),
                     self.client.get('/?format=xml'),
                     self.client.get('/', headers={'Accept': 'application/xrd+xml'}),
                     self.client.get('/', headers={'Accept': 'application/xml'}),
                     ):
            self.assert_xrd(resp)

    def test_xrd_or_jrd_handler_default_xrd(self):
        self.View.DEFAULT_TYPE = common.XrdOrJrd.XRD

        self.assert_xrd(self.client.get('/'))
        for resp in (self.client.get('/x.jrd'),
                     self.client.get('/x.json'),
                     self.client.get('/?format=jrd'),
                     self.client.get('/?format=json'),
                     self.client.get('/', headers={'Accept': 'application/jrd+json'}),
                     self.client.get('/', headers={'Accept': 'application/json'}),
                     ):
            self.assert_jrd(resp)

    def test_xrd_or_jrd_handler_accept_header_order(self):
        self.assert_jrd(self.client.get('/', headers={
            'Accept': 'application/jrd+json,application/xrd+xml',
        }))
        self.assert_xrd(self.client.get('/', headers={
            'Accept': 'application/xrd+xml,application/jrd+json',
        }))
