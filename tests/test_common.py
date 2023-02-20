# coding=utf-8
"""Unit tests for common.py."""
from unittest import mock

from granary import as2
from oauth_dropins.webutil import appengine_config, util
from oauth_dropins.webutil.util import json_dumps, json_loads
from oauth_dropins.webutil.testutil import requests_response
import requests
from werkzeug.exceptions import BadGateway

from app import app
import common
from models import Object, User
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
    'Content-Type': as2.CONTENT_TYPE,
})
NOT_ACCEPTABLE = requests_response(status=406)


class CommonTest(testutil.TestCase):
    @classmethod
    def setUpClass(cls):
        with appengine_config.ndb_client.context():
            # do this in setUpClass since generating RSA keys is slow
            cls.user = User.get_or_create('site')

    def setUp(self):
        super().setUp()
        self.app_context = app.test_request_context('/')
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()
        super().tearDown()

    def test_pretty_link(self):
        for expected, url, text in (
                ('<a href="http://foo">bar</a>', 'http://foo', 'bar'),
                ('<a href="http://x.y/@z">@z@x.y</a>', 'http://x.y/@z', None),
                ('<a href="http://x.y/@z">foo</a>', 'http://x.y/@z', 'foo'),
                ('<a href="http://x.y/users/z">@z@x.y</a>', 'http://x.y/users/z', None),
                ('<a href="http://x.y/users/z">foo</a>', 'http://x.y/users/z', 'foo'),
                ('<a href="http://x.y/@z/123">x.y/@z/123</a>', 'http://x.y/@z/123', None),
        ):
            self.assertEqual(expected, common.pretty_link(url, text=text))

        self.assertEqual(
            '<a href="/user/site"><img src="" class="profile"> site</a>',
            common.pretty_link('https://site/', user=self.user))

    @mock.patch('requests.get', return_value=AS2)
    def test_get_as2_direct(self, mock_get):
        resp = common.get_as2('http://orig', user=self.user)
        self.assertEqual(AS2, resp)
        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @mock.patch('requests.get', side_effect=[HTML_WITH_AS2, AS2])
    def test_get_as2_via_html(self, mock_get):
        resp = common.get_as2('http://orig', user=self.user)
        self.assertEqual(AS2, resp)
        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
            self.as2_req('http://as2', headers=common.as2.CONNEG_HEADERS),
        ))

    @mock.patch('requests.get', return_value=HTML)
    def test_get_as2_only_html(self, mock_get):
        with self.assertRaises(BadGateway):
            resp = common.get_as2('http://orig', user=self.user)

    @mock.patch('requests.get', return_value=NOT_ACCEPTABLE)
    def test_get_as2_not_acceptable(self, mock_get):
        with self.assertRaises(BadGateway):
            resp = common.get_as2('http://orig', user=self.user)

    @mock.patch('requests.get', side_effect=requests.exceptions.SSLError)
    def test_get_ssl_error(self, mock_get):
        with self.assertRaises(BadGateway):
            resp = common.get_as2('http://orig', user=self.user)

    def test_redirect_wrap_empty(self):
        self.assertIsNone(common.redirect_wrap(None))
        self.assertEqual('', common.redirect_wrap(''))

    def test_redirect_unwrap_empty(self):
        self.assertIsNone(common.redirect_unwrap(None))
        for obj in '', {}, []:
            self.assertEqual(obj, common.redirect_unwrap(obj))

    def test_unwrap_not_web(self):
        bad = {
            'type': 'Like',
            'object': 'http://localhost/r/foo bar',
        }
        self.assert_equals(bad, common.redirect_unwrap(bad))

    def test_unwrap_local_actor_urls(self):
        self.assert_equals(
            {'object': 'https://foo.com/'},
            common.redirect_unwrap({'object': 'http://localhost/foo.com'}))

        self.assert_equals(
            {'object': {'id': 'https://foo.com/'}},
            common.redirect_unwrap({'object': {'id': 'http://localhost/foo.com'}}))

    def test_postprocess_as2_multiple_in_reply_tos(self):
        with app.test_request_context('/'):
            self.assert_equals({
                'id': 'http://localhost/r/xyz',
                'inReplyTo': 'foo',
                'to': [as2.PUBLIC_AUDIENCE],
            }, common.postprocess_as2({
                'id': 'xyz',
                'inReplyTo': ['foo', 'bar'],
            }, user=User(id='site')))

    def test_postprocess_as2_multiple_url(self):
        with app.test_request_context('/'):
            self.assert_equals({
                'id': 'http://localhost/r/xyz',
                'url': ['http://localhost/r/foo', 'http://localhost/r/bar'],
                'to': [as2.PUBLIC_AUDIENCE],
            }, common.postprocess_as2({
                'id': 'xyz',
                'url': ['foo', 'bar'],
            }, user=User(id='site')))

    def test_postprocess_as2_multiple_image(self):
        with app.test_request_context('/'):
            self.assert_equals({
                'id': 'http://localhost/r/xyz',
                'attachment': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
                'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
                'to': [as2.PUBLIC_AUDIENCE],
            }, common.postprocess_as2({
                'id': 'xyz',
                'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
            }, user=User(id='site')))

    def test_postprocess_as2_actor_attributedTo(self):
        with app.test_request_context('/'):
            self.assert_equals({
                'actor': {
                    'id': 'baj',
                    'preferredUsername': 'site',
                    'url': 'http://localhost/r/https://site/',
                },
                'attributedTo': [{
                    'id': 'bar',
                    'preferredUsername': 'site',
                    'url': 'http://localhost/r/https://site/',
                }, {
                    'id': 'baz',
                    'preferredUsername': 'site',
                    'url': 'http://localhost/r/https://site/',
                }],
                'to': [as2.PUBLIC_AUDIENCE],
            }, common.postprocess_as2({
                'attributedTo': [{'id': 'bar'}, {'id': 'baz'}],
                'actor': {'id': 'baj'},
            }, user=User(id='site')))

    def test_postprocess_as2_note(self):
        with app.test_request_context('/'):
            self.assert_equals({
                '@context': 'https://www.w3.org/ns/activitystreams',
                'id': 'http://localhost/r/xyz#bridgy-fed-create',
                'type': 'Create',
                'actor': {
                    'id': 'http://localhost/site',
                    'url': 'http://localhost/r/https://site/',
                    'preferredUsername': 'site'
                },
                'object': {
                    'id': 'http://localhost/r/xyz',
                    'type': 'Note',
                    'to': [as2.PUBLIC_AUDIENCE],
                },
            }, common.postprocess_as2({
                'id': 'xyz',
                'type': 'Note',
            }, user=User(id='site')))

    def test_host_url(self):
        with app.test_request_context():
            self.assertEqual('http://localhost/', common.host_url())
            self.assertEqual('http://localhost/asdf', common.host_url('asdf'))
            self.assertEqual('http://localhost/foo/bar', common.host_url('/foo/bar'))

        with app.test_request_context(base_url='https://a.xyz', path='/foo'):
            self.assertEqual('https://a.xyz/', common.host_url())
            self.assertEqual('https://a.xyz/asdf', common.host_url('asdf'))
            self.assertEqual('https://a.xyz/foo/bar', common.host_url('/foo/bar'))

        with app.test_request_context(base_url='http://bridgy-federated.uc.r.appspot.com'):
            self.assertEqual('https://fed.brid.gy/asdf', common.host_url('asdf'))

    @mock.patch('requests.get')
    def test_signed_get_redirects_manually_with_new_sig_headers(self, mock_get):
        mock_get.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
            requests_response(status=200, allow_redirects=False),
        ]
        resp = common.signed_get('https://first', user=self.user)

        first = mock_get.call_args_list[0][1]
        second = mock_get.call_args_list[1][1]
        self.assertNotEqual(first['headers'], second['headers'])
        self.assertNotEqual(
            first['auth'].header_signer.sign(first['headers'], method='GET', path='/'),
            second['auth'].header_signer.sign(second['headers'], method='GET', path='/'))

    @mock.patch('requests.post')
    def test_signed_post_ignores_redirect(self, mock_post):
        mock_post.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
        ]
        resp = common.signed_post('https://first', user=self.user)
        mock_post.assert_called_once()
        self.assertEqual(302, resp.status_code)

    @mock.patch('requests.get', return_value=AS2)
    def test_get_object_http(self, mock_get):
        self.assertEqual(0, Object.query().count())

        # first time fetches over HTTP
        id = 'http://the/id'
        got = common.get_object(id)
        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, json_loads(got.as2))
        mock_get.assert_has_calls([self.as2_req(id)])

        # second time is in cache
        got.key.delete()
        mock_get.reset_mock()
        got = common.get_object(id)
        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, json_loads(got.as2))
        mock_get.assert_not_called()

    @mock.patch('requests.get')
    def test_get_object_datastore(self, mock_get):
        id = 'http://the/id'
        stored = Object(id=id, as2=json_dumps(AS2_OBJ), as1='{}')
        stored.put()
        common.get_object.cache.clear()

        # first time loads from datastore
        got = common.get_object(id)
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

        # second time is in cache
        stored.key.delete()
        got = common.get_object(id)
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

    @mock.patch('requests.get')
    def test_get_object_strips_fragment(self, mock_get):
        stored = Object(id='http://the/id', as2=json_dumps(AS2_OBJ), as1='{}')
        stored.put()
        common.get_object.cache.clear()

        got = common.get_object('http://the/id#ignore')
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

    @mock.patch('requests.get', return_value=AS2)
    def test_get_object_datastore_no_as2(self, mock_get):
        """If the stored Object has no as2, we should fall back to HTTP."""
        id = 'http://the/id'
        stored = Object(id=id, as2=None, as1='{}', status='in progress')
        stored.put()
        common.get_object.cache.clear()

        got = common.get_object(id)
        mock_get.assert_has_calls([self.as2_req(id)])

        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, json_loads(got.as2))
        mock_get.assert_has_calls([self.as2_req(id)])

        self.assert_object(id, as2=AS2_OBJ, as1=AS2_OBJ,
                           source_protocol='activitypub',
                           # check that it reused our original Object
                           status='in progress')
