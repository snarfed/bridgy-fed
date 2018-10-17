# coding=utf-8
"""Unit tests for activitypub.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import json
import urllib

from mock import call, patch
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

import activitypub
from activitypub import app
import common
from models import MagicKey, Response
import testutil


REPLY_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': 'A ☕ reply',
    'id': 'http://this/reply/id',
    'url': 'http://this/reply',
    'inReplyTo': 'http://orig/post',
    'cc': ['https://www.w3.org/ns/activitystreams#Public'],
}
REPLY_OBJECT_WRAPPED = copy.deepcopy(REPLY_OBJECT)
REPLY_OBJECT_WRAPPED['inReplyTo'] = common.redirect_wrap(
    REPLY_OBJECT_WRAPPED['inReplyTo'])
REPLY_ACTIVITY = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://this/reply/as2',
    'object': REPLY_OBJECT,
}

@patch('requests.post')
@patch('requests.get')
class ActivityPubTest(testutil.TestCase):

    def test_actor_handler(self, mock_get, _):
        mock_get.return_value = requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">Mrs. ☕ Foo</a>
</body>
""", url='https://foo.com/')

        got = app.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         timeout=util.HTTP_TIMEOUT)
        self.assertEquals(200, got.status_int)
        self.assertEquals(common.CONTENT_TYPE_AS2, got.headers['Content-Type'])
        self.assertEquals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type' : 'Person',
            'name': 'Mrs. ☕ Foo',
            'preferredUsername': 'foo.com',
            'id': 'http://localhost/foo.com',
            'url': 'http://localhost/r/https://foo.com/about-me',
            'inbox': 'http://localhost/foo.com/inbox',
            'publicKey': {
                'publicKeyPem': MagicKey.get_by_id('foo.com').public_pem(),
            },
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

    def test_inbox_reply_object(self, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT, mock_get, mock_post)

    def test_inbox_reply_object_wrapped(self, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED, mock_get, mock_post)

    def test_inbox_reply_create_activity(self, mock_get, mock_post):
        self._test_inbox_reply(REPLY_ACTIVITY, mock_get, mock_post)

    def _test_inbox_reply(self, as2, mock_get, mock_post):
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = app.get_response('/foo.com/inbox', method='POST',
                               body=json.dumps(as2))
        self.assertEquals(200, got.status_int, got.body)
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS, verify=False)

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

        resp = Response.get_by_id('http://this/reply http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(as2, json.loads(resp.source_as2))

    def test_inbox_like_proxy_url(self, mock_get, mock_post):
        actor = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://orig/actor',
            'type': 'Person',
            'name': 'Ms. Actor',
            'preferredUsername': 'msactor',
            'image': {'type': 'Image', 'url': 'http://orig/pic.jpg'},
        }
        mock_get.side_effect = [
            # source actor
            requests_response(actor, headers={'Content-Type': common.CONTENT_TYPE_AS2}),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        # based on example Mastodon like:
        # https://github.com/snarfed/bridgy-fed/issues/4#issuecomment-334212362
        # (reposts are very similar)
        as2_like = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://this/like#ok',
            'type': 'Like',
            'object': 'http://orig/post',
            'actor': 'http://orig/actor',
        }

        got = app.get_response('/foo.com/inbox', method='POST',
                               body=json.dumps(as2_like))
        self.assertEquals(200, got.status_int)

        as2_headers = copy.deepcopy(common.HEADERS)
        as2_headers.update(common.CONNEG_HEADERS_AS2_HTML)
        mock_get.assert_has_calls((
            call('http://orig/actor', headers=as2_headers, timeout=15),
            call('http://orig/post', headers=common.HEADERS, verify=False),
        ))

        args, kwargs = mock_post.call_args
        self.assertEquals(('http://orig/webmention',), args)
        self.assertEquals({
            # TODO
            'source': 'http://localhost/render?source=http%3A%2F%2Fthis%2Flike__ok&target=http%3A%2F%2Forig%2Fpost',
            'target': 'http://orig/post',
        }, kwargs['data'])

        resp = Response.get_by_id('http://this/like__ok http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        as2_like['actor'] = actor
        self.assertEqual(as2_like, json.loads(resp.source_as2))

    def test_inbox_unsupported_type(self, mock_get, mock_post):
        got = app.get_response('/foo.com/inbox', method='POST', body=json.dumps({
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'id': 'https://xoxo.zone/users/aaronpk#follows/40',
            'type': 'Follow',
            'actor': 'https://xoxo.zone/users/aaronpk',
            'object': 'http://snarfed.org/',
        }))
        self.assertEquals(501, got.status_int)
