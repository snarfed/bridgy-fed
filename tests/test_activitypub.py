# coding=utf-8
"""Unit tests for activitypub.py.

TODO: test error handling
"""
import copy
from unittest.mock import call, patch

from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

import activitypub
from app import application
import common
from models import Follower, MagicKey, Response
from . import testutil


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
REPLY_OBJECT_WRAPPED['inReplyTo'] = 'http://localhost:80/r/orig/post'
REPLY = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://this/reply/as2',
    'object': REPLY_OBJECT,
}
MENTION_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': '☕ mentions of @other @target@target',
    'id': 'http://this/mention/id',
    'url': 'http://this/mention',
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
    'cc': [
        'https://this/author/followers',
        'https://masto.foo/@other',
        'http://localhost/target',  # redirect-wrapped
    ],
    'tag': [{
        'type': 'Mention',
        'href': 'https://masto.foo/@other',
        'name': '@other@masto.foo',
    }, {
        'type': 'Mention',
        'href': 'http://localhost/target',  # redirect-wrapped
        'name': '@target@target',
    }],
}
MENTION = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://this/mention/as2',
    'object': MENTION_OBJECT,
}
# based on example Mastodon like:
# https://github.com/snarfed/bridgy-fed/issues/4#issuecomment-334212362
# (reposts are very similar)
LIKE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://this/like#ok',
    'type': 'Like',
    'object': 'http://orig/post',
    'actor': 'http://orig/actor',
}
LIKE_WRAPPED = copy.deepcopy(LIKE)
LIKE_WRAPPED['object'] = 'http://localhost/r/http://orig/post'
LIKE_WITH_ACTOR = copy.deepcopy(LIKE)
LIKE_WITH_ACTOR['actor'] = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://orig/actor',
    'type': 'Person',
    'name': 'Ms. Actor',
    'preferredUsername': 'msactor',
    'image': {'type': 'Image', 'url': 'http://orig/pic.jpg'},
}

FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/6d1a',
    'type': 'Follow',
    'actor': 'https://mastodon.social/users/swentel',
    'object': 'https://realize.be/',
}
FOLLOW_WRAPPED = copy.deepcopy(FOLLOW)
FOLLOW_WRAPPED['object'] = 'http://localhost/realize.be'
ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': FOLLOW['actor'],
    'type': 'Person',
    'inbox': 'http://follower/inbox',
}
FOLLOW_WITH_ACTOR = copy.deepcopy(FOLLOW)
FOLLOW_WITH_ACTOR['actor'] = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': FOLLOW['actor'],
    'type': 'Person',
    'inbox': 'http://follower/inbox',
}
FOLLOW_WRAPPED_WITH_ACTOR = copy.deepcopy(FOLLOW_WRAPPED)
FOLLOW_WRAPPED_WITH_ACTOR['actor'] = FOLLOW_WITH_ACTOR['actor']

ACCEPT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Accept',
    'id': 'tag:localhost:80:accept/realize.be/https://mastodon.social/6d1a',
    'actor': 'http://localhost/realize.be',
    'object': {
        'type': 'Follow',
        'actor': 'https://mastodon.social/users/swentel',
        'object': 'http://localhost/realize.be',
    }
}

UNDO_FOLLOW_WRAPPED = {
  '@context': 'https://www.w3.org/ns/activitystreams',
  'id': 'https://mastodon.social/6d1b',
  'type': 'Undo',
  'actor': 'https://mastodon.social/users/swentel',
  'object': FOLLOW_WRAPPED,
}

DELETE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/users/swentel#delete',
    'type': 'Delete',
    'actor': 'https://mastodon.social/users/swentel',
    'object': 'https://mastodon.social/users/swentel',
}


@patch('requests.post')
@patch('requests.get')
@patch('requests.head')
class ActivityPubTest(testutil.TestCase):

    def setUp(self):
        super(ActivityPubTest, self).setUp()
        activitypub.ActorHandler.get.cache_clear()

    def test_actor_handler(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">Mrs. ☕ Foo</a>
</body>
""", url='https://foo.com/', content_type=common.CONTENT_TYPE_HTML)

        got = application.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         stream=True, timeout=util.HTTP_TIMEOUT)
        self.assertEqual(200, got.status_int)
        type = got.headers['Content-Type']
        self.assertTrue(type.startswith(common.CONTENT_TYPE_AS2), type)
        self.assertEqual({
            '@context': [
                'https://www.w3.org/ns/activitystreams',
                'https://w3id.org/security/v1',
            ],
            'type' : 'Person',
            'name': 'Mrs. ☕ Foo',
            'summary': '',
            'preferredUsername': 'foo.com',
            'id': 'http://localhost/foo.com',
            'url': 'http://localhost/r/https://foo.com/about-me',
            'inbox': 'http://localhost/foo.com/inbox',
            'outbox': 'http://localhost/foo.com/outbox',
            'following': 'http://localhost/foo.com/following',
            'followers': 'http://localhost/foo.com/followers',
            'publicKey': {
                'id': 'foo.com',
                'publicKeyPem': MagicKey.get_by_id('foo.com').public_pem().decode(),
            },
        }, json_loads(got.body))

    def test_actor_handler_no_hcard(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
""")

        got = application.get_response('/foo.com')
        mock_get.assert_called_once_with('http://foo.com/', headers=common.HEADERS,
                                         stream=True, timeout=util.HTTP_TIMEOUT)
        self.assertEqual(400, got.status_int)
        self.assertIn('representative h-card', got.body.decode())

    def test_actor_blocked_tld(self, _, __, ___):
        got = application.get_response('/foo.json')
        self.assertEqual(404, got.status_int)

    def test_inbox_reply_object(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT, REPLY_OBJECT, *mocks)

    def test_inbox_reply_object_wrapped(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED, REPLY_OBJECT, *mocks)

    def test_inbox_reply_create_activity(self, *mocks):
        self._test_inbox_reply(REPLY, REPLY, *mocks)

    def _test_inbox_reply(self, as2, expected_as2, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://orig/post')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(as2).encode())
        self.assertEqual(200, got.status_int, got.body)
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS, timeout=15, stream=True)

        expected_headers = copy.deepcopy(common.HEADERS)
        expected_headers['Accept'] = '*/*'
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'http://localhost/render?source=http%3A%2F%2Fthis%2Freply&target=http%3A%2F%2Forig%2Fpost',
                'target': 'http://orig/post',
            },
            allow_redirects=False, timeout=15, stream=True,
            headers=expected_headers)

        resp = Response.get_by_id('http://this/reply http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(expected_as2, json_loads(resp.source_as2))

    def test_inbox_reply_drop_self_domain_target(self, mock_head, mock_get, mock_post):
        reply = copy.deepcopy(REPLY_OBJECT)
        # same domain as source; should drop
        reply['inReplyTo'] = 'http://localhost/this',

        mock_head.return_value = requests_response(url='http://this/')

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(reply).encode())
        self.assertEqual(200, got.status_int, got.body)

        mock_head.assert_called_once_with(
            'http://this', allow_redirects=True, stream=True, timeout=15)
        mock_get.assert_not_called()
        mock_post.assert_not_called()
        self.assertEqual(0, Response.query().count())

    def test_inbox_mention_object(self, *mocks):
        self._test_inbox_mention(MENTION_OBJECT, *mocks)

    def test_inbox_mention_create_activity(self, *mocks):
        self._test_inbox_mention(MENTION, *mocks)

    def _test_inbox_mention(self, as2, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(as2).encode())
        self.assertEqual(200, got.status_int, got.body)
        mock_get.assert_called_once_with(
            'http://target/', headers=common.HEADERS, timeout=15, stream=True)

        expected_headers = copy.deepcopy(common.HEADERS)
        expected_headers['Accept'] = '*/*'
        mock_post.assert_called_once_with(
            'http://target/webmention',
            data={
                'source': 'http://localhost/render?source=http%3A%2F%2Fthis%2Fmention&target=http%3A%2F%2Ftarget%2F',
                'target': 'http://target/',
            },
            allow_redirects=False, timeout=15, stream=True,
            headers=expected_headers)

        resp = Response.get_by_id('http://this/mention http://target/')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.handler.redirect_unwrap(as2), json_loads(resp.source_as2))

    def test_inbox_like(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://orig/post')
        mock_get.side_effect = [
            # source actor
            requests_response(LIKE_WITH_ACTOR['actor'], headers={'Content-Type': common.CONTENT_TYPE_AS2}),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        got = application.get_response('/foo.com/inbox', method='POST',
                                       body=json_dumps(LIKE_WRAPPED).encode())
        self.assertEqual(200, got.status_int)

        as2_headers = copy.deepcopy(common.HEADERS)
        as2_headers.update(common.CONNEG_HEADERS_AS2_HTML)
        mock_get.assert_has_calls((
            call('http://orig/actor', headers=as2_headers, stream=True, timeout=15),
            call('http://orig/post', headers=common.HEADERS, stream=True, timeout=15),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('http://orig/webmention',), args)
        self.assertEqual({
            # TODO
            'source': 'http://localhost/render?source=http%3A%2F%2Fthis%2Flike__ok&target=http%3A%2F%2Forig%2Fpost',
            'target': 'http://orig/post',
        }, kwargs['data'])

        resp = Response.get_by_id('http://this/like__ok http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(LIKE_WITH_ACTOR, json_loads(resp.source_as2))

    def test_inbox_follow_accept(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')
        mock_get.side_effect = [
            # source actor
            requests_response(FOLLOW_WITH_ACTOR['actor'],
                              content_type=common.CONTENT_TYPE_AS2),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(FOLLOW_WRAPPED).encode())
        self.assertEqual(200, got.status_int)

        as2_headers = copy.deepcopy(common.HEADERS)
        as2_headers.update(common.CONNEG_HEADERS_AS2_HTML)
        mock_get.assert_has_calls((
            call(FOLLOW['actor'], headers=as2_headers, stream=True, timeout=15),
        ))

        # check AP Accept
        self.assertEqual(2, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('http://follower/inbox',), args)
        self.assertEqual(ACCEPT, json_loads(kwargs['data']))

        # check webmention
        args, kwargs = mock_post.call_args_list[1]
        self.assertEqual(('https://realize.be/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/render?source=https%3A%2F%2Fmastodon.social%2F6d1a&target=https%3A%2F%2Frealize.be%2F',
            'target': 'https://realize.be/',
        }, kwargs['data'])

        resp = Response.get_by_id('https://mastodon.social/6d1a https://realize.be/')
        self.assertEqual('in', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(FOLLOW_WITH_ACTOR, json_loads(resp.source_as2))

        # check that we stored a Follower object
        follower = Follower.get_by_id('realize.be %s' % (FOLLOW['actor']))
        self.assertEqual('active', follower.status)
        self.assertEqual(FOLLOW_WRAPPED_WITH_ACTOR, json_loads(follower.last_follow))

    def test_inbox_undo_follow(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')

        Follower(id=Follower._id('realize.be', FOLLOW['actor'])).put()

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(UNDO_FOLLOW_WRAPPED).encode())
        self.assertEqual(200, got.status_int)

        follower = Follower.get_by_id('realize.be %s' % FOLLOW['actor'])
        self.assertEqual('inactive', follower.status)

    def test_inbox_undo_follow_doesnt_exist(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(UNDO_FOLLOW_WRAPPED).encode())
        self.assertEqual(200, got.status_int)

    def test_inbox_undo_follow_inactive(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')
        Follower(id=Follower._id('realize.be', 'https://mastodon.social/users/swentel'),
                 status='inactive').put()

        got = application.get_response('/foo.com/inbox', method='POST',
                               body=json_dumps(UNDO_FOLLOW_WRAPPED).encode())
        self.assertEqual(200, got.status_int)

    def test_inbox_unsupported_type(self, *_):
        got = application.get_response('/foo.com/inbox', method='POST', body=json_dumps({
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'id': 'https://xoxo.zone/users/aaronpk#follows/40',
            'type': 'Block',
            'actor': 'https://xoxo.zone/users/aaronpk',
            'object': 'http://snarfed.org/',
        }).encode())
        self.assertEqual(501, got.status_int)

    def test_inbox_delete_actor(self, mock_head, mock_get, mock_post):
        follower = Follower.get_or_create('realize.be', DELETE['actor'])
        Follower.get_or_create('snarfed.org', DELETE['actor'])
        # other unrelated follower
        other = Follower.get_or_create('realize.be', 'https://mas.to/users/other')
        self.assertEqual(3, Follower.query().count())

        got = application.get_response('/realize.be/inbox', method='POST',
                               body=json_dumps(DELETE).encode())
        self.assertEqual(200, got.status_int)

        # TODO: bring back
        # self.assertEqual([other], Follower.query().fetch())
