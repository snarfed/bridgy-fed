# coding=utf-8
"""Unit tests for activitypub.py."""
import copy
from datetime import datetime, timedelta
from unittest.mock import ANY, call, patch

from granary import as2
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from urllib3.exceptions import ReadTimeoutError

import activitypub
import common
from models import Follower, Object, Target, User
from . import testutil

ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/users/swentel',
    'type': 'Person',
    'inbox': 'http://follower/inbox',
}
REPLY_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': 'A ☕ reply',
    'id': 'http://th.is/reply/id',
    'url': 'http://th.is/reply',
    'inReplyTo': 'http://or.ig/post',
    'to': [as2.PUBLIC_AUDIENCE],
}
REPLY_OBJECT_WRAPPED = copy.deepcopy(REPLY_OBJECT)
REPLY_OBJECT_WRAPPED['inReplyTo'] = 'http://localhost/r/http://or.ig/post'
REPLY = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://th.is/reply/as2',
    'object': REPLY_OBJECT,
}
NOTE_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': '☕ just a normal post',
    'id': 'http://th.is/note/id',
    'url': 'http://th.is/note',
    'to': [as2.PUBLIC_AUDIENCE],
    'cc': [
        'https://th.is/author/followers',
        'https://masto.foo/@other',
        'http://localhost/target',  # redirect-wrapped
    ],
}
NOTE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://th.is/note/as2',
    'actor': 'https://masto.foo/@author',
    'object': NOTE_OBJECT,
}
MENTION_OBJECT = copy.deepcopy(NOTE_OBJECT)
MENTION_OBJECT.update({
    'id': 'http://th.is/mention/id',
    'url': 'http://th.is/mention',
    'tag': [{
        'type': 'Mention',
        'href': 'https://masto.foo/@other',
        'name': '@other@masto.foo',
    }, {
        'type': 'Mention',
        'href': 'http://localhost/tar.get',  # redirect-wrapped
        'name': '@tar.get@tar.get',
    }],
})
MENTION = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://th.is/mention/as2',
    'object': MENTION_OBJECT,
}
# based on example Mastodon like:
# https://github.com/snarfed/bridgy-fed/issues/4#issuecomment-334212362
# (reposts are very similar)
LIKE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://th.is/like#ok',
    'type': 'Like',
    'object': 'http://or.ig/post',
    'actor': 'http://or.ig/actor',
}
LIKE_WRAPPED = copy.deepcopy(LIKE)
LIKE_WRAPPED['object'] = 'http://localhost/r/http://or.ig/post'
LIKE_WITH_ACTOR = copy.deepcopy(LIKE)
# TODO: use ACTOR instead
LIKE_WITH_ACTOR['actor'] = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://or.ig/actor',
    'type': 'Person',
    'name': 'Ms. Actor',
    'preferredUsername': 'msactor',
    'image': {'type': 'Image', 'url': 'http://or.ig/pic.jpg'},
}

# repost of fediverse post, should be delivered to followers
REPOST = {
  '@context': 'https://www.w3.org/ns/activitystreams',
  'id': 'https://th.is/users/alice/statuses/654/activity',
  'type': 'Announce',
  'actor': ACTOR['id'],
  'object': NOTE_OBJECT['id'],
  'published': '2023-02-08T17:44:16Z',
  'to': ['https://www.w3.org/ns/activitystreams#Public'],
}
REPOST_FULL = {
    **REPOST,
    'actor': ACTOR,
    'object': NOTE_OBJECT,
}

FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/6d1a',
    'type': 'Follow',
    'actor': ACTOR['id'],
    'object': 'https://foo.com/',
}
FOLLOW_WRAPPED = copy.deepcopy(FOLLOW)
FOLLOW_WRAPPED['object'] = 'http://localhost/foo.com'
FOLLOW_WITH_ACTOR = copy.deepcopy(FOLLOW)
FOLLOW_WITH_ACTOR['actor'] = ACTOR
FOLLOW_WRAPPED_WITH_ACTOR = copy.deepcopy(FOLLOW_WRAPPED)
FOLLOW_WRAPPED_WITH_ACTOR['actor'] = ACTOR
FOLLOW_WITH_OBJECT = copy.deepcopy(FOLLOW)
FOLLOW_WITH_OBJECT['object'] = ACTOR

ACCEPT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Accept',
    'id': 'tag:fed.brid.gy:accept/foo.com/https://mastodon.social/6d1a',
    'actor': 'http://localhost/foo.com',
    'object': {
        'type': 'Follow',
        'actor': 'https://mastodon.social/users/swentel',
        'object': 'http://localhost/foo.com',
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

UPDATE_PERSON = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://a/person#update',
    'type': 'Update',
    'actor': 'https://mastodon.social/users/swentel',
    'object': {
        'type': 'Person',
        'id': 'https://a/person',
    },
}
UPDATE_NOTE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://a/note#update',
    'type': 'Update',
    'actor': 'https://mastodon.social/users/swentel',
    'object': {
        'type': 'Note',
        'id': 'https://a/note',
    },
}

@patch('requests.post')
@patch('requests.get')
@patch('requests.head')
class ActivityPubTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('foo.com')

    def test_actor(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">Mrs. ☕ Foo</a>
</body>
""", url='https://foo.com/', content_type=common.CONTENT_TYPE_HTML)

        got = self.client.get('/foo.com')
        self.assert_req(mock_get, 'https://foo.com/')
        self.assertEqual(200, got.status_code)
        type = got.headers['Content-Type']
        self.assertTrue(type.startswith(as2.CONTENT_TYPE), type)
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
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'Mrs. ☕ Foo',
                'value': '<a rel=\"me\" href="https://foo.com/about-me">foo.com/about-me</a>',
            }],
            'inbox': 'http://localhost/foo.com/inbox',
            'outbox': 'http://localhost/foo.com/outbox',
            'following': 'http://localhost/foo.com/following',
            'followers': 'http://localhost/foo.com/followers',
            'endpoints': {
                'sharedInbox': 'http://localhost/inbox',
            },
            'publicKey': {
                'id': 'http://localhost/foo.com',
                'owner': 'http://localhost/foo.com',
                'publicKeyPem': User.get_by_id('foo.com').public_pem().decode(),
            },
        }, got.json)

    def test_actor_rel_me_links(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<div class="h-card">
<a class="u-url" rel="me" href="/about-me">Mrs. ☕ Foo</a>
<a class="u-url" rel="me" href="/">should be ignored</a>
<a class="u-url" rel="me" href="http://one" title="one title">
  one text
</a>
<a class="u-url" rel="me" href="https://two" title=" two title "> </a>
</div>
</body>
""", url='https://foo.com/', content_type=common.CONTENT_TYPE_HTML)

        got = self.client.get('/foo.com')
        self.assertEqual(200, got.status_code)
        self.assertEqual([{
            'type': 'PropertyValue',
            'name': 'Mrs. ☕ Foo',
            'value': '<a rel="me" href="https://foo.com/about-me">foo.com/about-me</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'Web site',
            'value': '<a rel="me" href="https://foo.com/">foo.com</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'one text',
            'value': '<a rel="me" href="http://one">one</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'two title',
            'value': '<a rel="me" href="https://two">two</a>',
        }], got.json['attachment'])

    def test_actor_no_hcard(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
""")

        got = self.client.get('/foo.com')
        self.assert_req(mock_get, 'https://foo.com/')
        self.assertEqual(400, got.status_code)
        self.assertIn('representative h-card', got.get_data(as_text=True))

    def test_actor_override_preferredUsername(self, _, mock_get, __):
        mock_get.return_value = requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">
  <span class="p-nickname">Nick</span>
</a>
</body>
""", url='https://foo.com/', content_type=common.CONTENT_TYPE_HTML)

        got = self.client.get('/foo.com')
        self.assertEqual(200, got.status_code)
        self.assertEqual('foo.com', got.json['preferredUsername'])

    def test_actor_blocked_tld(self, _, __, ___):
        got = self.client.get('/foo.json')
        self.assertEqual(404, got.status_code)

    def test_actor_bad_domain(self, _, mock_get, ___):
        # https://console.cloud.google.com/errors/detail/CKGv-b6impW3Jg;time=P30D?project=bridgy-federated
        mock_get.side_effect = [
            ValueError('Invalid IPv6 URL'),
        ]
        got = self.client.get('/foo.com')
        self.assertEqual(400, got.status_code)

    def test_actor_no_user(self, *mocks):
        got = self.client.get('/nope.com')
        self.assertEqual(404, got.status_code)

    def test_individual_inbox_no_user(self, *mocks):
        got = self.client.post('/nope.com/inbox', json=REPLY)
        self.assertEqual(404, got.status_code)

    def test_inbox_activity_without_id(self, *_):
        note = copy.deepcopy(NOTE)
        del note['id']
        resp = self.client.post('/inbox', json=note)
        self.assertEqual(400, resp.status_code)

    def test_inbox_reply_object(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT,
                               {'as2': REPLY_OBJECT,
                                'type': 'comment',
                                'labels': ['notification']},
                               *mocks)

    def test_inbox_reply_object_wrapped(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED,
                               {'as2': REPLY_OBJECT,
                                'type': 'comment',
                                'labels': ['notification']},
                               *mocks)

    def test_inbox_reply_create_activity(self, *mocks):
        self._test_inbox_reply(REPLY,
                               {'as2': REPLY,
                                'type': 'post',
                                'object_ids': [REPLY_OBJECT['id']],
                                'labels': ['notification', 'activity'],
                                },
                               *mocks)

    def _test_inbox_reply(self, reply, expected_props, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://or.ig/post')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=reply)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'http://or.ig/post')
        self.assert_req(
            mock_post,
            'http://or.ig/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': 'http://localhost/render?id=http%3A%2F%2Fth.is%2Freply',
                'target': 'http://or.ig/post',
            },
        )

        self.assert_object('http://th.is/reply',
                           domains=['or.ig'],
                           source_protocol='activitypub',
                           status='complete',
                           as1=as2.to_as1(expected_props['as2']),
                           delivered=['http://or.ig/post'],
                           **expected_props)

    def test_inbox_reply_to_self_domain(self, mock_head, mock_get, mock_post):
        self._test_inbox_ignore_reply_to('http://localhost/th.is',
                                         mock_head, mock_get, mock_post)
        self.assert_req(mock_head, 'http://th.is', allow_redirects=True)

    def test_inbox_reply_to_in_blocklist(self, *mocks):
        self._test_inbox_ignore_reply_to('https://twitter.com/foo', *mocks)

    def _test_inbox_ignore_reply_to(self, reply_to, mock_head, mock_get, mock_post):
        reply = copy.deepcopy(REPLY_OBJECT)
        reply['inReplyTo'] = reply_to

        mock_head.return_value = requests_response(url='http://th.is/')

        got = self.client.post('/foo.com/inbox', json=reply)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        mock_get.assert_not_called()
        mock_post.assert_not_called()

    def test_individual_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/foo.com/inbox', *mocks)

    def test_shared_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/inbox', *mocks)

    def _test_inbox_create_obj(self, path, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')
        Follower.get_or_create('http://other/actor', 'bar.com')
        Follower.get_or_create(ACTOR['id'], 'baz.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor
        mock_post.return_value = requests_response()

        got = self.client.post(path, json=NOTE)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        expected_as2 = common.redirect_unwrap({
            **NOTE,
            'actor': ACTOR,
        })

        self.assert_object('http://th.is/note/as2',
                           source_protocol='activitypub',
                           status='complete',
                           as2=expected_as2,
                           as1=as2.to_as1(expected_as2),
                           domains=['foo.com', 'baz.com'],
                           type='post',
                           labels=['feed', 'activity'],
                           object_ids=[NOTE_OBJECT['id']])

    def test_shared_inbox_repost(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')
        Follower.get_or_create(ACTOR['id'], 'baz.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),  # source actor
            self.as2_resp(NOTE_OBJECT),  # object of repost
        ]
        mock_post.return_value = requests_response()  # webmention

        got = self.client.post('/inbox', json=REPOST)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        self.assert_object(REPOST['id'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=REPOST_FULL,
                           as1=as2.to_as1(REPOST_FULL),
                           domains=['foo.com', 'baz.com'],
                           type='share',
                           labels=['feed', 'activity'],
                           object_ids=[REPOST['object']])

    def test_inbox_not_public(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor

        not_public = copy.deepcopy(NOTE)
        del not_public['object']['to']

        got = self.client.post('/foo.com/inbox', json=not_public)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        obj = Object.get_by_id(not_public['id'])
        self.assertEqual([], obj.labels)
        self.assertEqual([], obj.domains)

        self.assertIsNone(Object.get_by_id(not_public['object']['id']))

    def test_inbox_mention_object(self, *mocks):
        self._test_inbox_mention(
            MENTION_OBJECT,
            {
                'type': 'note',  # not mention (?)
                'labels': ['notification'],
            },
            *mocks,
        )

    def test_inbox_mention_create_activity(self, *mocks):
        self._test_inbox_mention(
            MENTION,
            {
                'type': 'post',  # not mention (?)
                'object_ids': [MENTION_OBJECT['id']],
                'labels': ['notification', 'activity'],
            },
            *mocks,
        )

    def _test_inbox_mention(self, mention, expected_props, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://tar.get')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=mention)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'http://tar.get/')
        self.assert_req(
            mock_post,
            'http://tar.get/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': 'http://localhost/render?id=http%3A%2F%2Fth.is%2Fmention',
                'target': 'http://tar.get/',
            },
        )

        expected_as2 = common.redirect_unwrap(mention)
        self.assert_object('http://th.is/mention',
                           domains=['tar.get'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=expected_as2,
                           as1=as2.to_as1(expected_as2),
                           delivered=['http://tar.get/'],
                           **expected_props)

    def test_inbox_like(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://or.ig/post')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=LIKE)
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.as2_req('http://or.ig/actor'),
            self.req('http://or.ig/post'),
        )),

        args, kwargs = mock_post.call_args
        self.assertEqual(('http://or.ig/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/render?id=http%3A%2F%2Fth.is%2Flike%23ok',
            'target': 'http://or.ig/post',
        }, kwargs['data'])

        self.assert_object('http://th.is/like#ok',
                           domains=['or.ig'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=LIKE_WITH_ACTOR,
                           as1=as2.to_as1(LIKE_WITH_ACTOR),
                           delivered=['http://or.ig/post'],
                           type='like',
                           labels=['notification', 'activity'],
                           object_ids=[LIKE['object']])

    def test_inbox_follow_accept_with_id(self, *mocks):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT, *mocks)

        follow = copy.deepcopy(FOLLOW_WITH_ACTOR)
        follow['url'] = 'https://mastodon.social/users/swentel#followed-https://foo.com/'

        self.assert_object('https://mastodon.social/6d1a',
                           domains=['foo.com'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=follow,
                           as1=as2.to_as1(follow),
                           delivered=['https://foo.com/'],
                           type='follow',
                           labels=['notification', 'activity'],
                           object_ids=[FOLLOW['object']])

        follower = Follower.query().get()
        self.assertEqual(FOLLOW_WRAPPED_WITH_ACTOR, json_loads(follower.last_follow))

    def test_inbox_follow_accept_with_object(self, *mocks):
        wrapped_user = {
            'id': FOLLOW_WRAPPED['object'],
            'url': FOLLOW_WRAPPED['object'],
        }
        unwrapped_user = {
            'id': FOLLOW['object'],
            'url': FOLLOW['object'],
        }

        follow = copy.deepcopy(FOLLOW_WRAPPED)
        follow['object'] = wrapped_user

        accept = copy.deepcopy(ACCEPT)
        accept['actor'] = accept['object']['object'] = wrapped_user

        self._test_inbox_follow_accept(follow, accept, *mocks)

        follower = Follower.query().get()
        follow.update({
            'actor': ACTOR,
            'object': wrapped_user,
        })
        self.assertEqual(follow, json_loads(follower.last_follow))

        follow.update({
            'actor': FOLLOW_WITH_ACTOR['actor'],
            'object': unwrapped_user,
            'url': 'https://mastodon.social/users/swentel#followed-https://foo.com/',
        })
        self.assert_object('https://mastodon.social/6d1a',
                           domains=['foo.com'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=follow,
                           as1=as2.to_as1(follow),
                           delivered=['https://foo.com/'],
                           type='follow',
                           labels=['notification', 'activity'],
                           object_ids=[FOLLOW['object']])

    def _test_inbox_follow_accept(self, follow_as2, accept_as2,
                                  mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(FOLLOW_WITH_ACTOR['actor']),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=follow_as2)
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.as2_req(FOLLOW['actor']),
        ))

        # check AP Accept
        self.assertEqual(2, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('http://follower/inbox',), args)
        self.assertEqual(accept_as2, json_loads(kwargs['data']))

        # check webmention
        args, kwargs = mock_post.call_args_list[1]
        self.assertEqual(('https://foo.com/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/render?id=https%3A%2F%2Fmastodon.social%2F6d1a',
            'target': 'https://foo.com/',
        }, kwargs['data'])

        # check that we stored a Follower object
        follower = Follower.get_by_id(f'foo.com {FOLLOW["actor"]}')
        self.assertEqual('active', follower.status)

    def test_inbox_follow_use_instead_strip_www(self, mock_head, mock_get, mock_post):
        User.get_or_create('www.foo.com', use_instead=self.user.key).put()

        mock_head.return_value = requests_response(url='https://www.foo.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(ACTOR),
            # target post webmention discovery
            requests_response('<html></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        # check that the Follower doesn't have www
        follower = Follower.get_by_id(f'foo.com {ACTOR["id"]}')
        self.assertEqual('active', follower.status)
        self.assertEqual(FOLLOW_WRAPPED_WITH_ACTOR, json_loads(follower.last_follow))

    def test_inbox_undo_follow(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')

        Follower.get_or_create('foo.com', ACTOR['id'])

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        follower = Follower.get_by_id(f'foo.com {FOLLOW["actor"]}')
        self.assertEqual('inactive', follower.status)

    def test_inbox_follow_inactive(self, mock_head, mock_get, mock_post):
        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(FOLLOW_WITH_ACTOR['actor']),
            # target post webmention discovery
            requests_response(
                '<html><head><link rel="webmention" href="/webmention"></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        # check that the Follower is now active
        follower = Follower.get_by_id(f'foo.com {FOLLOW["actor"]}')
        self.assertEqual('active', follower.status)

    def test_inbox_undo_follow_doesnt_exist(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_inactive(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_composite_object(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        undo_follow = copy.deepcopy(UNDO_FOLLOW_WRAPPED)
        undo_follow['object']['object'] = {'id': undo_follow['object']['object']}
        got = self.client.post('/foo.com/inbox', json=undo_follow)
        self.assertEqual(200, got.status_code)

    def test_inbox_unsupported_type(self, *_):
        got = self.client.post('/foo.com/inbox', json={
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'id': 'https://xoxo.zone/users/aaronpk#follows/40',
            'type': 'Block',
            'actor': 'https://xoxo.zone/users/aaronpk',
            'object': 'http://snarfed.org/',
        })
        self.assertEqual(501, got.status_code)

    def test_inbox_bad_object_url(self, mock_head, mock_get, mock_post):
        # https://console.cloud.google.com/errors/detail/CMKn7tqbq-GIRA;time=P30D?project=bridgy-federated
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor

        id = 'https://mastodon.social/users/tmichellemoore#likes/56486252'
        bad_url = 'http://localhost/r/Testing \u2013 Brid.gy \u2013 Post to Mastodon 3'
        got = self.client.post('/foo.com/inbox', json={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': id,
            'type': 'Like',
            'actor': ACTOR['id'],
            'object': bad_url,
        })

        # bad object, should ignore activity
        self.assertEqual(200, got.status_code)
        mock_post.assert_not_called()

        obj = Object.get_by_id(id)
        self.assertEqual([], obj.labels)
        self.assertEqual([], obj.domains)

        self.assertIsNone(Object.get_by_id(bad_url))

    def test_delete_actor(self, _, __, ___):
        follower = Follower.get_or_create('foo.com', DELETE['actor'])
        followee = Follower.get_or_create(DELETE['actor'], 'snarfed.org')
        # other unrelated follower
        other = Follower.get_or_create('foo.com', 'https://mas.to/users/other')
        self.assertEqual(3, Follower.query().count())

        got = self.client.post('/inbox', json=DELETE)
        self.assertEqual(200, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

    def test_delete_note(self, _, __, ___):
        key = Object(id='http://an/obj', as1='{}').put()

        delete = {
            **DELETE,
            'object': 'http://an/obj',
        }
        resp = self.client.post('/inbox', json=delete)
        self.assertEqual(200, resp.status_code)
        self.assertTrue(key.get().deleted)
        self.assert_object(delete['id'], as2=delete, as1=as2.to_as1(delete),
                           type='delete', source_protocol='activitypub',
                           status='complete')

    def test_update_note(self, *_):
        Object(id='https://a/note', as1='{}').put()
        self._test_update()

    def test_update_unknown(self, *_):
        self._test_update()

    def _test_update(self):
        resp = self.client.post('/inbox', json=UPDATE_NOTE)
        self.assertEqual(200, resp.status_code)

        obj = UPDATE_NOTE['object']
        self.assert_object('https://a/note', type='note', as2=obj,
                           as1=as2.to_as1(obj), source_protocol='activitypub')
        self.assert_object(UPDATE_NOTE['id'], source_protocol='activitypub',
                           type='update', status='complete', as2=UPDATE_NOTE,
                           as1=as2.to_as1(UPDATE_NOTE))

    def test_inbox_webmention_discovery_connection_fails(self, mock_head,
                                                         mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # target post webmention discovery
            ReadTimeoutError(None, None, None),
        ]

        got = self.client.post('/foo.com/inbox', json=LIKE)
        self.assertEqual(504, got.status_code)

    def test_inbox_no_webmention_endpoint(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # target post webmention discovery
            requests_response('<html><body>foo</body></html>'),
        ]

        got = self.client.post('/foo.com/inbox', json=LIKE)
        self.assertEqual(200, got.status_code)

        self.assert_object('http://th.is/like#ok',
                           domains=['or.ig'],
                           source_protocol='activitypub',
                           status='ignored',
                           as2=LIKE_WITH_ACTOR,
                           as1=as2.to_as1(LIKE_WITH_ACTOR),
                           type='like',
                           labels=['notification', 'activity'],
                           object_ids=[LIKE['object']])

    def test_inbox_id_already_seen(self, *mocks):
        obj_key = Object(id=FOLLOW_WRAPPED['id'], as1='{}').put()

        got = self.client.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(204, got.status_code)
        self.assertEqual(0, Follower.query().count())

        # second time should use in memory cache
        obj_key.delete()
        got = self.client.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(204, got.status_code)
        self.assertEqual(0, Follower.query().count())

    def test_followers_collection_unknown_user(self, *args):
        resp = self.client.get('/nope.com/followers')
        self.assertEqual(404, resp.status_code)

    def test_followers_collection_empty(self, *args):
        User.get_or_create('foo.com')

        resp = self.client.get('/foo.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/foo.com/followers',
            'type': 'Collection',
            'summary': "foo.com's followers",
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/foo.com/followers',
                'items': [],
            },
        }, resp.json)

    def store_followers(self):
        Follower.get_or_create('foo.com', 'https://bar.com',
                               last_follow=json_dumps(FOLLOW_WITH_ACTOR))
        Follower.get_or_create('http://other/actor', 'foo.com')
        Follower.get_or_create('foo.com', 'https://baz.com',
                               last_follow=json_dumps(FOLLOW_WITH_ACTOR))
        Follower.get_or_create('foo.com', 'baj.com', status='inactive')

    def test_followers_collection(self, *args):
        User.get_or_create('foo.com')
        self.store_followers()

        resp = self.client.get('/foo.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/foo.com/followers',
            'type': 'Collection',
            'summary': "foo.com's followers",
            'totalItems': 2,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/foo.com/followers',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('common.PAGE_SIZE', 1)
    def test_followers_collection_page(self, *args):
        User.get_or_create('foo.com')
        self.store_followers()
        before = (datetime.utcnow() + timedelta(seconds=1)).isoformat()
        next = Follower.get_by_id('foo.com https://baz.com').updated.isoformat()

        resp = self.client.get(f'/foo.com/followers?before={before}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': f'http://localhost/foo.com/followers?before={before}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/foo.com/followers',
            'next': f'http://localhost/foo.com/followers?before={next}',
            'prev': f'http://localhost/foo.com/followers?after={before}',
            'items': [ACTOR],
        }, resp.json)

    def test_following_collection_unknown_user(self, *args):
        resp = self.client.get('/nope.com/following')
        self.assertEqual(404, resp.status_code)

    def test_following_collection_empty(self, *args):
        User.get_or_create('foo.com')

        resp = self.client.get('/foo.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/foo.com/following',
            'summary': "foo.com's following",
            'type': 'Collection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/foo.com/following',
                'items': [],
            },
        }, resp.json)

    def store_following(self):
        Follower.get_or_create('https://bar.com', 'foo.com',
                               last_follow=json_dumps(FOLLOW_WITH_OBJECT))
        Follower.get_or_create('foo.com', 'http://other/actor')
        Follower.get_or_create('https://baz.com', 'foo.com',
                               last_follow=json_dumps(FOLLOW_WITH_OBJECT))
        Follower.get_or_create('baj.com', 'foo.com', status='inactive')

    def test_following_collection(self, *args):
        User.get_or_create('foo.com')
        self.store_following()

        resp = self.client.get('/foo.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/foo.com/following',
            'summary': "foo.com's following",
            'type': 'Collection',
            'totalItems': 2,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/foo.com/following',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('common.PAGE_SIZE', 1)
    def test_following_collection_page(self, *args):
        User.get_or_create('foo.com')
        self.store_following()
        after = datetime(1900, 1, 1).isoformat()
        prev = Follower.get_by_id('https://baz.com foo.com').updated.isoformat()

        resp = self.client.get(f'/foo.com/following?after={after}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': f'http://localhost/foo.com/following?after={after}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/foo.com/following',
            'prev': f'http://localhost/foo.com/following?after={prev}',
            'next': f'http://localhost/foo.com/following?before={after}',
            'items': [ACTOR],
        }, resp.json)

    def test_outbox_empty(self, _, mock_get, __):
        resp = self.client.get(f'/foo.com/outbox')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/foo.com/outbox',
            'summary': "foo.com's outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/foo.com/outbox',
                'items': [],
            },
        }, resp.json)
