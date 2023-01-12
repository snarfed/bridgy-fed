# coding=utf-8
"""Unit tests for activitypub.py.

TODO: test error handling
"""
import copy
from unittest.mock import ANY, call, patch

from granary import as2
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from urllib3.exceptions import ReadTimeoutError

import activitypub
import common
from models import Follower, User, Activity
from . import testutil

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
LIKE_WITH_ACTOR['actor'] = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://or.ig/actor',
    'type': 'Person',
    'name': 'Ms. Actor',
    'preferredUsername': 'msactor',
    'image': {'type': 'Image', 'url': 'http://or.ig/pic.jpg'},
}

ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/users/swentel',
    'type': 'Person',
    'inbox': 'http://follower/inbox',
}
FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/6d1a',
    'type': 'Follow',
    'actor': ACTOR['id'],
    'object': 'https://www.realize.be/',
}
FOLLOW_WRAPPED = copy.deepcopy(FOLLOW)
FOLLOW_WRAPPED['object'] = 'http://localhost/www.realize.be'
FOLLOW_WITH_ACTOR = copy.deepcopy(FOLLOW)
FOLLOW_WITH_ACTOR['actor'] = ACTOR
FOLLOW_WRAPPED_WITH_ACTOR = copy.deepcopy(FOLLOW_WRAPPED)
FOLLOW_WRAPPED_WITH_ACTOR['actor'] = ACTOR

ACCEPT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Accept',
    'id': 'tag:fed.brid.gy:accept/www.realize.be/https://mastodon.social/6d1a',
    'actor': 'http://localhost/www.realize.be',
    'object': {
        'type': 'Follow',
        'actor': 'https://mastodon.social/users/swentel',
        'object': 'http://localhost/www.realize.be',
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
                'name': 'Link',
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
        got = self.client.get('/snarfed.org]')
        self.assertEqual(400, got.status_code)

    def test_inbox_reply_object(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT, REPLY_OBJECT, *mocks)

    def test_inbox_reply_object_wrapped(self, *mocks):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED, REPLY_OBJECT, *mocks)

    def test_inbox_reply_create_activity(self, *mocks):
        self._test_inbox_reply(REPLY, REPLY, *mocks)

    def _test_inbox_reply(self, as2, expected_as2, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://or.ig/post')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        got = self.client.post('/foo.com/inbox', json=as2)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'http://or.ig/post')
        self.assert_req(
            mock_post,
            'http://or.ig/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': 'http://localhost/render?source=http%3A%2F%2Fth.is%2Freply&target=http%3A%2F%2For.ig%2Fpost',
                'target': 'http://or.ig/post',
            },
        )

        activity = Activity.get_by_id('http://th.is/reply http://or.ig/post')
        self.assertEqual(['or.ig'], activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('activitypub', activity.protocol)
        self.assertEqual('complete', activity.status)
        self.assertEqual(expected_as2, json_loads(activity.source_as2))

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
        self.assertEqual(0, Activity.query().count())

    def test_inbox_create_activity(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')
        Follower.get_or_create('http://other/actor', 'bar.com')
        Follower.get_or_create(ACTOR['id'], 'baz.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor
        mock_post.return_value = requests_response()

        with self.client:
            got = self.client.post('/foo.com/inbox', json=NOTE)
            self.assertEqual(200, got.status_code, got.get_data(as_text=True))

            activity = Activity.get_by_id('http://th.is/note/as2 Public')
            self.assertEqual('in', activity.direction)
            self.assertEqual('activitypub', activity.protocol)
            self.assertEqual('complete', activity.status)
            expected_as2 = copy.deepcopy(NOTE)
            expected_as2['actor'] = ACTOR
            self.assertEqual(common.redirect_unwrap(expected_as2),
                             json_loads(activity.source_as2))
            self.assert_equals(['foo.com', 'baz.com'], activity.domain)

    def test_inbox_not_public(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor

        not_public = copy.deepcopy(NOTE)
        del not_public['object']['to']

        with self.client:
            got = self.client.post('/foo.com/inbox', json=not_public)
            self.assertEqual(200, got.status_code, got.get_data(as_text=True))
            self.assertEqual(0, Activity.query().count())

    def test_inbox_mention_object(self, *mocks):
        self._test_inbox_mention(MENTION_OBJECT, *mocks)

    def test_inbox_mention_create_activity(self, *mocks):
        self._test_inbox_mention(MENTION, *mocks)

    def _test_inbox_mention(self, as2, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://tar.get')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        mock_post.return_value = requests_response()

        with self.client:
            got = self.client.post('/foo.com/inbox', json=as2)
            self.assertEqual(200, got.status_code, got.get_data(as_text=True))
            self.assert_req(mock_get, 'http://tar.get/')
            self.assert_req(
                mock_post,
                'http://tar.get/webmention',
                headers={'Accept': '*/*'},
                allow_redirects=False,
                data={
                    'source': 'http://localhost/render?source=http%3A%2F%2Fth.is%2Fmention&target=http%3A%2F%2Ftar.get%2F',
                    'target': 'http://tar.get/',
                },
            )

            activity = Activity.get_by_id('http://th.is/mention http://tar.get/')
            self.assertEqual(['tar.get'], activity.domain)
            self.assertEqual('in', activity.direction)
            self.assertEqual('activitypub', activity.protocol)
            self.assertEqual('complete', activity.status)
            self.assertEqual(common.redirect_unwrap(as2), json_loads(activity.source_as2))

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
            # TODO
            'source': 'http://localhost/render?source=http%3A%2F%2Fth.is%2Flike__ok&target=http%3A%2F%2For.ig%2Fpost',
            'target': 'http://or.ig/post',
        }, kwargs['data'])

        activity = Activity.get_by_id('http://th.is/like__ok http://or.ig/post')
        self.assertEqual(['or.ig'], activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('activitypub', activity.protocol)
        self.assertEqual('complete', activity.status)
        self.assertEqual(LIKE_WITH_ACTOR, json_loads(activity.source_as2))

    def test_inbox_follow_accept_with_id(self, mock_head, mock_get, mock_post):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT,
                                       mock_head, mock_get, mock_post)

        activity = Activity.query().get()
        follow = copy.deepcopy(FOLLOW_WITH_ACTOR)
        follow['url'] = 'https://mastodon.social/users/swentel#followed-https://www.realize.be/'

        self.assertEqual(follow, json_loads(activity.source_as2))

        follower = Follower.query().get()
        self.assertEqual(FOLLOW_WRAPPED_WITH_ACTOR, json_loads(follower.last_follow))

    def test_inbox_follow_accept_with_object(self, mock_head, mock_get, mock_post):
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

        self._test_inbox_follow_accept(follow, accept, mock_head, mock_get, mock_post)

        follower = Follower.query().get()
        follow.update({
            'actor': ACTOR,
            'object': wrapped_user,
        })
        self.assertEqual(follow, json_loads(follower.last_follow))

        activity = Activity.query().get()
        follow.update({
            'actor': FOLLOW_WITH_ACTOR['actor'],
            'object': unwrapped_user,
            'url': 'https://mastodon.social/users/swentel#followed-https://www.realize.be/',
        })
        self.assertEqual(follow, json_loads(activity.source_as2))

    def _test_inbox_follow_accept(self, follow_as2, accept_as2,
                                  mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://www.realize.be/')
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
        self.assertEqual(('https://www.realize.be/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/render?source=https%3A%2F%2Fmastodon.social%2F6d1a&target=https%3A%2F%2Fwww.realize.be%2F',
            'target': 'https://www.realize.be/',
        }, kwargs['data'])

        activity = Activity.get_by_id('https://mastodon.social/6d1a https://www.realize.be/')
        self.assertEqual(['www.realize.be'], activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('activitypub', activity.protocol)
        self.assertEqual('complete', activity.status)

        # check that we stored a Follower object
        follower = Follower.get_by_id(f'www.realize.be {FOLLOW["actor"]}')
        self.assertEqual('active', follower.status)

    def test_inbox_follow_use_instead_strip_www(self, mock_head, mock_get, mock_post):
        root = User.get_or_create('realize.be')
        User.get_or_create('www.realize.be', use_instead=root.key)

        mock_head.return_value = requests_response(url='https://www.realize.be/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(ACTOR),
            # target post webmention discovery
            requests_response('<html></html>'),
        ]
        mock_post.return_value = requests_response()

        follow = copy.deepcopy(FOLLOW_WRAPPED)
        follow['object'] = 'http://localhost/realize.be'
        got = self.client.post('/foo.com/inbox', json=follow)
        self.assertEqual(200, got.status_code)

        # check that the Follower doesn't have www
        follower = Follower.get_by_id(f'realize.be {ACTOR["id"]}')
        self.assertEqual('active', follower.status)

        follow['actor'] = ACTOR
        self.assertEqual(follow, json_loads(follower.last_follow))

    def test_inbox_undo_follow(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://www.realize.be/')

        Follower.get_or_create('www.realize.be', ACTOR['id'])

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        follower = Follower.get_by_id(f'www.realize.be {FOLLOW["actor"]}')
        self.assertEqual('inactive', follower.status)

    def test_inbox_follow_inactive(self, mock_head, mock_get, mock_post):
        Follower.get_or_create('www.realize.be', ACTOR['id'], status='inactive')

        mock_head.return_value = requests_response(url='https://www.realize.be/')
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
        follower = Follower.get_by_id(f'www.realize.be {FOLLOW["actor"]}')
        self.assertEqual('active', follower.status)

    def test_inbox_undo_follow_doesnt_exist(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_inactive(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')
        Follower.get_or_create('realize.be', ACTOR['id'], status='inactive')

        got = self.client.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_composite_object(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://realize.be/')
        Follower.get_or_create('realize.be', ACTOR['id'], status='inactive')

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
        got = self.client.post('/foo.com/inbox', json={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://mastodon.social/users/tmichellemoore#likes/56486252',
            'type': 'Like',
            'actor': ACTOR['id'],
            'object': 'http://localhost/r/Testing \u2013 Brid.gy \u2013 Post to Mastodon 3',
        })

        # bad object, should ignore activity
        self.assertEqual(200, got.status_code)
        mock_post.assert_not_called()
        self.assertEqual(0, Activity.query().count())

    def test_individual_inbox_delete_actor_noop(self, mock_head, mock_get, mock_post):
        """Deletes sent to individual users' inboxes do nothing."""
        follower = Follower.get_or_create('realize.be', DELETE['actor'])
        followee = Follower.get_or_create(DELETE['actor'], 'snarfed.org')
        # other unrelated follower
        other = Follower.get_or_create('realize.be', 'https://mas.to/users/other')
        self.assertEqual(3, Follower.query().count())

        got = self.client.post('/realize.be/inbox', json=DELETE)
        self.assertEqual(200, got.status_code)
        self.assertEqual('active', follower.key.get().status)
        self.assertEqual('active', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

    def test_shared_inbox_delete_actor(self, mock_head, mock_get, mock_post):
        """Deletes sent to the shared inbox actually deactivate followers."""
        follower = Follower.get_or_create('realize.be', DELETE['actor'])
        followee = Follower.get_or_create(DELETE['actor'], 'snarfed.org')
        # other unrelated follower
        other = Follower.get_or_create('realize.be', 'https://mas.to/users/other')
        self.assertEqual(3, Follower.query().count())

        got = self.client.post('/inbox', json=DELETE)
        self.assertEqual(200, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

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

        activity = Activity.get_by_id('http://th.is/like__ok http://or.ig/post')
        self.assertEqual(['or.ig'], activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('activitypub', activity.protocol)
        self.assertEqual('ignored', activity.status)

    def test_followers_collection_unknown_user(self, *args):
        resp = self.client.get('/foo.com/followers')
        self.assertEqual(404, resp.status_code)

    def test_followers_collection(self, *args):
        User.get_or_create('foo.com')

        resp = self.client.get('/foo.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'summary': "foo.com's followers",
            'type': 'Collection',
            'totalItems': 0,
            'items': [],
        }, resp.json)

        Follower.get_or_create('foo.com', 'bar.com')
        Follower.get_or_create('http://other/actor', 'foo.com')
        Follower.get_or_create('foo.com', 'baz.com')
        Follower.get_or_create('foo.com', 'baj.com', status='inactive')

        resp = self.client.get('/foo.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'summary': "foo.com's followers",
            'type': 'Collection',
            'totalItems': 2,
            'items': [],
# TODO
# {
#                 'type': 'Create',
#                 'actor': 'http://www.test.example/sally',
#                 'object': 'http://example.org/foo',
#             },
#             {
#                 'type': 'Like',
#                 'actor': 'http://www.test.example/joe',
#                 'object': 'http://example.org/foo',
#             }],
        }, resp.json)

    def test_following_collection_unknown_user(self, *args):
        resp = self.client.get('/foo.com/following')
        self.assertEqual(404, resp.status_code)

    def test_following_collection(self, *args):
        User.get_or_create('foo.com')

        resp = self.client.get('/foo.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'summary': "foo.com's following",
            'type': 'Collection',
            'totalItems': 0,
            'items': [],
        }, resp.json)

        Follower.get_or_create('bar.com', 'foo.com')
        Follower.get_or_create('foo.com', 'http://other/actor')
        Follower.get_or_create('baz.com', 'foo.com')
        Follower.get_or_create('baj.com', 'foo.com', status='inactive')

        resp = self.client.get('/foo.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'summary': "foo.com's following",
            'type': 'Collection',
            'totalItems': 2,
            'items': [],
        }, resp.json)
