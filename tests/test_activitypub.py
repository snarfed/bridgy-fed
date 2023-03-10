# coding=utf-8
"""Unit tests for activitypub.py."""
from base64 import b64encode
import copy
from datetime import datetime, timedelta
from hashlib import sha256
import logging
from unittest.mock import ANY, call, patch
import urllib.parse

from google.cloud import ndb
from granary import as2, microformats2
from httpsig import HeaderSigner
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from urllib3.exceptions import ReadTimeoutError
from werkzeug.exceptions import BadGateway

import activitypub
from activitypub import ActivityPub
from app import app
import common
import models
from models import Follower, Object, User
import protocol
from protocol import Protocol
from . import testutil

ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mastodon.social/users/swentel',
    'type': 'Person',
    'inbox': 'http://follower/inbox',
    'name': 'Mrs. ☕ Foo',
    'icon': {'type': 'Image', 'url': 'https://foo.com/me.jpg'},
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
  'id': 'https://mas.to/users/alice/statuses/654/activity',
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
WEBMENTION_DISCOVERY = requests_response(
    '<html><head><link rel="webmention" href="/webmention"></html>')

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


@patch('requests.post')
@patch('requests.get')
@patch('requests.head')
class ActivityPubTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('foo.com', has_hcard=True, actor_as2=ACTOR)
        with app.test_request_context('/'):
            self.key_id_obj = Object(id='http://my/key/id', as2={
                **ACTOR,
                'publicKey': {
                    'id': 'http://my/key/id#unused',
                    'owner': 'http://own/er',
                    'publicKeyPem': self.user.public_pem().decode(),
                },
            }).put()

    def sign(self, path, body):
        """Constructs HTTP Signature, returns headers."""
        digest = b64encode(sha256(body.encode()).digest()).decode()
        headers = {
            'Date': 'Sun, 02 Jan 2022 03:04:05 GMT',
            'Host': 'localhost',
            'Content-Type': as2.CONTENT_TYPE,
            'Digest': f'SHA-256={digest}',
        }
        hs = HeaderSigner('http://my/key/id#unused', self.user.private_pem().decode(),
                          algorithm='rsa-sha256', sign_header='signature',
                          headers=('Date', 'Host', 'Digest', '(request-target)'))
        return hs.sign(headers, method='POST', path=path)

    def post(self, path, json=None):
        """Wrapper around self.client.post that adds signature."""
        body = json_dumps(json)
        return self.client.post(path, data=body, headers=self.sign(path, body))

    def test_actor(self, *_):
        got = self.client.get('/foo.com')
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
            'url': 'http://localhost/r/https://foo.com/',
            'icon': {'type': 'Image', 'url': 'https://foo.com/me.jpg'},
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
                'publicKeyPem': self.user.public_pem().decode(),
            },
        }, got.json)

    def test_actor_blocked_tld(self, _, __, ___):
        got = self.client.get('/foo.json')
        self.assertEqual(404, got.status_code)

    def test_actor_no_user(self, *mocks):
        got = self.client.get('/nope.com')
        self.assertEqual(404, got.status_code)

    def test_individual_inbox_no_user(self, *mocks):
        got = self.post('/nope.com/inbox', json=REPLY)
        self.assertEqual(404, got.status_code)

    def test_inbox_activity_without_id(self, *_):
        note = copy.deepcopy(NOTE)
        del note['id']
        resp = self.post('/inbox', json=note)
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
        self.assert_object(REPLY_OBJECT['id'],
                           source_protocol='activitypub',
                           as2=REPLY_OBJECT,
                           type='comment')

    def _test_inbox_reply(self, reply, expected_props, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://or.ig/post')
        mock_get.return_value = WEBMENTION_DISCOVERY
        mock_post.return_value = requests_response()

        got = self.post('/foo.com/inbox', json=reply)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'http://or.ig/post')
        expected_id = urllib.parse.quote_plus(reply['id'])
        self.assert_req(
            mock_post,
            'http://or.ig/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'http://localhost/render?id={expected_id}',
                'target': 'http://or.ig/post',
            },
        )

        self.assert_object(reply['id'],
                           domains=['or.ig'],
                           source_protocol='activitypub',
                           status='complete',
                           delivered=['http://or.ig/post'],
                           **expected_props)

    def test_inbox_reply_to_self_domain(self, mock_head, mock_get, mock_post):
        self._test_inbox_ignore_reply_to('http://localhost/th.is',
                                         mock_head, mock_get, mock_post)

    def test_inbox_reply_to_in_blocklist(self, *mocks):
        self._test_inbox_ignore_reply_to('https://twitter.com/foo', *mocks)

    def _test_inbox_ignore_reply_to(self, reply_to, mock_head, mock_get, mock_post):
        reply = copy.deepcopy(REPLY_OBJECT)
        reply['inReplyTo'] = reply_to

        mock_head.return_value = requests_response(url='http://th.is/')

        got = self.post('/foo.com/inbox', json=reply)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        mock_get.assert_not_called()
        mock_post.assert_not_called()

    def test_individual_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/foo.com/inbox', *mocks)

    def test_shared_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/inbox', *mocks)

    def _test_inbox_create_obj(self, path, mock_head, mock_get, mock_post):
        Follower.get_or_create(NOTE['actor'], 'foo.com')
        Follower.get_or_create('http://other/actor', 'bar.com')
        Follower.get_or_create(NOTE['actor'], 'baz.com')
        Follower.get_or_create(NOTE['actor'], 'baj.com', status='inactive')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor
        mock_post.return_value = requests_response()

        got = self.post(path, json=NOTE)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        expected_as2 = common.redirect_unwrap({
            **NOTE,
            'actor': ACTOR,
        })

        self.assert_object('http://th.is/note/as2',
                           source_protocol='activitypub',
                           as2=expected_as2,
                           domains=['foo.com', 'baz.com'],
                           type='post',
                           labels=['activity', 'feed'],
                           object_ids=[NOTE_OBJECT['id']])
        self.assert_object(NOTE_OBJECT['id'],
                           source_protocol='activitypub',
                           as2=NOTE_OBJECT,
                           type='note')

    def test_repost_of_federated_post(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/orig')
        mock_get.return_value = WEBMENTION_DISCOVERY
        mock_post.return_value = requests_response()  # webmention

        orig_url = 'https://foo.com/orig'
        note = {
            **NOTE_OBJECT,
            'url': 'https://foo.com/orig',
        }
        with app.test_request_context('/'):
            Object(id=orig_url, as2=note).put()

        repost = {
            **REPOST_FULL,
            'object': f'http://localhost/r/{orig_url}',
        }
        got = self.post('/foo.com/inbox', json=repost)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        source_url = f'http://localhost/render?id={urllib.parse.quote_plus(REPOST["id"])}'
        self.assert_req(
            mock_post,
            'https://foo.com/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': source_url,
                'target': orig_url,
            },
        )

        repost['object'] = note
        self.assert_object(REPOST_FULL['id'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=repost,
                           as1=as2.to_as1(repost),
                           domains=['foo.com'],
                           delivered=['https://foo.com/orig'],
                           type='share',
                           labels=['activity', 'feed', 'notification'],
                           object_ids=[NOTE_OBJECT['id']])

    def test_shared_inbox_repost(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')
        Follower.get_or_create(ACTOR['id'], 'baz.com')
        Follower.get_or_create(ACTOR['id'], 'baj.com', status='inactive')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),  # source actor
            self.as2_resp(NOTE_OBJECT),  # object of repost
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()  # webmention

        got = self.post('/inbox', json=REPOST)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        # webmention
        expected_id = urllib.parse.quote_plus(REPOST['id'])
        self.assert_req(
            mock_post,
            'http://th.is/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'http://localhost/render?id={expected_id}',
                'target': NOTE_OBJECT['url'],
            },
        )

        self.assert_object(REPOST['id'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=REPOST_FULL,
                           domains=['foo.com', 'baz.com', 'th.is'],
                           type='share',
                           labels=['activity', 'feed', 'notification'],
                           object_ids=[REPOST['object']],
                           delivered=[NOTE_OBJECT['url']])

    def test_inbox_not_public(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(ACTOR['id'], 'foo.com')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor

        not_public = copy.deepcopy(NOTE)
        del not_public['object']['to']

        got = self.post('/foo.com/inbox', json=not_public)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        self.assertIsNone(Object.get_by_id(not_public['id']))
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

        # redirect unwrap
        expected_as2 = copy.deepcopy(MENTION_OBJECT)
        expected_as2['tag'][1]['href'] = 'https://tar.get/'
        self.assert_object(MENTION_OBJECT['id'],
                           source_protocol='activitypub',
                           as2=expected_as2,
                           type='note')

    def _test_inbox_mention(self, mention, expected_props, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            WEBMENTION_DISCOVERY,
            HTML,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/foo.com/inbox', json=mention)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'https://tar.get/')
        expected_id = urllib.parse.quote_plus(mention['id'])
        self.assert_req(
            mock_post,
            'https://tar.get/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'http://localhost/render?id={expected_id}',
                'target': 'https://tar.get/',
            },
        )

        expected_as2 = common.redirect_unwrap(mention)
        self.assert_object(mention['id'],
                           domains=['tar.get', 'masto.foo'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=expected_as2,
                           delivered=['https://tar.get/'],
                           **expected_props)

    def test_inbox_like(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='http://or.ig/post')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/foo.com/inbox', json=LIKE)
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
                           delivered=['http://or.ig/post'],
                           type='like',
                           labels=['notification', 'activity'],
                           object_ids=[LIKE['object']])

    def test_inbox_follow_accept_with_id(self, *mocks):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT, *mocks)

        follow = {
            **FOLLOW_WITH_ACTOR,
            'url': 'https://mastodon.social/users/swentel#followed-https://foo.com/',
        }
        self.assert_object('https://mastodon.social/6d1a',
                           domains=['foo.com'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=follow,
                           delivered=['https://foo.com/'],
                           type='follow',
                           labels=['notification', 'activity'],
                           object_ids=[FOLLOW['object']])

        follower = Follower.query().get()
        self.assertEqual(follow, follower.last_follow)

    def test_inbox_follow_accept_with_object(self, *mocks):
        wrapped_user = {
            'id': FOLLOW_WRAPPED['object'],
            'url': FOLLOW_WRAPPED['object'],
        }
        unwrapped_user = {
            'id': FOLLOW['object'],
            'url': FOLLOW['object'],
        }

        follow = {
            **FOLLOW,
            'object': unwrapped_user,
        }

        self._test_inbox_follow_accept(follow, ACCEPT, *mocks)

        follower = Follower.query().get()
        follow.update({
            'actor': ACTOR,
            'url': 'https://mastodon.social/users/swentel#followed-https://foo.com/',
        })
        self.assertEqual(follow, follower.last_follow)
        self.assert_object('https://mastodon.social/6d1a',
                           domains=['foo.com'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=follow,
                           delivered=['https://foo.com/'],
                           type='follow',
                           labels=['notification', 'activity'],
                           object_ids=[FOLLOW['object']])

    def _test_inbox_follow_accept(self, follow_as2, accept_as2,
                                  mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(ACTOR),
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/foo.com/inbox', json=follow_as2)
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

        got = self.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        # check that the Follower doesn't have www
        follower = Follower.get_by_id(f'foo.com {ACTOR["id"]}')
        self.assertEqual('active', follower.status)
        self.assertEqual({
            **FOLLOW_WITH_ACTOR,
            'url': 'https://mastodon.social/users/swentel#followed-https://foo.com/',
        }, follower.last_follow)

    def test_inbox_undo_follow(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        Follower.get_or_create('foo.com', ACTOR['id'])

        got = self.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        follower = Follower.get_by_id(f'foo.com {FOLLOW["actor"]}')
        self.assertEqual('inactive', follower.status)

    def test_inbox_follow_inactive(self, mock_head, mock_get, mock_post):
        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(FOLLOW_WITH_ACTOR['actor']),
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

        # check that the Follower is now active
        follower = Follower.get_by_id(f'foo.com {FOLLOW["actor"]}')
        self.assertEqual('active', follower.status)

    def test_inbox_undo_follow_doesnt_exist(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        got = self.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_inactive(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        got = self.post('/foo.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)

    def test_inbox_undo_follow_composite_object(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://foo.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        Follower.get_or_create('foo.com', ACTOR['id'], status='inactive')

        undo_follow = copy.deepcopy(UNDO_FOLLOW_WRAPPED)
        undo_follow['object']['object'] = {'id': undo_follow['object']['object']}
        got = self.post('/foo.com/inbox', json=undo_follow)
        self.assertEqual(200, got.status_code)

    def test_inbox_unsupported_type(self, *_):
        got = self.post('/foo.com/inbox', json={
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
        got = self.post('/foo.com/inbox', json={
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
        self.assertEqual(['activity'], obj.labels)
        self.assertEqual([], obj.domains)

        self.assertIsNone(Object.get_by_id(bad_url))

    @patch('activitypub.logger.info', side_effect=logging.info)
    @patch('common.logger.info', side_effect=logging.info)
    def test_inbox_verify_http_signature(self, mock_common_log, mock_activitypub_log,
                                         _, mock_get, ___):
        # actor with a public key
        self.key_id_obj.delete()
        Protocol.get_object.cache.clear()
        mock_get.return_value = self.as2_resp({
            **ACTOR,
            'publicKey': {
                'id': 'http://my/key/id#unused',
                'owner': 'http://own/er',
                'publicKeyPem': self.user.public_pem().decode(),
            },
        })

        # valid signature
        body = json_dumps(NOTE)
        headers = self.sign('/inbox', json_dumps(NOTE))
        resp = self.client.post('/inbox', data=body, headers=headers)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        mock_get.assert_has_calls((
            self.as2_req('http://my/key/id'),
        ))
        mock_activitypub_log.assert_any_call('HTTP Signature verified!')

        # invalid signature, missing keyId
        protocol.seen_ids.clear()
        obj_key = ndb.Key(Object, NOTE['id'])
        obj_key.delete()

        resp = self.client.post('/inbox', data=body, headers={
            **headers,
            'signature': headers['signature'].replace(
                'keyId="http://my/key/id#unused",', ''),
        })
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'HTTP Signature missing keyId'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: HTTP Signature missing keyId')

        # invalid signature, content changed
        protocol.seen_ids.clear()
        obj_key = ndb.Key(Object, NOTE['id'])
        obj_key.delete()

        resp = self.client.post('/inbox', json={**NOTE, 'content': 'z'}, headers=headers)
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'Invalid Digest header, required for HTTP Signature'},
                         resp.json)
        mock_common_log.assert_any_call('Returning 401: Invalid Digest header, required for HTTP Signature')

        # invalid signature, header changed
        protocol.seen_ids.clear()
        obj_key.delete()
        orig_date = headers['Date']

        resp = self.client.post('/inbox', data=body, headers={**headers, 'Date': 'X'})
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'HTTP Signature verification failed'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: HTTP Signature verification failed')

        # no signature
        protocol.seen_ids.clear()
        obj_key.delete()
        resp = self.client.post('/inbox', json=NOTE)
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'error': 'No HTTP Signature'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: No HTTP Signature')

    def test_delete_actor(self, *mocks):
        follower = Follower.get_or_create('foo.com', DELETE['actor'])
        followee = Follower.get_or_create(DELETE['actor'], 'snarfed.org')
        # other unrelated follower
        other = Follower.get_or_create('foo.com', 'https://mas.to/users/other')
        self.assertEqual(3, Follower.query().count())

        got = self.post('/inbox', json=DELETE)
        self.assertEqual(200, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

    def test_delete_actor_not_stored(self, _, mock_get, ___):
        self.key_id_obj.delete()
        Protocol.get_object.cache.clear()

        mock_get.return_value = requests_response(status=410)
        got = self.post('/inbox', json={**DELETE, 'object': 'http://my/key/id'})
        self.assertEqual(202, got.status_code)

    def test_delete_note(self, _, mock_get, ___):
        obj = Object(id='http://an/obj', as2={})
        obj.put()

        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        delete = {
            **DELETE,
            'object': 'http://an/obj',
        }
        resp = self.post('/inbox', json=delete)
        self.assertEqual(200, resp.status_code)
        self.assertTrue(obj.key.get().deleted)
        self.assert_object(delete['id'], as2=delete,
                           type='delete', source_protocol='activitypub',
                           status='complete')

        obj.deleted = True
        self.assert_entities_equal(obj, Protocol.get_object.cache['http://an/obj'])

    def test_update_note(self, *mocks):
        Object(id='https://a/note', as2={}).put()
        self._test_update(*mocks)

    def test_update_unknown(self, *mocks):
        self._test_update(*mocks)

    def _test_update(self, _, mock_get, ___):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        resp = self.post('/inbox', json=UPDATE_NOTE)
        self.assertEqual(200, resp.status_code)

        obj = UPDATE_NOTE['object']
        self.assert_object('https://a/note', type='note', as2=obj,
                           source_protocol='activitypub')
        self.assert_object(UPDATE_NOTE['id'], source_protocol='activitypub',
                           type='update', status='complete', as2=UPDATE_NOTE)

        self.assert_entities_equal(Object.get_by_id('https://a/note'),
                                   Protocol.get_object.cache['https://a/note'])

    def test_inbox_webmention_discovery_connection_fails(self, mock_head,
                                                         mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # target post webmention discovery
            ReadTimeoutError(None, None, None),
        ]

        got = self.post('/foo.com/inbox', json=LIKE)
        self.assertEqual(504, got.status_code)

    def test_inbox_no_webmention_endpoint(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # target post webmention discovery
            requests_response('<html><body>foo</body></html>'),
        ]

        got = self.post('/foo.com/inbox', json=LIKE)
        self.assertEqual(200, got.status_code)

        self.assert_object('http://th.is/like#ok',
                           domains=['or.ig'],
                           source_protocol='activitypub',
                           status='complete',
                           as2=LIKE_WITH_ACTOR,
                           type='like',
                           labels=['notification', 'activity'],
                           object_ids=[LIKE['object']])

    def test_inbox_id_already_seen(self, *mocks):
        obj_key = Object(id=FOLLOW_WRAPPED['id'], as2={}).put()

        got = self.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)
        self.assertEqual(0, Follower.query().count())

        # second time should use in memory cache
        obj_key.delete()
        got = self.post('/foo.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(200, got.status_code)
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
                               last_follow=FOLLOW_WITH_ACTOR)
        Follower.get_or_create('http://other/actor', 'foo.com')
        Follower.get_or_create('foo.com', 'https://baz.com',
                               last_follow=FOLLOW_WITH_ACTOR)
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

    @patch('models.PAGE_SIZE', 1)
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
                               last_follow=FOLLOW_WITH_OBJECT)
        Follower.get_or_create('foo.com', 'http://other/actor')
        Follower.get_or_create('https://baz.com', 'foo.com',
                               last_follow=FOLLOW_WITH_OBJECT)
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

    @patch('models.PAGE_SIZE', 1)
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


class ActivityPubUtilsTest(testutil.TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('foo.com', has_hcard=True, actor_as2=ACTOR)
        self.app_context = app.test_request_context('/')
        self.app_context.__enter__()

    def tearDown(self):
        self.app_context.__exit__(None, None, None)
        super().tearDown()

    def test_postprocess_as2_multiple_in_reply_tos(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'inReplyTo': 'foo',
            'to': [as2.PUBLIC_AUDIENCE],
        }, activitypub.postprocess_as2({
            'id': 'xyz',
            'inReplyTo': ['foo', 'bar'],
        }, user=User(id='site')))

    def test_postprocess_as2_multiple_url(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'url': ['http://localhost/r/foo', 'http://localhost/r/bar'],
            'to': [as2.PUBLIC_AUDIENCE],
        }, activitypub.postprocess_as2({
            'id': 'xyz',
            'url': ['foo', 'bar'],
        }, user=User(id='site')))

    def test_postprocess_as2_multiple_image(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'attachment': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
            'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
            'to': [as2.PUBLIC_AUDIENCE],
        }, activitypub.postprocess_as2({
            'id': 'xyz',
            'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
        }, user=User(id='site')))

    def test_postprocess_as2_actor_attributedTo(self):
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
        }, activitypub.postprocess_as2({
            'attributedTo': [{'id': 'bar'}, {'id': 'baz'}],
            'actor': {'id': 'baj'},
        }, user=User(id='site')))

    def test_postprocess_as2_note(self):
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
        }, activitypub.postprocess_as2({
            'id': 'xyz',
            'type': 'Note',
        }, user=User(id='site')))

    # TODO: make these generic and use FakeProtocol
    @patch('requests.get')
    def test_get_object_http(self, mock_get):
        mock_get.return_value = AS2

        id = 'http://the/id'
        self.assertIsNone(Object.get_by_id(id))

        # first time fetches over HTTP
        got = ActivityPub.get_object(id)
        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, got.as2)
        mock_get.assert_has_calls([self.as2_req(id)])

        # second time is in cache
        got.key.delete()
        mock_get.reset_mock()

        got = ActivityPub.get_object(id)
        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, got.as2)
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_get_object_datastore(self, mock_get):
        id = 'http://the/id'
        stored = Object(id=id, as2=AS2_OBJ)
        stored.put()
        Protocol.get_object.cache.clear()

        # first time loads from datastore
        got = ActivityPub.get_object(id)
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

        # second time is in cache
        stored.key.delete()
        got = ActivityPub.get_object(id)
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_get_object_strips_fragment(self, mock_get):
        stored = Object(id='http://the/id', as2=AS2_OBJ)
        stored.put()
        Protocol.get_object.cache.clear()

        got = ActivityPub.get_object('http://the/id#ignore')
        self.assert_entities_equal(stored, got)
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_get_object_datastore_no_as2(self, mock_get):
        """If the stored Object has no as2, we should fall back to HTTP."""
        id = 'http://the/id'
        stored = Object(id=id, as2={}, status='in progress')
        stored.put()
        Protocol.get_object.cache.clear()

        mock_get.return_value = AS2
        got = ActivityPub.get_object(id)
        mock_get.assert_has_calls([self.as2_req(id)])

        self.assert_equals(id, got.key.id())
        self.assert_equals(AS2_OBJ, got.as2)
        mock_get.assert_has_calls([self.as2_req(id)])

        self.assert_object(id, as2=AS2_OBJ, as1=AS2_OBJ,
                           source_protocol='activitypub',
                           # check that it reused our original Object
                           status='in progress')

    @patch('requests.get')
    def test_signed_get_redirects_manually_with_new_sig_headers(self, mock_get):
        mock_get.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
            requests_response(status=200, allow_redirects=False),
        ]
        resp = activitypub.signed_get('https://first', user=self.user)

        first = mock_get.call_args_list[0][1]
        second = mock_get.call_args_list[1][1]
        self.assertNotEqual(first['headers'], second['headers'])
        self.assertNotEqual(
            first['auth'].header_signer.sign(first['headers'], method='GET', path='/'),
            second['auth'].header_signer.sign(second['headers'], method='GET', path='/'))

    @patch('requests.post')
    def test_signed_post_ignores_redirect(self, mock_post):
        mock_post.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
        ]

        resp = activitypub.signed_post('https://first', user=self.user)
        mock_post.assert_called_once()
        self.assertEqual(302, resp.status_code)

    @patch('requests.get')
    def test_fetch_direct(self, mock_get):
        mock_get.return_value = AS2
        obj = Object()

        ActivityPub.fetch('http://orig', obj, user=self.user)
        self.assertEqual(AS2_OBJ, obj.as2)
        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_via_html(self, mock_get):
        mock_get.side_effect = [HTML_WITH_AS2, AS2]
        obj = Object()

        ActivityPub.fetch('http://orig', obj, user=self.user)
        self.assertEqual(AS2_OBJ, obj.as2)
        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
            self.as2_req('http://as2', headers=common.as2.CONNEG_HEADERS),
        ))

    @patch('requests.get')
    def test_fetch_only_html(self, mock_get):
        mock_get.return_value = HTML
        with self.assertRaises(BadGateway):
            ActivityPub.fetch('http://orig', Object(), user=self.user)

    @patch('requests.get')
    def test_fetch_not_acceptable(self, mock_get):
        mock_get.return_value=NOT_ACCEPTABLE
        with self.assertRaises(BadGateway):
            ActivityPub.fetch('http://orig', Object(), user=self.user)

    @patch('requests.get')
    def test_fetch_ssl_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.SSLError
        with self.assertRaises(BadGateway):
            ActivityPub.fetch('http://orig', Object(), user=self.user)

    @patch('requests.get')
    def test_fetch_datastore_no_content(self, mock_get):
        mock_get.return_value = self.as2_resp('')

        with self.assertRaises(BadGateway):
            got = ActivityPub.fetch('http://the/id', Object())

        mock_get.assert_has_calls([self.as2_req('http://the/id')])

    @patch('requests.get')
    def test_fetch_datastore_not_json(self, mock_get):
        mock_get.return_value = self.as2_resp('XYZ not JSON')

        with self.assertRaises(BadGateway):
            got = ActivityPub.fetch('http://the/id', Object())

        mock_get.assert_has_calls([self.as2_req('http://the/id')])
