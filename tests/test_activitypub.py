"""Unit tests for activitypub.py."""
from base64 import b64encode
import copy
from datetime import datetime, timedelta
from hashlib import sha256
import logging
from unittest import skip
from unittest.mock import patch

from flask import g
from google.cloud import ndb
from granary import as2, microformats2
from httpsig import HeaderSigner
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import domain_from_link, json_dumps, json_loads
from oauth_dropins.webutil import util
import requests
from urllib3.exceptions import ReadTimeoutError
from werkzeug.exceptions import BadGateway

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

import activitypub
from activitypub import ActivityPub, default_signature_user, postprocess_as2
from atproto import ATProto
import common
from models import Follower, Object
import protocol
from web import Web

# have to import module, not attrs, to avoid circular import
from . import test_web
from . import test_webfinger

ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mas.to/users/swentel',
    'type': 'Person',
    'inbox': 'http://mas.to/inbox',
    'name': 'Mrs. ☕ Foo',
    'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
    'image': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
}
ACTOR_AS1 = as2.to_as1(ACTOR)
ACTOR_BASE = {
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'type': 'Person',
    'id': 'http://localhost/user.com',
    'url': 'http://localhost/r/https://user.com/',
    'preferredUsername': 'user.com',
    'summary': '',
    'inbox': 'http://localhost/user.com/inbox',
    'outbox': 'http://localhost/user.com/outbox',
    'following': 'http://localhost/user.com/following',
    'followers': 'http://localhost/user.com/followers',
    'endpoints': {
        'sharedInbox': 'https://web.brid.gy/ap/sharedInbox',
    },
    'publicKey': {
        'id': 'http://localhost/user.com#key',
        'owner': 'http://localhost/user.com',
        'publicKeyPem': 'populated in setUp()',
    },
}
ACTOR_BASE_FULL = {
    **ACTOR_BASE,
    'name': 'Ms. ☕ Baz',
    'attachment': [{
        'name': 'Web site',
        'type': 'PropertyValue',
        'value': '<a rel="me" href="https://user.com"><span class="invisible">https://</span>user.com</a>',
    }],
}
ACTOR_FAKE = {
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'type': 'Person',
    'id': 'https://fa.brid.gy/ap/fake:user',
    'url': 'https://fa.brid.gy/r/fake:user',
    'inbox': 'https://fa.brid.gy/ap/fake:user/inbox',
    'outbox': 'https://fa.brid.gy/ap/fake:user/outbox',
    'following': 'https://fa.brid.gy/ap/fake:user/following',
    'followers': 'https://fa.brid.gy/ap/fake:user/followers',
    'endpoints': {'sharedInbox': 'https://fa.brid.gy/ap/sharedInbox'},
    'preferredUsername': 'fake:handle:user',
    'summary': '',
    'publicKey': {
        'id': 'https://fa.brid.gy/ap/fake:user#key',
        'owner': 'https://fa.brid.gy/ap/fake:user',
        'publicKeyPem': 'populated in setUp()',
    },
}
REPLY_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': 'A ☕ reply',
    'id': 'http://mas.to/reply/id',
    'url': 'http://mas.to/reply',
    'inReplyTo': 'https://user.com/post',
    'to': [as2.PUBLIC_AUDIENCE],
}
REPLY_OBJECT_WRAPPED = copy.deepcopy(REPLY_OBJECT)
REPLY_OBJECT_WRAPPED['inReplyTo'] = 'http://localhost/r/https://user.com/post'
REPLY = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://mas.to/reply/as2',
    'object': REPLY_OBJECT,
}
NOTE_OBJECT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Note',
    'content': '☕ just a normal post',
    'id': 'http://mas.to/note/id',
    'url': 'http://mas.to/note',
    'to': [as2.PUBLIC_AUDIENCE],
    'cc': [
        'https://mas.to/author/followers',
        'https://masto.foo/@other',
        'http://localhost/target',  # redirect-wrapped
    ],
}
NOTE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Create',
    'id': 'http://mas.to/note/as2',
    'actor': 'https://masto.foo/@author',
    'object': NOTE_OBJECT,
}
MENTION_OBJECT = copy.deepcopy(NOTE_OBJECT)
MENTION_OBJECT.update({
    'id': 'http://mas.to/mention/id',
    'url': 'http://mas.to/mention',
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
    'id': 'http://mas.to/mention/as2',
    'object': MENTION_OBJECT,
}
# based on example Mastodon like:
# https://github.com/snarfed/bridgy-fed/issues/4#issuecomment-334212362
# (reposts are very similar)
LIKE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'http://mas.to/like#ok',
    'type': 'Like',
    'object': 'https://user.com/post',
    'actor': 'https://mas.to/actor',
}
LIKE_WRAPPED = copy.deepcopy(LIKE)
LIKE_WRAPPED['object'] = 'http://localhost/r/https://user.com/post'
LIKE_ACTOR = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mas.to/actor',
    'type': 'Person',
    'name': 'Ms. Actor',
    'preferredUsername': 'msactor',
    'icon': {'type': 'Image', 'url': 'https://user.com/pic.jpg'},
    'image': [
        {'type': 'Image', 'url': 'https://user.com/thumb.jpg'},
        {'type': 'Image', 'url': 'https://user.com/pic.jpg'},
    ],
}
LIKE_WITH_ACTOR = {
    **LIKE,
    'actor': LIKE_ACTOR,
}

# repost, should be delivered to followers if object is a fediverse post,
# translated to webmention if object is an indieweb post
REPOST = {
  '@context': 'https://www.w3.org/ns/activitystreams',
  'id': 'https://mas.to/users/alice/statuses/654/activity',
  'type': 'Announce',
  'actor': ACTOR['id'],
  'object': NOTE_OBJECT['id'],
  'published': '2023-02-08T17:44:16Z',
  'to': [as2.PUBLIC_AUDIENCE],
}
REPOST_FULL = {
    **REPOST,
    'actor': ACTOR,
    'object': NOTE_OBJECT,
}

FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mas.to/6d1a',
    'type': 'Follow',
    'actor': ACTOR['id'],
    'object': 'https://user.com/',
}
FOLLOW_WRAPPED = copy.deepcopy(FOLLOW)
FOLLOW_WRAPPED['object'] = 'http://localhost/user.com'
FOLLOW_WITH_ACTOR = copy.deepcopy(FOLLOW)
FOLLOW_WITH_ACTOR['actor'] = ACTOR
FOLLOW_WRAPPED_WITH_ACTOR = copy.deepcopy(FOLLOW_WRAPPED)
FOLLOW_WRAPPED_WITH_ACTOR['actor'] = ACTOR
FOLLOW_WITH_OBJECT = copy.deepcopy(FOLLOW)
FOLLOW_WITH_OBJECT['object'] = ACTOR

ACCEPT_FOLLOW = copy.deepcopy(FOLLOW_WITH_ACTOR)
del ACCEPT_FOLLOW['@context']
del ACCEPT_FOLLOW['actor']['@context']
ACCEPT_FOLLOW['actor']['image'] = {'type': 'Image', 'url': 'https://user.com/me.jpg'}
ACCEPT_FOLLOW['object'] = 'http://localhost/user.com'
ACCEPT = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Accept',
    'id': 'http://localhost/user.com/followers#accept-https://mas.to/6d1a',
    'actor': 'http://localhost/user.com',
    'object': {
        'type': 'Follow',
        'id': 'https://mas.to/6d1a',
        'object': 'http://localhost/user.com',
        'actor': 'https://mas.to/users/swentel',
        'url': 'https://mas.to/users/swentel#followed-user.com',
        'to': [as2.PUBLIC_AUDIENCE],
    },
   'to': [as2.PUBLIC_AUDIENCE],
}

UNDO_FOLLOW_WRAPPED = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mas.to/6d1b',
    'type': 'Undo',
    'actor': 'https://mas.to/users/swentel',
    'object': FOLLOW_WRAPPED,
}

DELETE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://mas.to/users/swentel#delete',
    'type': 'Delete',
    'actor': 'https://mas.to/users/swentel',
    'object': 'https://mas.to/users/swentel',
}

UPDATE_PERSON = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://a/person#update',
    'type': 'Update',
    'actor': 'https://mas.to/users/swentel',
    'object': {
        'type': 'Person',
        'id': 'https://a/person',
    },
}
UPDATE_NOTE = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': 'https://a/note#update',
    'type': 'Update',
    'actor': 'https://mas.to/users/swentel',
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
class ActivityPubTest(TestCase):

    def setUp(self):
        super().setUp()
        self.request_context.push()

        self.user = self.make_user('user.com', cls=Web, has_hcard=True,
                                   has_redirects=True,
                                   obj_as1={**ACTOR_AS1, 'id': 'https://user.com/'})
        self.swentel_key = ndb.Key(ActivityPub, 'https://mas.to/users/swentel')
        self.masto_actor_key = ndb.Key(ActivityPub, 'https://mas.to/actor')

        for obj in ACTOR_BASE, ACTOR_FAKE:
            obj['publicKey']['publicKeyPem'] = self.user.public_pem().decode()

        self.key_id_obj = Object(id='http://my/key/id', as2={
            **ACTOR,
            'publicKey': {
                'id': 'http://my/key/id#unused',
                'owner': 'http://own/er',
                'publicKeyPem': self.user.public_pem().decode(),
            },
        })
        self.key_id_obj.put()

    def assert_object(self, id, **props):
        props.setdefault('delivered_protocol', 'web')
        return super().assert_object(id, **props)

    def sign(self, path, body, host=None):
        """Constructs HTTP Signature, returns headers."""
        digest = b64encode(sha256(body.encode()).digest()).decode()
        headers = {
            'Date': 'Sun, 02 Jan 2022 03:04:05 GMT',
            'Host': host or 'localhost',
            'Content-Type': as2.CONTENT_TYPE,
            'Digest': f'SHA-256={digest}',
        }
        hs = HeaderSigner('http://my/key/id#unused', self.user.private_pem().decode(),
                          algorithm='rsa-sha256', sign_header='signature',
                          headers=('Date', 'Host', 'Digest', '(request-target)'))
        return hs.sign(headers, method='POST', path=path)

    def post(self, path, json=None, base_url=None, **kwargs):
        """Wrapper around self.client.post that adds signature."""
        body = json_dumps(json)
        host = domain_from_link(base_url) if base_url else None
        headers = self.sign(path, body, host=host)
        return self.client.post(path, data=body, headers=headers,
                                base_url=base_url, **kwargs)

    def test_actor_fake(self, *_):
        self.make_user('fake:user', cls=Fake)
        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/')
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        type = got.headers['Content-Type']
        self.assertTrue(type.startswith(as2.CONTENT_TYPE), type)
        self.assertEqual(ACTOR_FAKE, got.json)

    def test_actor_fake_protocol_subdomain(self, *_):
        self.make_user('fake:user', cls=Fake)
        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/')
        self.assertEqual(200, got.status_code)
        self.assertEqual(ACTOR_FAKE, got.json)

    def test_actor_web(self, *_):
        """Web users are special cased to drop the /web/ prefix."""
        got = self.client.get('/user.com')
        self.assertEqual(200, got.status_code)
        type = got.headers['Content-Type']
        self.assertTrue(type.startswith(as2.CONTENT_TYPE), type)
        self.assertEqual({
            **ACTOR_BASE,
            '@context': [
                'https://www.w3.org/ns/activitystreams',
                'https://w3id.org/security/v1',
            ],
            'name': 'Mrs. ☕ Foo',
            'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
            'image': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
        }, got.json)

    def test_actor_blocked_tld(self, _, __, ___):
        got = self.client.get('/foo.json')
        self.assertEqual(404, got.status_code)

    def test_actor_new_user_fetch(self, _, mock_get, __):
        self.user.obj_key.delete()
        self.user.key.delete()
        protocol.objects_cache.clear()

        mock_get.return_value = requests_response(test_web.ACTOR_HTML)

        got = self.client.get('/user.com')
        self.assertEqual(200, got.status_code)
        self.assert_equals(ACTOR_BASE_FULL, got.json, ignore=['publicKeyPem'])

    def test_actor_new_user_fetch_no_mf2(self, _, mock_get, __):
        self.user.obj_key.delete()
        self.user.key.delete()
        protocol.objects_cache.clear()

        mock_get.return_value = requests_response('<html></html>')

        got = self.client.get('/user.com')
        self.assertEqual(200, got.status_code)
        self.assert_equals(ACTOR_BASE, got.json, ignore=['publicKeyPem'])

    def test_actor_new_user_fetch_fails(self, _, mock_get, ___):
        mock_get.side_effect = ReadTimeoutError(None, None, None)
        got = self.client.get('/nope.com')
        self.assertEqual(504, got.status_code)

    def test_actor_handle_existing_user(self, _, __, ___):
        self.make_user('fake:user', cls=Fake, obj_as2=ACTOR)
        got = self.client.get('/ap/fake:handle:user', base_url='https://fa.brid.gy/')
        self.assertEqual(200, got.status_code)
        self.assert_equals({
            **ACTOR,
            **ACTOR_FAKE,
        }, got.json, ignore=['publicKeyPem'])

    def test_actor_handle_new_user(self, _, __, ___):
        Fake.fetchable['fake:user'] = as2.to_as1({
            **ACTOR,
            'id': 'fake:user',
        })
        got = self.client.get('/ap/fake:handle:user', base_url='https://fa.brid.gy/')
        self.assertEqual(200, got.status_code)
        self.assert_equals({
            **ACTOR,
            **ACTOR_FAKE,
        }, got.json, ignore=['publicKeyPem'])

    def test_actor_no_handle(self, *_):
        self.store_object(id='did:plc:user', raw={'foo': 'bar'})
        self.make_user('did:plc:user', cls=ATProto)
        got = self.client.get('/ap/did:plc:user', base_url='https://atproto.brid.gy/')
        self.assertEqual(200, got.status_code)
        self.assertNotIn('preferredUsername', got.json)

    def test_actor_handle_user_fetch_fails(self, _, __, ___):
        got = self.client.get('/ap/fake/fake:handle:nope')
        self.assertEqual(404, got.status_code)

    def test_actor_no_matching_protocol(self, *_):
        resp = self.client.get('/foo.json',
                               base_url='https://bridgy-federated.appspot.com/')
        self.assertEqual(404, resp.status_code)

    def test_actor_web_redirects(self, *_):
        for path, base_url in [
                ('/ap/user.com', None),
                ('/ap/user.com', 'https://web.brid.gy/'),
                ('/user.com', 'https://web.brid.gy/'),
        ]:
            resp = self.client.get(path, base_url=base_url)
            self.assertEqual(301, resp.status_code)
            self.assertEqual('https://fed.brid.gy/user.com', resp.headers['Location'])

    def test_individual_inbox_no_user(self, mock_head, mock_get, mock_post):
        self.user.key.delete()

        mock_get.side_effect = [self.as2_resp(LIKE_ACTOR)]

        reply = {
            **REPLY,
            'actor': LIKE_ACTOR,
        }
        self._test_inbox_reply(reply, mock_head, mock_get, mock_post)

        self.assert_user(ActivityPub, 'https://mas.to/actor', obj_as2=LIKE_ACTOR)

    def test_inbox_activity_without_id(self, *_):
        note = copy.deepcopy(NOTE)
        del note['id']
        resp = self.post('/ap/sharedInbox', json=note)
        self.assertEqual(400, resp.status_code)

    def test_inbox_reply_object(self, mock_head, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(REPLY_OBJECT),
                           type='comment')
        # auto-generated post activity
        self.assert_object(
            'http://mas.to/reply/id#bridgy-fed-create',
            source_protocol='activitypub',
            our_as1={
                **as2.to_as1(REPLY),
                'id': 'http://mas.to/reply/id#bridgy-fed-create',
                'published': '2022-01-02T03:04:05+00:00',
            },
            status='complete',
            delivered=['https://user.com/post'],
            type='post',
            notify=[self.user.key],
        )

    def test_inbox_reply_object_wrapped(self, mock_head, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(REPLY_OBJECT),
                           type='comment')
        # auto-generated post activity
        self.assert_object(
            'http://mas.to/reply/id#bridgy-fed-create',
            source_protocol='activitypub',
            our_as1={
                **as2.to_as1(REPLY),
                'id': 'http://mas.to/reply/id#bridgy-fed-create',
                'published': '2022-01-02T03:04:05+00:00',
            },
            status='complete',
            delivered=['https://user.com/post'],
            type='post',
            notify=[self.user.key],
        )

    def test_inbox_reply_create_activity(self, mock_head, mock_get, mock_post):
        self._test_inbox_reply(REPLY, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1({
                               **REPLY_OBJECT,
                               'author': None,
                           }),
                           type='comment')
        # sent activity
        self.assert_object(
            'http://mas.to/reply/as2',
            source_protocol='activitypub',
            as2=REPLY,
            status='complete',
            delivered=['https://user.com/post'],
            type='post',
            notify=[self.user.key],
        )

    def _test_inbox_reply(self, reply, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/post')
        mock_get.side_effect = (
            (list(mock_get.side_effect) if mock_get.side_effect else [])
            + [
                requests_response(test_web.NOTE_HTML),
                requests_response(test_web.NOTE_HTML),
                WEBMENTION_DISCOVERY,
            ])
        mock_post.return_value = requests_response()

        got = self.post('/ap/web/user.com/inbox', json=reply)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))
        self.assert_req(mock_get, 'https://user.com/post')

        convert_id = reply['id']
        if reply['type'] != 'Create':
            convert_id += '%23bridgy-fed-create'

        self.assert_req(
            mock_post,
            'https://user.com/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'https://ap.brid.gy/convert/web/{convert_id}',
                'target': 'https://user.com/post',
            },
        )

    def test_inbox_reply_protocol_subdomain(self, reply, *_):
        Fake.fetchable['fake:post'] = as2.to_as1({
            **NOTE_OBJECT,
            'id': 'fake:post',
        })
        reply = {
            **REPLY_OBJECT,
            'id': 'fake:my-reply',
            'inReplyTo': 'fake:post',
        }
        got = self.post('/ap/fake:user/inbox', json=reply,
                        base_url='https://fa.brid.gy/')
        self.assertEqual(202, got.status_code)
        self.assertEqual([('fake:my-reply#bridgy-fed-create', 'fake:post:target')],
                         Fake.sent)

    def test_inbox_reply_to_self_domain(self, mock_head, mock_get, mock_post):
        mock_get.return_value = test_web.ACTOR_HTML_RESP
        self._test_inbox_ignore_reply_to('http://localhost/user.com',
                                         mock_head, mock_get, mock_post)

    def test_inbox_reply_to_in_blocklist(self, mock_head, mock_get, mock_post):
        mock_get.return_value = HTML
        self._test_inbox_ignore_reply_to('https://twitter.com/foo',
                                         mock_head, mock_get, mock_post)

    def _test_inbox_ignore_reply_to(self, reply_to, mock_head, mock_get, mock_post):
        reply = copy.deepcopy(REPLY_OBJECT)
        reply['inReplyTo'] = reply_to

        got = self.post('/user.com/inbox', json=reply)
        self.assertEqual(204, got.status_code, got.get_data(as_text=True))
        mock_post.assert_not_called()

    def test_individual_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/user.com/inbox', *mocks)

    def test_shared_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/inbox', *mocks)

    def test_ap_sharedInbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/ap/sharedInbox', *mocks)

    def _test_inbox_create_obj(self, path, mock_head, mock_get, mock_post):
        swentel = self.make_user('https://mas.to/users/swentel', cls=ActivityPub)
        Follower.get_or_create(to=swentel, from_=self.user)
        bar = self.make_user('fake:bar', cls=Fake, obj_id='fake:bar')
        Follower.get_or_create(to=self.make_user('https://other.actor',
                                                 cls=ActivityPub),
                               from_=bar)
        baz = self.make_user('fake:baz', cls=Fake, obj_id='fake:baz')
        Follower.get_or_create(to=swentel, from_=baz)
        baj = self.make_user('fake:baj', cls=Fake, obj_id='fake:baj')
        Follower.get_or_create(to=swentel, from_=baj, status='inactive')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor
        mock_post.return_value = requests_response()

        got = self.post(path, json=NOTE)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        expected_obj = {
            **as2.to_as1(NOTE_OBJECT),
            'author': {'id': 'https://masto.foo/@author'},
            'cc': [
                {'id': 'https://mas.to/author/followers'},
                {'id': 'https://masto.foo/@other'},
                {'id': 'target'},
            ],
        }
        self.assert_object(NOTE_OBJECT['id'],
                           source_protocol='activitypub',
                           our_as1=expected_obj,
                           type='note',
                           feed=[self.user.key, baz.key])

        expected_create = as2.to_as1(common.unwrap(NOTE))
        expected_create.update({
            'actor': as2.to_as1(ACTOR),
            'object': expected_obj,
        })
        self.assert_object('http://mas.to/note/as2',
                           source_protocol='activitypub',
                           our_as1=expected_create,
                           users=[ndb.Key(ActivityPub, 'https://masto.foo/@author')],
                           type='post',
                           object_ids=[NOTE_OBJECT['id']],
                           status='complete',
                           delivered=['shared:target'],
                           delivered_protocol='fake')

    def test_repost_of_indieweb(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/orig')
        mock_get.return_value = WEBMENTION_DISCOVERY
        mock_post.return_value = requests_response()  # webmention

        orig_url = 'https://user.com/orig'
        note = {
            **NOTE_OBJECT,
            'id': 'https://user.com/orig',
        }
        del note['url']
        Object(id=orig_url, mf2=microformats2.object_to_json(as2.to_as1(note)),
               source_protocol='web').put()

        repost = copy.deepcopy(REPOST_FULL)
        repost['object'] = f'http://localhost/r/{orig_url}'
        got = self.post('/user.com/inbox', json=repost)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        self.assert_req(
            mock_post,
            'https://user.com/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'https://ap.brid.gy/convert/web/{REPOST["id"]}',
                'target': orig_url,
            },
        )

        self.assert_object(REPOST_FULL['id'],
                           source_protocol='activitypub',
                           status='complete',
                           as2={
                               **REPOST,
                               'actor': ACTOR,
                               'object': orig_url,
                           },
                           users=[self.swentel_key],
                           delivered=['https://user.com/orig'],
                           type='share',
                           object_ids=['https://user.com/orig'])

    def test_shared_inbox_repost_of_fediverse(self, mock_head, mock_get, mock_post):
        to = self.make_user(ACTOR['id'], cls=ActivityPub)
        Follower.get_or_create(to=to, from_=self.user)
        baz = self.make_user('fake:baz', cls=Fake, obj_id='fake:baz')
        Follower.get_or_create(to=to, from_=baz)
        baj = self.make_user('fake:baj', cls=Fake, obj_id='fake:baj')
        Follower.get_or_create(to=to, from_=baj, status='inactive')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),  # source actor
            self.as2_resp(NOTE_OBJECT),  # object of repost
            # protocol inference
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            HTML,  # no webmention endpoint
        ]

        got = self.post('/ap/sharedInbox', json=REPOST)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        mock_post.assert_not_called()  # no webmention

        self.assert_object(REPOST['id'],
                           source_protocol='activitypub',
                           status='complete',
                           our_as1=as2.to_as1({**REPOST, 'actor': ACTOR}),
                           users=[self.swentel_key],
                           feed=[self.user.key, baz.key],
                           delivered=['shared:target'],
                           delivered_protocol='fake',
                           type='share',
                           object_ids=[REPOST['object']])

    def test_inbox_no_user(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # protocol inference
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            # target post webmention discovery
            HTML,
        ]

        got = self.post('/ap/sharedInbox', json={
            **LIKE,
            'object': 'http://nope.com/post',
        })
        self.assertEqual(202, got.status_code)

        self.assert_object('http://mas.to/like#ok',
                           # no nope.com Web user key since it didn't exist
                           source_protocol='activitypub',
                           status='ignored',
                           our_as1=as2.to_as1({
                               **LIKE_WITH_ACTOR,
                               'object': 'http://nope.com/post',
                           }),
                           type='like',
                           notify=[self.user.key],
                           users=[self.masto_actor_key],
                           object_ids=['http://nope.com/post'])

    def test_inbox_not_public(self, mock_head, mock_get, mock_post):
        Follower.get_or_create(to=self.make_user(ACTOR['id'], cls=ActivityPub),
                               from_=self.user)

        mock_head.return_value = requests_response(url='http://target')
        mock_get.return_value = self.as2_resp(ACTOR)  # source actor

        not_public = copy.deepcopy(NOTE)
        del not_public['object']['to']

        got = self.post('/user.com/inbox', json=not_public)
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))

        self.assertIsNone(Object.get_by_id(not_public['id']))
        self.assertIsNone(Object.get_by_id(not_public['object']['id']))

    def test_inbox_like(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/post')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=LIKE)
        self.assertEqual(202, got.status_code)

        self.assertIn(self.as2_req('https://mas.to/actor'), mock_get.mock_calls)
        self.assertIn(self.req('https://user.com/post'), mock_get.mock_calls)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://user.com/webmention',), args)
        self.assertEqual({
            'source': 'https://ap.brid.gy/convert/web/http://mas.to/like%23ok',
            'target': 'https://user.com/post',
        }, kwargs['data'])

        self.assert_object('http://mas.to/like#ok',
                           notify=[self.user.key],
                           users=[self.masto_actor_key],
                           source_protocol='activitypub',
                           status='complete',
                           our_as1=as2.to_as1(LIKE_WITH_ACTOR),
                           delivered=['https://user.com/post'],
                           type='like',
                           object_ids=[LIKE['object']])

    def test_inbox_like_indirect_user_creates_User(self, mock_get, *_):
        self.user.direct = False
        self.user.put()

        mock_get.return_value = self.as2_resp(LIKE_ACTOR)

        self.test_inbox_like()
        self.assert_user(ActivityPub, 'https://mas.to/actor', obj_as2=LIKE_ACTOR)

    def test_inbox_like_no_object_error(self, *_):
        Fake.fetchable = {'fake:user': {'id': 'fake:user'}}
        got = self.post('/inbox', json={
            'id': 'fake:like',
            'type': 'Like',
            'actor': 'fake:user',
            'object': None,
        })
        self.assertEqual(400, got.status_code)

    def test_inbox_follow_accept_with_id(self, *mocks):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT, *mocks)

        follow = {
            **FOLLOW_WITH_ACTOR,
            'url': 'https://mas.to/users/swentel#followed-user.com',
        }
        self.assert_object('https://mas.to/6d1a',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           status='complete',
                           our_as1=as2.to_as1(follow),
                           delivered=['https://user.com/'],
                           type='follow',
                           object_ids=[FOLLOW['object']])

    def test_inbox_follow_accept_with_object(self, *mocks):
        follow = {
            **FOLLOW,
            'object': {
                'id': FOLLOW['object'],
                'url': FOLLOW['object'],
            },
        }
        accept = copy.deepcopy(ACCEPT)
        accept['object']['url'] = 'https://mas.to/users/swentel#followed-https://user.com/'
        self._test_inbox_follow_accept(follow, accept, *mocks)

        follow.update({
            'actor': ACTOR,
            'url': 'https://mas.to/users/swentel#followed-https://user.com/',
        })
        self.assert_object('https://mas.to/6d1a',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           status='complete',
                           our_as1=as2.to_as1(follow),
                           delivered=['https://user.com/'],
                           type='follow',
                           object_ids=[FOLLOW['object']])

    def test_inbox_follow_accept_shared_inbox(self, mock_head, mock_get, mock_post):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT,
                                       mock_head, mock_get, mock_post,
                                       inbox_path='/ap/sharedInbox')

        url = 'https://mas.to/users/swentel#followed-user.com'
        self.assert_object('https://mas.to/6d1a',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           status='complete',
                           our_as1=as2.to_as1({**FOLLOW_WITH_ACTOR, 'url': url}),
                           delivered=['https://user.com/'],
                           type='follow',
                           object_ids=[FOLLOW['object']])

    def test_inbox_follow_accept_webmention_fails(self, mock_head, mock_get,
                                                  mock_post):
        mock_post.side_effect = [
            requests_response(),         # AP Accept
            requests.ConnectionError(),  # webmention
        ]
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT,
                                       mock_head, mock_get, mock_post)

        url = 'https://mas.to/users/swentel#followed-user.com'
        self.assert_object('https://mas.to/6d1a',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           status='failed',
                           our_as1=as2.to_as1({**FOLLOW_WITH_ACTOR, 'url': url}),
                           delivered=[],
                           failed=['https://user.com/'],
                           type='follow',
                           object_ids=[FOLLOW['object']])

    def _test_inbox_follow_accept(self, follow_as2, accept_as2, mock_head,
                                  mock_get, mock_post, inbox_path='/user.com/inbox'):
        # this should makes us make the follower ActivityPub as direct=True
        self.user.direct = False
        self.user.put()

        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),  # source actor
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        if not mock_post.return_value and not mock_post.side_effect:
            mock_post.return_value = requests_response()

        got = self.post(inbox_path, json=follow_as2)
        self.assertEqual(202, got.status_code)

        mock_get.assert_has_calls((
            self.as2_req(FOLLOW['actor']),
        ))

        # check AP Accept
        self.assertEqual(2, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('http://mas.to/inbox',), args)
        self.assertEqual(accept_as2, json_loads(kwargs['data']))

        # check webmention
        args, kwargs = mock_post.call_args_list[1]
        self.assertEqual(('https://user.com/webmention',), args)
        self.assertEqual({
            'source': 'https://ap.brid.gy/convert/web/https://mas.to/6d1a',
            'target': 'https://user.com/',
        }, kwargs['data'])

        # check that we stored Follower and ActivityPub user for the follower
        self.assert_entities_equal(
            Follower(to=self.user.key,
                     from_=ActivityPub(id=ACTOR['id']).key,
                     status='active',
                     follow=Object(id=FOLLOW['id']).key),
            Follower.query().fetch(),
            ignore=['created', 'updated'])

        self.assert_user(ActivityPub, 'https://mas.to/users/swentel',
                         obj_as2=ACTOR, direct=True)
        self.assert_user(Web, 'user.com', direct=False,
                         has_hcard=True, has_redirects=True)

    def test_inbox_follow_use_instead_strip_www(self, mock_head, mock_get, mock_post):
        self.make_user('www.user.com', cls=Web, use_instead=self.user.key)

        mock_head.return_value = requests_response(url='https://www.user.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(ACTOR),
            # target user
            test_web.ACTOR_HTML_RESP,
            # target post webmention discovery
            requests_response('<html></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)

        follower = Follower.query().get()
        self.assert_entities_equal(
            Follower(to=self.user.key,
                     from_=ActivityPub(id=ACTOR['id']).key,
                     status='active',
                     follow=Object(id=FOLLOW['id']).key),
            follower,
            ignore=['created', 'updated'])

        # double check that Follower doesn't have www
        self.assertEqual('user.com', follower.to.id())

        # double check that follow Object doesn't have www
        self.assertEqual('active', follower.status)
        self.assertEqual('https://mas.to/users/swentel#followed-user.com',
                         follower.follow.get().as2['url'])

    def test_inbox_undo_follow(self, mock_head, mock_get, mock_post):
        follower = Follower(to=self.user.key,
                            from_=ActivityPub(id=ACTOR['id']).key,
                            status='active')
        follower.put()

        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)

        # check that the Follower is now inactive
        self.assertEqual('inactive', follower.key.get().status)

    def test_inbox_follow_inactive(self, mock_head, mock_get, mock_post):
        follower = Follower.get_or_create(
            to=self.user,
            from_=self.make_user(ACTOR['id'], cls=ActivityPub),
            status='inactive')

        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            # source actor
            self.as2_resp(FOLLOW_WITH_ACTOR['actor']),
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)

        # check that the Follower is now active
        self.assertEqual('active', follower.key.get().status)

    def test_inbox_undo_follow_doesnt_exist(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)

    def test_inbox_undo_follow_inactive(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        follower = Follower.get_or_create(to=self.user,
                                          from_=ActivityPub.get_or_create(ACTOR['id']),
                                          status='inactive')

        got = self.post('/user.com/inbox', json=UNDO_FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)

    def test_inbox_undo_follow_composite_object(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            test_web.ACTOR_HTML_RESP,
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        follower = Follower.get_or_create(to=self.user,
                                          from_=ActivityPub.get_or_create(ACTOR['id']),
                                          status='inactive')

        undo_follow = copy.deepcopy(UNDO_FOLLOW_WRAPPED)
        undo_follow['object']['object'] = {'id': undo_follow['object']['object']}
        got = self.post('/user.com/inbox', json=undo_follow)
        self.assertEqual(202, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)

    def test_inbox_unsupported_type(self, *_):
        got = self.post('/user.com/inbox', json={
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

        id = 'https://mas.to/users/tmichellemoore#likes/56486252'
        bad_url = 'http://localhost/r/Testing \u2013 Brid.gy \u2013 Post to Mastodon 3'
        bad = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': id,
            'type': 'Like',
            'actor': ACTOR['id'],
            'object': bad_url,
        }
        got = self.post('/user.com/inbox', json=bad)

        # bad object, should ignore activity
        self.assertEqual(204, got.status_code)
        mock_post.assert_not_called()

        expected = {
            **as2.to_as1(bad),
            'actor': as2.to_as1(ACTOR),
            'object': 'https://Testing – Brid.gy – Post to Mastodon 3/',
        }
        self.assert_object(id,
                           our_as1=expected,
                           users=[self.swentel_key],
                           source_protocol='activitypub',
                           status='ignored',
                           )
        self.assertIsNone(Object.get_by_id(bad_url))

    @patch('activitypub.logger.info', side_effect=logging.info)
    @patch('common.logger.info', side_effect=logging.info)
    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_http_signature(self, mock_common_log, mock_activitypub_log,
                                         _, mock_get, ___):
        # actor with a public key
        self.key_id_obj.key.delete()
        protocol.objects_cache.clear()
        actor_as2 = {
            **ACTOR,
            'publicKey': {
                'id': 'http://my/key/id#unused',
                'owner': 'http://own/er',
                'publicKeyPem': self.user.public_pem().decode(),
            },
        }
        mock_get.return_value = self.as2_resp(actor_as2)

        # valid signature
        body = json_dumps(NOTE)
        headers = self.sign('/ap/sharedInbox', json_dumps(NOTE))
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(204, resp.status_code, resp.get_data(as_text=True))
        mock_get.assert_has_calls((
            self.as2_req('http://my/key/id'),
        ))
        mock_activitypub_log.assert_any_call('HTTP Signature verified!')

        # valid signature, Object has no key
        self.key_id_obj.as2 = ACTOR
        self.key_id_obj.put()
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))

        # valid signature, Object has our_as1 instead of as2
        self.key_id_obj.clear()
        self.key_id_obj.our_as1 = as2.to_as1(actor_as2)
        self.key_id_obj.put()
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(204, resp.status_code, resp.get_data(as_text=True))
        mock_activitypub_log.assert_any_call('HTTP Signature verified!')

        # invalid signature, missing keyId
        protocol.seen_ids.clear()
        obj_key = ndb.Key(Object, NOTE['id'])
        obj_key.delete()

        resp = self.client.post('/ap/sharedInbox', data=body, headers={
            **headers,
            'signature': headers['signature'].replace(
                'keyId="http://my/key/id#unused",', ''),
        })
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'HTTP Signature missing keyId'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: HTTP Signature missing keyId', exc_info=None)

        # invalid signature, content changed
        protocol.seen_ids.clear()
        obj_key = ndb.Key(Object, NOTE['id'])
        obj_key.delete()

        resp = self.client.post('/ap/sharedInbox', json={**NOTE, 'content': 'z'}, headers=headers)
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'Invalid Digest header, required for HTTP Signature'},
                         resp.json)
        mock_common_log.assert_any_call('Returning 401: Invalid Digest header, required for HTTP Signature', exc_info=None)

        # invalid signature, header changed
        protocol.seen_ids.clear()
        obj_key.delete()

        resp = self.client.post('/ap/sharedInbox', data=body, headers={**headers, 'Date': 'X'})
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'HTTP Signature verification failed'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: HTTP Signature verification failed', exc_info=None)

        # no signature
        protocol.seen_ids.clear()
        obj_key.delete()
        resp = self.client.post('/ap/sharedInbox', json=NOTE)
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'error': 'No HTTP Signature'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: No HTTP Signature', exc_info=None)

    def test_delete_actor(self, *mocks):
        deleted = self.make_user(DELETE['actor'], cls=ActivityPub)
        follower = Follower.get_or_create(to=self.user, from_=deleted)
        followee = Follower.get_or_create(to=deleted, from_=Fake(id='fake:user'))

        # other unrelated follower
        other = self.make_user('https://mas.to/users/other', cls=ActivityPub)
        other = Follower.get_or_create(to=self.user, from_=other)

        self.assertEqual(3, Follower.query().count())

        got = self.post('/ap/sharedInbox', json=DELETE)
        self.assertEqual(204, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)
        self.assertEqual('inactive', followee.key.get().status)
        self.assertEqual('active', other.key.get().status)

    def test_delete_actor_not_fetchable(self, _, mock_get, ___):
        self.key_id_obj.key.delete()
        protocol.objects_cache.clear()

        mock_get.return_value = requests_response(status=410)
        got = self.post('/ap/sharedInbox', json={**DELETE, 'object': 'http://my/key/id'})
        self.assertEqual(202, got.status_code)

    def test_delete_actor_empty_deleted_object(self, _, mock_get, ___):
        self.key_id_obj.as2 = None
        self.key_id_obj.deleted = True
        self.key_id_obj.put()
        protocol.objects_cache.clear()

        got = self.post('/ap/sharedInbox', json={**DELETE, 'object': 'http://my/key/id'})
        self.assertEqual(202, got.status_code)
        mock_get.assert_not_called()

    def test_delete_note(self, _, mock_get, ___):
        obj = Object(id='http://an/obj')
        obj.put()

        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        delete = {
            **DELETE,
            'object': 'http://an/obj',
        }
        resp = self.post('/ap/sharedInbox', json=delete)
        self.assertEqual(204, resp.status_code)
        self.assertTrue(obj.key.get().deleted)
        self.assert_object(delete['id'],
                           our_as1={
                               **as2.to_as1(delete),
                               'actor': as2.to_as1(ACTOR),
                           },
                           type='delete',
                           source_protocol='activitypub',
                           status='ignored',
                           users=[ActivityPub(id='https://mas.to/users/swentel').key])

        obj.populate(deleted=True, as2=None)
        self.assert_entities_equal(obj,
                                   protocol.objects_cache['http://an/obj'],
                                   ignore=['expire', 'created', 'updated'])

    def test_update_note(self, *mocks):
        Object(id='https://a/note', as2={}).put()
        self._test_update(*mocks)

    def test_update_unknown(self, *mocks):
        self._test_update(*mocks)

    def _test_update(self, _, mock_get, ___):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
        ]

        resp = self.post('/ap/sharedInbox', json=UPDATE_NOTE)
        self.assertEqual(204, resp.status_code)

        note_as1 = as2.to_as1({
            **UPDATE_NOTE['object'],
            'author': {'id': 'https://mas.to/users/swentel'},
        })
        self.assert_object('https://a/note',
                           type='note',
                           our_as1=note_as1,
                           source_protocol='activitypub')

        update_as1 = {
            **as2.to_as1(UPDATE_NOTE),
            'object': note_as1,
            'actor': as2.to_as1(ACTOR),
        }
        self.assert_object(UPDATE_NOTE['id'],
                           source_protocol='activitypub',
                           type='update',
                           status='ignored',
                           our_as1=update_as1,
                           users=[self.swentel_key])

        self.assert_entities_equal(Object.get_by_id('https://a/note'),
                                   protocol.objects_cache['https://a/note'])

    def test_inbox_webmention_discovery_connection_fails(self, mock_head,
                                                         mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # protocol inference
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            # target post webmention discovery
            ReadTimeoutError(None, None, None),
        ]

        got = self.post('/user.com/inbox', json=LIKE)
        self.assertEqual(202, got.status_code)

    def test_inbox_no_webmention_endpoint(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            # source actor
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            # protocol inference
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            # target post webmention discovery
            HTML,
        ]

        got = self.post('/user.com/inbox', json=LIKE)
        self.assertEqual(202, got.status_code)

        self.assert_object('http://mas.to/like#ok',
                           notify=[self.user.key],
                           users=[self.masto_actor_key],
                           source_protocol='activitypub',
                           status='ignored',
                           our_as1=as2.to_as1(LIKE_WITH_ACTOR),
                           type='like',
                           object_ids=[LIKE['object']])

    def test_inbox_id_already_seen(self, *mocks):
        obj_key = Object(id=FOLLOW_WRAPPED['id'], as2={}).put()

        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(204, got.status_code)
        self.assertEqual(0, Follower.query().count())

        # second time should use in memory cache
        obj_key.delete()
        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(204, got.status_code)
        self.assertEqual(0, Follower.query().count())

    def test_inbox_http_sig_is_not_actor_author(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),  # author
        ]

        with self.assertLogs() as logs:
            got = self.post('/user.com/inbox', json={
                **NOTE_OBJECT,
                'author': 'https://alice',
            })
            self.assertEqual(204, got.status_code, got.get_data(as_text=True))

        self.assertIn(
            "WARNING:protocol:actor https://alice isn't authed user http://my/key/id",
            logs.output)

    def test_followers_collection_unknown_user(self, *_):
        resp = self.client.get('/nope.com/followers')
        self.assertEqual(404, resp.status_code)

    def test_followers_collection_empty(self, *_):
        resp = self.client.get('/user.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/user.com/followers',
            'type': 'Collection',
            'summary': "user.com's followers",
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/followers',
                'items': [],
            },
        }, resp.json)

    def store_followers(self):
        follow = Object(id=FOLLOW_WITH_ACTOR['id'], as2=FOLLOW_WITH_ACTOR).put()

        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://bar', cls=ActivityPub, obj_as2=ACTOR),
            follow=follow)
        Follower.get_or_create(
            to=self.make_user('https://other.actor', cls=ActivityPub),
            from_=self.user)
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://baz', cls=ActivityPub, obj_as2=ACTOR),
            follow=follow)
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://baj', cls=Fake),
            status='inactive')

    def test_followers_collection_fake(self, *_):
        self.make_user('foo.com', cls=Fake)

        resp = self.client.get('/ap/foo.com/followers',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/ap/foo.com/followers',
            'type': 'Collection',
            'summary': "foo.com's followers",
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://fa.brid.gy/ap/foo.com/followers',
                'items': [],
            },
        }, resp.json)

    def test_followers_collection(self, *_):
        self.store_followers()

        resp = self.client.get('/user.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/user.com/followers',
            'type': 'Collection',
            'summary': "user.com's followers",
            'totalItems': 2,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/followers',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('models.PAGE_SIZE', 1)
    def test_followers_collection_page(self, *_):
        self.store_followers()
        before = (datetime.utcnow() + timedelta(seconds=1)).isoformat()
        next = Follower.query(Follower.from_ == ActivityPub(id='http://baz').key,
                              Follower.to == self.user.key,
                              ).get().updated.isoformat()

        resp = self.client.get(f'/user.com/followers?before={before}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': f'http://localhost/user.com/followers?before={before}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/user.com/followers',
            'next': f'http://localhost/user.com/followers?before={next}',
            'prev': f'http://localhost/user.com/followers?after={before}',
            'items': [ACTOR],
        }, resp.json)

    def test_following_collection_unknown_user(self, *_):
        resp = self.client.get('/nope.com/following')
        self.assertEqual(404, resp.status_code)

    def test_following_collection_empty(self, *_):
        resp = self.client.get('/user.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/user.com/following',
            'summary': "user.com's following",
            'type': 'Collection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/following',
                'items': [],
            },
        }, resp.json)

    def store_following(self):
        follow = Object(id=FOLLOW_WITH_ACTOR['id'], as2=FOLLOW_WITH_ACTOR).put()

        Follower.get_or_create(
            to=self.make_user('http://bar', cls=ActivityPub, obj_as2=ACTOR),
            from_=self.user,
            follow=follow)
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('https://other.actor', cls=ActivityPub))
        Follower.get_or_create(
            to=self.make_user('http://baz', cls=ActivityPub, obj_as2=ACTOR),
            from_=self.user, follow=follow)
        Follower.get_or_create(
            to=self.make_user('http://baj', cls=ActivityPub),
            from_=self.user,
            status='inactive')

    def test_following_collection(self, *_):
        self.store_following()

        resp = self.client.get('/user.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/user.com/following',
            'summary': "user.com's following",
            'type': 'Collection',
            'totalItems': 2,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/following',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('models.PAGE_SIZE', 1)
    def test_following_collection_page(self, *_):
        self.store_following()
        after = datetime(1900, 1, 1).isoformat()
        prev = Follower.query(Follower.to == ActivityPub(id='http://baz').key,
                              Follower.from_ == self.user.key,
                              ).get().updated.isoformat()

        resp = self.client.get(f'/user.com/following?after={after}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': f'http://localhost/user.com/following?after={after}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/user.com/following',
            'prev': f'http://localhost/user.com/following?after={prev}',
            'next': f'http://localhost/user.com/following?before={after}',
            'items': [ACTOR],
        }, resp.json)

    def test_following_collection_head(self, *_):
        resp = self.client.head(f'/user.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('', resp.get_data(as_text=True))

    def test_outbox_fake_empty(self, *_):
        self.make_user('fake:foo', cls=Fake)
        resp = self.client.get(f'/ap/fake:foo/outbox',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/ap/fake:foo/outbox',
            'summary': "fake:foo's outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://fa.brid.gy/ap/fake:foo/outbox',
                'items': [],
            },
        }, resp.json)

    def store_outbox_objects(self, user):
        for i, obj in enumerate([REPLY, MENTION, LIKE, DELETE]):
            self.store_object(id=obj['id'], users=[user.key], as2=obj)

    @patch('models.PAGE_SIZE', 2)
    def test_outbox_fake_objects(self, *_):
        user = self.make_user('fake:foo', cls=Fake)
        self.store_outbox_objects(user)

        resp = self.client.get(f'/ap/fake:foo/outbox',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)

        after = Object.get_by_id(LIKE['id']).updated.isoformat()
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/ap/fake:foo/outbox',
            'summary': "fake:foo's outbox",
            'type': 'OrderedCollection',
            'totalItems': 4,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://fa.brid.gy/ap/fake:foo/outbox',
                'items': [DELETE, LIKE],
                'next': f'https://fa.brid.gy/ap/fake:foo/outbox?before={after}',
            },
        }, resp.json)

    @patch('models.PAGE_SIZE', 2)
    def test_outbox_fake_objects_page(self, *_):
        user = self.make_user('fake:foo', cls=Fake)
        self.store_outbox_objects(user)

        after = datetime(1900, 1, 1).isoformat()
        resp = self.client.get(f'/ap/fake:foo/outbox?after={after}',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)

        prev = Object.get_by_id(MENTION['id']).updated.isoformat()
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': f'https://fa.brid.gy/ap/fake:foo/outbox?after={after}',
            'type': 'CollectionPage',
            'partOf': 'https://fa.brid.gy/ap/fake:foo/outbox',
            'prev': f'https://fa.brid.gy/ap/fake:foo/outbox?after={prev}',
            'next': f'https://fa.brid.gy/ap/fake:foo/outbox?before={after}',
            'items': [MENTION, REPLY],
        }, resp.json)

    def test_outbox_web_empty(self, *_):
        resp = self.client.get(f'/user.com/outbox')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'http://localhost/user.com/outbox',
            'summary': "user.com's outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/outbox',
                'items': [],
            },
        }, resp.json)

    def test_outbox_web_head(self, *_):
        resp = self.client.head(f'/user.com/outbox')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('', resp.get_data(as_text=True))


class ActivityPubUtilsTest(TestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com', cls=Web, has_hcard=True, obj_as2=ACTOR)

    def test_put_validates_id(self, *_):
        for bad in (
            '',
            'not a url',
            'ftp://not.web/url',
            'https:///no/domain',
            'https://fed.brid.gy/foo',
            'https://ap.brid.gy/foo',
            'http://localhost/foo',
        ):
            with self.assertRaises(AssertionError):
                ActivityPub(id=bad).put()

    def test_owns_id(self):
        self.assertIsNone(ActivityPub.owns_id('http://foo/bar'))
        self.assertEqual(False, ActivityPub.owns_id('at://did:plc:foo/bar/123'))
        self.assertEqual(False, ActivityPub.owns_id('e45fab982'))
        self.assertEqual(False, ActivityPub.owns_id('https://example.com/'))
        self.assertEqual(False, ActivityPub.owns_id('https://twitter.com/foo'))
        self.assertEqual(False, ActivityPub.owns_id('https://fed.brid.gy/foo'))

    def test_owns_handle(self):
        for handle in ('@user@instance', 'user@instance.com', 'user.com@instance.com',
                     'user@instance'):
            with self.subTest(handle=handle):
                assert ActivityPub.owns_handle(handle)

        for handle in ('instance', 'instance.com', '@user', '@user.com',
                    'http://user.com'):
            with self.subTest(handle=handle):
                self.assertFalse(ActivityPub.owns_handle(handle))

    def test_handle_to_id_stored(self):
        self.make_user(id='http://inst.com/@user', cls=ActivityPub)
        self.assertEqual('http://inst.com/@user',
                         ActivityPub.handle_to_id('@user@inst.com'))

    @patch('requests.get')
    def test_handle_to_id_fetch(self, mock_get):
        mock_get.return_value = requests_response(test_webfinger.WEBFINGER)
        self.assertEqual('http://localhost/user.com',
                         ActivityPub.handle_to_id('@user@inst.com'))
        self.assert_req(
            mock_get,
            'https://inst.com/.well-known/webfinger?resource=acct:user@inst.com')

    @patch('requests.get', return_value=requests_response({}))
    def test_handle_to_id_not_found(self, mock_get):
        self.assertIsNone(ActivityPub.handle_to_id('@user@inst.com'))
        self.assert_req(
            mock_get,
            'https://inst.com/.well-known/webfinger?resource=acct:user@inst.com')

    def test_postprocess_as2_multiple_in_reply_tos(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'inReplyTo': 'foo',
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'inReplyTo': ['foo', 'bar'],
        }))

    def test_postprocess_as2_multiple_url(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'url': ['http://localhost/r/foo', 'http://localhost/r/bar'],
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'url': ['foo', 'bar'],
        }))

    def test_postprocess_as2_multiple_image(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'attachment': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
            'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'image': [{'url': 'http://r/foo'}, {'url': 'http://r/bar'}],
        }))

    def test_postprocess_as2_actor_attributedTo_author(self):
        g.user = Fake(id='fake:site')
        self.assert_equals({
            'actor': 'baj',
            'attributedTo': ['bar', 'baz'],
            'author': 'biff',
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'attributedTo': [{'id': 'bar'}, {'id': 'baz'}],
            'actor': {'id': 'baj'},
            'author': {'id': 'biff'},
        }))

    def test_postprocess_as2_note(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'type': 'Note',
            'content': 'foo',
            'contentMap': {'en': 'foo'},
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'type': 'Note',
            'content': 'foo',
        }))

    def test_postprocess_as2_hashtag(self):
        """https://github.com/snarfed/bridgy-fed/issues/45"""
        self.assert_equals({
            'tag': [
                {'type': 'Hashtag', 'name': '#bar', 'href': 'bar'},
                {'type': 'Hashtag', 'name': '#baz', 'href': 'http://localhost/hashtag/baz'},
                {'type': 'Mention', 'href': 'foo'},
            ],
            'to': [as2.PUBLIC_AUDIENCE],
            'cc': ['foo'],
        }, postprocess_as2({
            'tag': [
                {'name': 'bar', 'href': 'bar'},
                {'type': 'Tag', 'name': '#baz'},
                # should leave alone
                {'type': 'Mention', 'href': 'foo'},
            ],
        }))

    def test_postprocess_as2_url_attachments(self):
        g.user = self.user
        got = postprocess_as2(as2.from_as1({
            'objectType': 'person',
            'urls': [
                {
                    'value': 'https://user.com/about-me',
                    'displayName': 'Mrs. \u2615 Foo',
                }, {
                    'value': 'https://user.com/',
                    'displayName': 'should be ignored',
                }, {
                    'value': 'http://one',
                    'displayName': 'one text',
                }, {
                    'value': 'https://two',
                    'displayName': 'two title',
                },
            ]
        }))

        self.assert_equals([{
            'type': 'PropertyValue',
            'name': 'Mrs. ☕ Foo',
            'value': '<a rel="me" href="https://user.com/about-me"><span class="invisible">https://</span>user.com/about-me</a>',

        }, {
            'type': 'PropertyValue',
            'name': 'Web site',
            'value': '<a rel="me" href="https://user.com"><span class="invisible">https://</span>user.com</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'one text',
            'value': '<a rel="me" href="http://one"><span class="invisible">http://</span>one</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'two title',
            'value': '<a rel="me" href="https://two"><span class="invisible">https://</span>two</a>',
        }], got['attachment'])

    def test_postprocess_as2_preserves_preferredUsername(self):
        # preferredUsername stays y.z despite user's username. since Mastodon
        # queries Webfinger for preferredUsername@fed.brid.gy
        # https://github.com/snarfed/bridgy-fed/issues/77#issuecomment-949955109
        g.user = self.user
        self.assertEqual('user.com', postprocess_as2({
            'type': 'Person',
            'url': 'https://user.com/about-me',
            'preferredUsername': 'nick',
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'nick',
                'value': '<a rel="me" href="https://user.com/about-me"><span class="invisible">https://</span>user.com/about-me</a>',
            }],
        })['preferredUsername'])

    def test_postprocess_as2_mentions_into_cc(self):
        obj = copy.deepcopy(MENTION_OBJECT)
        del obj['cc']
        self.assertEqual(['https://masto.foo/@other'],
                         postprocess_as2(obj)['cc'])

    @patch('requests.get')
    def test_signed_get_redirects_manually_with_new_sig_headers(self, mock_get):
        mock_get.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
            requests_response(status=200, allow_redirects=False),
        ]
        activitypub.signed_get('https://first')

        first = mock_get.call_args_list[0][1]
        second = mock_get.call_args_list[1][1]
        self.assertNotEqual(first['headers'], second['headers'])

    @patch('requests.get')
    def test_signed_get_redirects_to_relative_url(self, mock_get):
        mock_get.side_effect = [
            # redirected URL is relative, we have to resolve it
            requests_response(status=302, redirected_url='/second',
                              allow_redirects=False),
            requests_response(status=200, allow_redirects=False),
        ]
        activitypub.signed_get('https://first')

        self.assertEqual(('https://first/second',), mock_get.call_args_list[1][0])

        first = mock_get.call_args_list[0][1]
        second = mock_get.call_args_list[1][1]

        # headers are equal because host is the same
        self.assertEqual(first['headers'], second['headers'])
        self.assertEqual(
            first['auth'].header_signer.sign(first['headers'], method='GET', path='/'),
            second['auth'].header_signer.sign(second['headers'], method='GET', path='/'))

    @patch('requests.post', return_value=requests_response(status=200))
    def test_signed_post_g_user_is_activitypub_so_use_default_user(self, mock_post):
        g.user = ActivityPub(id='http://feddy')
        activitypub.signed_post('https://url')

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('https://url',), args)
        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(default_signature_user().private_pem(), rsa_key.exportKey())

    @patch('requests.post')
    def test_signed_post_ignores_redirect(self, mock_post):
        mock_post.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
        ]

        g.user = self.user
        resp = activitypub.signed_post('https://first')
        mock_post.assert_called_once()
        self.assertEqual(302, resp.status_code)

    @patch('requests.get')
    def test_fetch_direct(self, mock_get):
        mock_get.return_value = AS2
        obj = Object(id='http://orig')
        ActivityPub.fetch(obj)
        self.assertEqual(AS2_OBJ, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_direct_ld_content_type(self, mock_get):
        mock_get.return_value = requests_response(AS2_OBJ, headers={
            'Content-Type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
        })
        obj = Object(id='http://orig')
        ActivityPub.fetch(obj)
        self.assertEqual(AS2_OBJ, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_via_html(self, mock_get):
        mock_get.side_effect = [HTML_WITH_AS2, AS2]
        obj = Object(id='http://orig')
        ActivityPub.fetch(obj)
        self.assertEqual(AS2_OBJ, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
            self.as2_req('http://as2', headers=as2.CONNEG_HEADERS),
        ))

    @patch('requests.get')
    def test_fetch_only_html(self, mock_get):
        mock_get.return_value = HTML

        obj = Object(id='http://orig')
        self.assertFalse(ActivityPub.fetch(obj))
        self.assertIsNone(obj.as1)

    @patch('requests.get')
    def test_fetch_not_acceptable(self, mock_get):
        mock_get.return_value = NOT_ACCEPTABLE

        obj = Object(id='http://orig')
        self.assertFalse(ActivityPub.fetch(obj))
        self.assertIsNone(obj.as1)

    @patch('requests.get')
    def test_fetch_ssl_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.SSLError
        with self.assertRaises(BadGateway):
            ActivityPub.fetch(Object(id='http://orig'))

    @patch('requests.get')
    def test_fetch_no_content(self, mock_get):
        mock_get.return_value = self.as2_resp('')

        with self.assertRaises(BadGateway):
            ActivityPub.fetch(Object(id='http://the/id'))

        mock_get.assert_has_calls([self.as2_req('http://the/id')])

    @patch('requests.get')
    def test_fetch_not_json(self, mock_get):
        mock_get.return_value = self.as2_resp('XYZ not JSON')

        with self.assertRaises(BadGateway):
            ActivityPub.fetch(Object(id='http://the/id'))

        mock_get.assert_has_calls([self.as2_req('http://the/id')])

    def test_fetch_non_url(self):
        obj = Object(id='x y z')
        self.assertFalse(ActivityPub.fetch(obj))
        self.assertIsNone(obj.as1)

    def test_convert(self):
        obj = Object()
        self.assertEqual({}, ActivityPub.convert(obj))

        obj.our_as1 = {}
        self.assertEqual({}, ActivityPub.convert(obj))

        obj.as2 = {'baz': 'biff'}
        self.assertEqual({'baz': 'biff'}, ActivityPub.convert(obj))

        # prevent HTTP fetch to infer protocol
        self.store_object(id='https://mas.to/thing', source_protocol='activitypub')
        obj.as2 = None
        obj.our_as1 = {
            'id': 'fake:like',
            'objectType': 'activity',
            'verb': 'like',
            'actor': 'fake:user',
            'object': 'https://mas.to/thing',
        }
        g.user = self.user
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/convert/ap/fake:like',
            'type': 'Like',
            'actor': 'https://fa.brid.gy/ap/fake:user',
            'object': 'https://mas.to/thing',
            'to': [as2.PUBLIC_AUDIENCE],
        }, ActivityPub.convert(obj))

    def test_postprocess_as2_idempotent(self):
        g.user = self.user

        for obj in (ACTOR, REPLY_OBJECT, REPLY_OBJECT_WRAPPED, REPLY,
                    NOTE_OBJECT, NOTE, MENTION_OBJECT, MENTION, LIKE,
                    LIKE_WRAPPED, REPOST, FOLLOW, FOLLOW_WRAPPED, ACCEPT,
                    UNDO_FOLLOW_WRAPPED, DELETE, UPDATE_NOTE,
                    LIKE_WITH_ACTOR, REPOST_FULL, FOLLOW_WITH_ACTOR,
                    FOLLOW_WRAPPED_WITH_ACTOR, FOLLOW_WITH_OBJECT, UPDATE_PERSON,
                    ):
            with self.subTest(obj=obj):
                obj = copy.deepcopy(obj)
                self.assert_equals(postprocess_as2(obj),
                                   postprocess_as2(postprocess_as2(obj)),
                                   ignore=['to'])

    def test_ap_address(self):
        user = ActivityPub(obj=Object(id='a', as2={
            **ACTOR,
            'preferredUsername': 'me',
        }))
        self.assertEqual('@me@mas.to', user.ap_address())
        self.assertEqual('@me@mas.to', user.handle)

        user.obj.as2 = ACTOR
        self.assertEqual('@swentel@mas.to', user.ap_address())
        self.assertEqual('@swentel@mas.to', user.handle)

        user = ActivityPub(id='https://mas.to/users/alice')
        self.assertEqual('@alice@mas.to', user.ap_address())
        self.assertEqual('@alice@mas.to', user.handle)

    def test_ap_actor(self):
        user = self.make_user('http://foo/actor', cls=ActivityPub)
        self.assertEqual('http://foo/actor', user.ap_actor())

    def test_handle_as(self):
        user = self.make_user('http://a', cls=ActivityPub, obj_as2={
            'id': 'https://mas.to/users/foo',
            'preferredUsername': 'me',
        })
        self.assertEqual('me.mas.to.ap.brid.gy', user.handle_as('atproto'))

    def test_web_url(self):
        user = self.make_user('http://foo/actor', cls=ActivityPub)
        self.assertEqual('http://foo/actor', user.web_url())

        user.obj = Object(id='a', as2=copy.deepcopy(ACTOR))  # no url
        self.assertEqual('http://foo/actor', user.web_url())

        user.obj.as2['url'] = ['http://my/url']
        self.assertEqual('http://my/url', user.web_url())

    def test_handle(self):
        user = self.make_user('http://foo', cls=ActivityPub)
        self.assertIsNone(user.handle)
        self.assertEqual('http://foo', user.handle_or_id())

        user.obj = Object(id='a', as2=ACTOR)
        self.assertEqual('@swentel@mas.to', user.handle)
        self.assertEqual('@swentel@mas.to', user.handle_or_id())

    @skip
    def test_target_for_not_activitypub(self):
        with self.assertRaises(AssertionError):
            ActivityPub.target_for(Object(source_protocol='web'))

    def test_target_for_actor(self):
        self.assertEqual(ACTOR['inbox'], ActivityPub.target_for(
            Object(source_protocol='ap', as2=ACTOR)))

        actor = copy.deepcopy(ACTOR)
        del actor['inbox']
        self.assertIsNone(ActivityPub.target_for(
            Object(source_protocol='ap', as2=actor)))

        actor['publicInbox'] = 'so-public'
        self.assertEqual('so-public', ActivityPub.target_for(
            Object(source_protocol='ap', as2=actor)))

        # sharedInbox
        self.assertEqual('so-public', ActivityPub.target_for(
            Object(source_protocol='ap', as2=actor), shared=True))
        actor['endpoints'] = {
            'sharedInbox': 'so-shared',
        }
        self.assertEqual('so-public', ActivityPub.target_for(
            Object(source_protocol='ap', as2=actor)))
        self.assertEqual('so-shared', ActivityPub.target_for(
            Object(source_protocol='ap', as2=actor), shared=True))

    def test_target_for_object(self):
        obj = Object(as2=NOTE_OBJECT, source_protocol='ap')
        self.assertIsNone(ActivityPub.target_for(obj))

        Object(id=ACTOR['id'], as2=ACTOR).put()
        obj.as2 = {
            **NOTE_OBJECT,
            'author': ACTOR['id'],
        }
        self.assertEqual('http://mas.to/inbox', ActivityPub.target_for(obj))

        del obj.as2['author']
        obj.as2['actor'] = copy.deepcopy(ACTOR)
        obj.as2['actor']['url'] = [obj.as2['actor'].pop('id')]
        self.assertEqual('http://mas.to/inbox', ActivityPub.target_for(obj))

    @patch('requests.get')
    def test_target_for_object_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(ACTOR)

        obj = Object(as2={
            **NOTE_OBJECT,
            'author': 'http://the/author',
        }, source_protocol='ap')
        self.assertEqual('http://mas.to/inbox', ActivityPub.target_for(obj))
        mock_get.assert_has_calls([self.as2_req('http://the/author')])

    @patch('requests.get')
    def test_target_for_author_is_object_id(self, mock_get):
        mock_get.return_value = HTML

        obj = self.store_object(id='http://the/author', our_as1={
            'author': 'http://the/author',
        })
        # test is that we short circuit out instead of infinite recursion
        g.user = self.user
        self.assertIsNone(ActivityPub.target_for(obj))

    @patch('requests.post')
    def test_send_blocklisted(self, mock_post):
        self.assertFalse(ActivityPub.send(Object(as2=NOTE),
                                          'https://fed.brid.gy/ap/sharedInbox'))
        mock_post.assert_not_called()

    @patch('requests.post')
    def test_send_convert_ids(self, mock_post):
        mock_post.return_value = requests_response()

        like = Object(our_as1={
            'id': 'fake:like',
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
            'actor': 'fake:user',
        })
        g.user = self.user
        self.assertTrue(ActivityPub.send(like, 'https://inbox'))

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('https://inbox',), args)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/convert/ap/fake:like',
            'type': 'Like',
            'object': 'https://fa.brid.gy/convert/ap/fake:post',
            'actor': 'https://fa.brid.gy/ap/fake:user',
            'to': [as2.PUBLIC_AUDIENCE],
        }, json_loads(kwargs['data']))
