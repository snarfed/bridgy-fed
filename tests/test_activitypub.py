"""Unit tests for activitypub.py."""
from base64 import b64encode
import copy
from datetime import datetime, timedelta, UTC
from hashlib import sha256
import logging
from unittest import skip
from unittest.mock import patch

from google.cloud import ndb
from granary import as1, as2, microformats2
from httpsig import HeaderSigner
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import domain_from_link, json_dumps, json_loads
import requests
from requests import TooManyRedirects
from requests.exceptions import InvalidURL
from urllib3.exceptions import ReadTimeoutError
from werkzeug.exceptions import BadGateway, BadRequest

# import first so that Fake is defined before URL routes are registered
from . import testutil
from .testutil import ExplicitFake, Fake, global_user, OtherFake, TestCase

import activitypub
from activitypub import (
    ActivityPub,
    instance_actor,
    postprocess_as2,
    postprocess_as2_actor,
    SECURITY_CONTEXT,
)
from atproto import ATProto
import common
from flask_app import app
import memcache
from models import Follower, Object, Target
import protocol
from protocol import DELETE_TASK_DELAY
from web import Web

# have to import module, not attrs, to avoid circular import
from . import test_web
from . import test_webfinger

ACTOR = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/users/swentel',
    'type': 'Person',
    'inbox': 'http://mas.to/inbox',
    'name': 'Mrs. ☕ Foo',
    'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
    'image': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
    'discoverable': True,
    'indexable': True,
}
ACTOR_AS1 = as2.to_as1(ACTOR)
ACTOR_BASE = {
    '@context': as2.CONTEXT + [activitypub.SECURITY_CONTEXT, activitypub.AKA_CONTEXT],
    'type': 'Person',
    'id': 'http://localhost/user.com',
    'url': 'http://localhost/r/https://user.com/',
    'preferredUsername': 'user.com',
    'inbox': 'http://localhost/user.com/inbox',
    'outbox': 'http://localhost/user.com/outbox',
    'following': 'http://localhost/user.com/following',
    'followers': 'http://localhost/user.com/followers',
    'endpoints': {
        'sharedInbox': 'http://localhost/ap/sharedInbox',
    },
    'alsoKnownAs': ['https://user.com/'],
    'manuallyApprovesFollowers': False,
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
    '@context': as2.CONTEXT + [activitypub.SECURITY_CONTEXT, activitypub.AKA_CONTEXT],
    'type': 'Person',
    'id': 'https://fa.brid.gy/ap/fake:user',
    'url': 'https://fa.brid.gy/r/web:fake:user',
    'inbox': 'https://fa.brid.gy/ap/fake:user/inbox',
    'outbox': 'https://fa.brid.gy/ap/fake:user/outbox',
    'following': 'https://fa.brid.gy/ap/fake:user/following',
    'followers': 'https://fa.brid.gy/ap/fake:user/followers',
    'endpoints': {'sharedInbox': 'https://fa.brid.gy/ap/sharedInbox'},
    'preferredUsername': 'fake-handle-user',
    'summary': '',
    'alsoKnownAs': ['uri:fake:user'],
    'manuallyApprovesFollowers': False,
}
ACTOR_FAKE_USER = {
    **ACTOR_FAKE,
    '@context': as2.CONTEXT + [
        as2.DISCOVERABLE_INDEXABLE_CONTEXT,
        as2.PROPERTY_VALUE_CONTEXT,
        activitypub.SECURITY_CONTEXT,
        activitypub.AKA_CONTEXT,
    ],
    'name': 'fake-handle-user',
    'type': 'Person',
    'summary': '🌉 <a href="https://fed.brid.gy/fa/fake:handle:user">bridged</a> from 🤡 <a href="web:fake:user">fake:handle:user</a> by <a href="https://fed.brid.gy/">Bridgy Fed</a>',
    'discoverable': True,
    'indexable': True,
}

REPLY_OBJECT = {
    '@context': as2.CONTEXT,
    'type': 'Note',
    'content': 'A ☕ reply',
    'id': 'http://mas.to/reply/id',
    'url': 'http://mas.to/reply',
    'attributedTo': 'https://mas.to/users/swentel',
    'inReplyTo': 'https://user.com/post',
    'to': [as2.PUBLIC_AUDIENCE],
}
REPLY_OBJECT_WRAPPED = copy.deepcopy(REPLY_OBJECT)
REPLY_OBJECT_WRAPPED['inReplyTo'] = 'http://localhost/r/https://user.com/post'
REPLY = {
    '@context': as2.CONTEXT,
    'type': 'Create',
    'id': 'http://mas.to/reply/as2',
    'object': REPLY_OBJECT,
}
NOTE_OBJECT = {
    '@context': as2.CONTEXT,
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
    '@context': as2.CONTEXT,
    'type': 'Create',
    'id': 'http://mas.to/note/as2',
    'actor': 'https://mas.to/users/swentel',
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
    '@context': as2.CONTEXT,
    'type': 'Create',
    'id': 'http://mas.to/mention/as2',
    'object': MENTION_OBJECT,
}
# based on example Mastodon like:
# https://github.com/snarfed/bridgy-fed/issues/4#issuecomment-334212362
# (reposts are very similar)
LIKE = {
    '@context': as2.CONTEXT,
    'id': 'http://mas.to/like#ok',
    'type': 'Like',
    'object': 'https://user.com/post',
    'actor': 'https://mas.to/me',
}
LIKE_WRAPPED = copy.deepcopy(LIKE)
LIKE_WRAPPED['object'] = 'http://localhost/r/https://user.com/post'
LIKE_ACTOR = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/me',
    'type': 'Person',
    'name': 'Ms. Actor',
    'preferredUsername': 'msactor',
    'icon': {'type': 'Image', 'url': 'https://user.com/pic.jpg'},
    'image': [
        {'type': 'Image', 'url': 'https://user.com/thumb.jpg'},
        {'type': 'Image', 'url': 'https://user.com/pic.jpg'},
    ],
    'discoverable': True,
    'indexable': True,
}
LIKE_WITH_ACTOR = {
    **LIKE,
    'actor': LIKE_ACTOR,
}

# repost, should be delivered to followers if object is a fediverse post,
# translated to webmention if object is an indieweb post
REPOST = {
  '@context': as2.CONTEXT,
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
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/follow',
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
    '@context': as2.CONTEXT,
    'type': 'Accept',
    'id': 'https://localhost/r/user.com/followers#accept-https://mas.to/follow',
    'actor': 'http://localhost/user.com',
    'object': {
        'type': 'Follow',
        'id': 'https://mas.to/follow',
        'object': 'http://localhost/user.com',
        'actor': 'https://mas.to/users/swentel',
        'url': 'https://mas.to/users/swentel#followed-user.com',
        'to': [as2.PUBLIC_AUDIENCE],
    },
   'to': [as2.PUBLIC_AUDIENCE],
}

UNDO_FOLLOW_WRAPPED = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/6d1b',
    'type': 'Undo',
    'actor': 'https://mas.to/users/swentel',
    'object': FOLLOW_WRAPPED,
}

DELETE = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/users/swentel#delete',
    'type': 'Delete',
    'actor': 'https://mas.to/users/swentel',
    'object': 'https://mas.to/users/swentel',
}

UPDATE_PERSON = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/person#update',
    'type': 'Update',
    'actor': 'https://mas.to/users/swentel',
    'object': {
        'type': 'Person',
        'id': 'https://mas.to/person',
    },
}
UPDATE_NOTE = {
    '@context': as2.CONTEXT,
    'id': 'https://mas.to/note#update',
    'type': 'Update',
    'actor': 'https://mas.to/users/swentel',
    'object': {
        'type': 'Note',
        'id': 'https://mas.to/note',
        'content': 'foo',
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


def add_key(obj):
    obj['publicKey'] = {
        'id': f'{obj["id"]}#key',
        'owner': obj['id'],
        'publicKeyPem': global_user.public_pem().decode(),
    }
    return obj


def sign(path, body, key_id, host='localhost'):
    """Constructs HTTP Signature, returns headers."""
    digest = b64encode(sha256(body.encode()).digest()).decode()
    headers = {
        'Date': 'Sun, 02 Jan 2022 03:04:05 GMT',
        'Host': host,
        'Content-Type': as2.CONTENT_TYPE,
        'Digest': f'SHA-256={digest}',
    }
    hs = HeaderSigner(key_id, global_user.private_pem().decode(),
                      algorithm='rsa-sha256', sign_header='signature',
                      headers=('Date', 'Host', 'Digest', '(request-target)'))
    return hs.sign(headers, method='POST', path=path)


# @patch.object(Fake, 'HAS_COPIES', False)
# @patch.object(OtherFake, 'HAS_COPIES', False)
@patch('requests.post')
@patch('requests.get')
@patch('requests.head')
class ActivityPubTest(TestCase):

    def setUp(self):
        super().setUp()

        self.user = self.make_user('user.com', cls=Web, has_hcard=True,
                                   has_redirects=True,
                                   obj_as1={**ACTOR_AS1, 'id': 'https://user.com/'})
        self.swentel_key = ndb.Key(ActivityPub, 'https://mas.to/users/swentel')
        self.masto_actor_key = ndb.Key(ActivityPub, 'https://mas.to/me')

        self.key_id_obj = Object(id='http://mas.to/key/id', as2={
            **ACTOR,
            'id': 'http://mas.to/key/id',
        })

        for obj in ACTOR, ACTOR_BASE, ACTOR_FAKE, LIKE_ACTOR, self.key_id_obj.as2:
            add_key(obj)

    def post(self, path, json=None, base_url=None, **kwargs):
        """Wrapper around self.client.post that adds signature."""
        body = json_dumps(json)
        host = domain_from_link(base_url) if base_url else None
        headers = sign(path, body, host=host, key_id=as1.get_owner(as2.to_as1(json)))
        return self.client.post(path, data=body, headers=headers,
                                base_url=base_url, **kwargs)

    @patch('ids.ATPROTO_HANDLE_DOMAINS', ('a.co', 'b.org'))
    @patch('activitypub.OLD_ACCOUNT_EXEMPT_DOMAINS', ('a.co', 'c.d.net'))
    def test_REQUIRES_OLD_ACCOUNT_and_REQUIRES_AVATAR(self, *_):
        for id in ('http://a.co/x', 'http://sub.subb.a.co/y', 'http://b.org/'):
            with self.subTest(id=id):
                self.assertFalse(ActivityPub(id=id).REQUIRES_AVATAR)
                self.assertFalse(ActivityPub(id=id).REQUIRES_OLD_ACCOUNT)

        cdnet = ActivityPub(id='https://c.d.net/e/f')
        self.assertTrue(cdnet.REQUIRES_AVATAR)
        self.assertFalse(cdnet.REQUIRES_OLD_ACCOUNT)

        zio = ActivityPub(id='https://z.io/y')
        self.assertTrue(zio.REQUIRES_AVATAR)
        self.assertTrue(zio.REQUIRES_OLD_ACCOUNT)

    def test_actor_fake(self, *_):
        self.make_user('fake:user', cls=Fake, enabled_protocols=['activitypub'])
        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE_LD_PROFILE})
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assertEqual(as2.CONTENT_TYPE_LD_PROFILE, got.headers['Content-Type'])
        self.assertEqual('Accept', got.headers['Vary'])
        self.assertEqual(ACTOR_FAKE, got.json)

    def test_actor_fake_protocol_subdomain(self, *_):
        self.make_user('fake:user', cls=Fake, enabled_protocols=['activitypub'])
        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assertEqual(ACTOR_FAKE, got.json)
        self.assertEqual('Accept', got.headers['Vary'])

    def test_actor_web(self, *_):
        """Web users are special cased to drop the /web/ prefix."""
        got = self.client.get('/user.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assertEqual(as2.CONTENT_TYPE, got.headers['Content-Type'])
        self.assertEqual('Accept', got.headers['Vary'])
        self.assert_equals({
            **ACTOR_BASE_FULL,
            'type': 'Person',
            'name': 'Mrs. ☕ Foo',
            'summary': '',
            'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
            'image': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
            'discoverable': True,
            'indexable': True,
        }, got.json, ignore=['@context', 'attachment', 'publicKey'])

    def test_actor_blocked_tld(self, _, __, ___):
        got = self.client.get('/foo.json')
        self.assertEqual(404, got.status_code)

    def test_actor_no_conneg_redirect_to_profile(self, _, __, ___):
        got = self.client.get('/user.com')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://user.com/', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_actor_conneg_star_redirect_to_profile(self, _, __, ___):
        got = self.client.get('/user.com', headers={'Accept': '*/*'})
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://user.com/', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_actor_conneg_html_redirect_to_profile(self, _, __, ___):
        got = self.client.get('/user.com', headers={'Accept': 'text/html'})
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://user.com/', got.headers['Location'])
        self.assertEqual('Accept', got.headers['Vary'])

    def test_actor_new_user_fetch(self, _, mock_get, __):
        self.make_user(cls=Web, id='fa.brid.gy')
        self.user.obj_key.delete()
        self.user.key.delete()
        mock_get.side_effect = test_web.web_user_gets('user.com')

        got = self.client.get('/user.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assert_equals(add_key({
            **ACTOR_BASE_FULL,
            'discoverable': True,
            'indexable': True,
        }), got.json, ignore=['@context', 'publicKeyPem', 'summary'])

    def test_actor_new_user_fetch_no_mf2(self, _, mock_get, __):
        self.user.obj_key.delete()
        self.user.key.delete()

        mock_get.side_effect = [
            WEBMENTION_DISCOVERY,
            requests_response(status=404),
            WEBMENTION_DISCOVERY,
        ]

        got = self.client.get('/user.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, got.status_code)

    def test_actor_new_user_fetch_fails(self, _, mock_get, ___):
        mock_get.side_effect = ReadTimeoutError(None, None, None)
        got = self.client.get('/nope.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(504, got.status_code)

    def test_actor_handle_existing_user(self, _, __, ___):
        self.make_user(cls=Web, id='fa.brid.gy')
        self.make_user('fake:user', cls=Fake, obj_as1=as2.to_as1({
            **ACTOR_FAKE,
            'id': 'fake:profile:user',
        }), enabled_protocols=['activitypub'])

        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assert_equals(ACTOR_FAKE_USER, got.json,
                           ignore=['attachment', 'publicKey'])

    @patch.object(Fake, 'DEFAULT_ENABLED_PROTOCOLS', new=['activitypub'])
    def test_actor_handle_new_user(self, _, __, ___):
        self.make_user(cls=Web, id='fa.brid.gy')
        Fake.fetchable['fake:profile:user'] = as2.to_as1({
            **ACTOR_FAKE,
            'id': 'fake:profile:user',
        })
        got = self.client.get('/ap/fake:user', base_url='https://fa.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assert_equals(ACTOR_FAKE_USER, got.json,
                           ignore=['attachment', 'publicKey'])

    def test_actor_activitypub_not_enabled(self, *_):
        obj = self.store_object(id='did:plc:user', raw={'foo': 'baz'})
        self.make_user('did:plc:user', cls=ATProto, obj_key=obj.key)
        got = self.client.get('/ap/did:plc:user', base_url='https://bsky.brid.gy/')
        self.assertEqual(404, got.status_code)

    def test_actor_atproto_no_handle(self, *_):
        self.store_object(id='did:plc:user', raw={'foo': 'bar'})
        self.store_object(id='at://did:plc:user/app.bsky.actor.profile/self', bsky={
            '$type': 'app.bsky.actor.profile',
            'displayName': 'Alice',
        })

        self.make_user('did:plc:user', cls=ATProto, enabled_protocols=['activitypub'])

        got = self.client.get('/ap/did:plc:user', base_url='https://bsky.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assertNotIn('preferredUsername', got.json)

    def test_actor_handle_user_fetch_fails(self, _, __, ___):
        got = self.client.get('/ap/fake/fake:nope',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, got.status_code)

    def test_actor_no_matching_protocol(self, *_):
        resp = self.client.get('/foo.json',
                               base_url='https://bridgy-federated.appspot.com/',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, resp.status_code)

    def test_actor_web_redirects(self, *_):
        resp = self.client.get('/ap/user.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://fed.brid.gy/user.com', resp.headers['Location'])

        self.user.ap_subdomain = 'web'
        self.user.put()
        resp = self.client.get('/user.com', base_url='https://fed.brid.gy/',
                               headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://web.brid.gy/user.com', resp.headers['Location'])

        self.user.ap_subdomain = 'fed'
        self.user.put()
        got = self.client.get('/user.com', base_url='https://web.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(301, got.status_code)
        self.assertEqual('https://fed.brid.gy/user.com', got.headers['Location'])

    def test_actor_opted_out(self, *_):
        self.user.obj.our_as1['summary'] = '#nobridge'
        self.user.obj.put()
        self.user.put()

        got = self.client.get('/user.com', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, got.status_code)

        got = self.client.get('/user.com')
        self.assertEqual(404, got.status_code)

    def test_actor_bad_id(self, *_):
        # Web.get_or_create => urllib.parse.urlparse raises
        # ValueError: Invalid IPv6 URL
        got = self.client.get('/bsky]foo.bar', headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, got.status_code)

    def test_actor_protocol_bot_user(self, *_):
        """Web users are special cased to drop the /web/ prefix."""
        actor_as2 = json_loads(util.read('bsky.brid.gy.as2.json'))
        self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky',
                       obj_as2=copy.deepcopy(actor_as2),
                       obj_id='https://bsky.brid.gy/')

        got = self.client.get('/bsky.brid.gy', base_url='https://bsky.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assertEqual(as2.CONTENT_TYPE, got.headers['Content-Type'])

        # assertEqual instead of assert_equals so that we check that nothing in
        # @context is duplicated
        # https://github.com/snarfed/bridgy-fed/issues/1003
        got_json = copy.deepcopy(got.json)
        for field in ['inbox', 'outbox', 'endpoints', 'followers', 'following',
                      'publicKey']:
            got_json.pop(field)
        self.assertEqual(actor_as2, got_json)

    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_actor_protocol_bot_user_doesnt_exist(self, *_):
        got = self.client.get('/web.brid.gy', base_url='https://web.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(404, got.status_code, got.get_data(as_text=True))

    def test_instance_actor_fetch(self, *_):
        def reset_instance_actor():
            activitypub._INSTANCE_ACTOR = testutil.global_user
        self.addCleanup(reset_instance_actor)

        actor_as2 = json_loads(util.read('fed.brid.gy.as2.json'))
        self.make_user(common.PRIMARY_DOMAIN, cls=Web, obj_as2=actor_as2,
                       obj_id='https://fed.brid.gy/', ap_subdomain='fed',
                       has_redirects=True)

        activitypub._INSTANCE_ACTOR = None
        got = self.client.get('/fed.brid.gy', base_url='https://fed.brid.gy/',
                              headers={'Accept': as2.CONTENT_TYPE})
        self.assertEqual(200, got.status_code)
        self.assert_equals(actor_as2, got.json,
                           ignore=['inbox', 'outbox', 'endpoints', 'followers',
                                   'following', 'publicKey', 'publicKeyPem'])

    def test_individual_inbox_no_user(self, mock_head, mock_get, mock_post):
        self.user.key.delete()

        mock_get.side_effect = [
            self.as2_resp(LIKE_ACTOR),
            self.as2_resp(LIKE_ACTOR),
            requests_response(status=404),
        ]

        reply = {
            **REPLY,
            'actor': LIKE_ACTOR,
        }
        self._test_inbox_reply(reply, mock_head, mock_get, mock_post)

        self.assert_user(ActivityPub, 'https://mas.to/me', obj_as2=LIKE_ACTOR)

    def test_inbox_transient_activity_generates_id(self, mock_head, mock_get,
                                                   mock_post):
        user = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        mock_get.return_value = self.as2_resp(ACTOR)

        note = copy.deepcopy(NOTE)
        del note['id']
        del note['object']['cc']

        resp = self.post('/ap/sharedInbox', json=note)
        self.assertEqual(204, resp.status_code)

        self.assert_object('http://mas.to/note/id',
                           source_protocol='activitypub',
                           users=[user.key],
                           deleted=False,
                           ignore=['our_as1'])

    def test_inbox_bad_id(self, *_):
        user = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        for id in 'x y', 'mas.to', 'https:///':
            with self.subTest(id=id):
                resp = self.post('/ap/sharedInbox', json={**NOTE, 'id': id})
                self.assertEqual(400, resp.status_code)
                self.assertIsNone(Object.get_by_id('mas.to'))

    def test_inbox_bad_actor_id(self, mock_head, mock_get, mock_post):
        for id in '', 'x y', 'mas.to', 'https:///':
            with self.subTest(id=id):
                got = self.post('/user.com/inbox', json={
                    'type': 'Move',
                    'actor': id,
                    'object': 'http://inst/obj',
                })
                self.assertEqual(400, got.status_code)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_inbox_create_receive_task(self, mock_create_task, *mocks):
        common.RUN_TASKS_INLINE = False

        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        resp = self.post('/ap/sharedInbox', json=NOTE)
        self.assert_task(mock_create_task, 'receive', id='http://mas.to/note/as2',
                         source_protocol='activitypub', as2=NOTE,
                         authed_as=ACTOR['id'],
                         received_at='2022-01-02T03:04:05+00:00')

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_inbox_delete_receive_task(self, mock_create_task, *mocks):
        common.RUN_TASKS_INLINE = False

        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        resp = self.post('/ap/sharedInbox', json=DELETE)
        delayed_eta = util.to_utc_timestamp(NOW) + DELETE_TASK_DELAY.total_seconds()
        self.assert_task(mock_create_task, 'receive', id=DELETE['id'],
                         source_protocol='activitypub', as2=DELETE,
                         authed_as=ACTOR['id'],
                         received_at='2022-01-02T03:04:05+00:00',
                         eta_seconds=delayed_eta)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_inbox_undo_follow_receive_task_no_delay(self, mock_create_task, *mocks):
        common.RUN_TASKS_INLINE = False

        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        resp = self.post('/ap/sharedInbox', json=UNDO_FOLLOW_WRAPPED)
        self.assert_task(mock_create_task, 'receive', id=UNDO_FOLLOW_WRAPPED['id'],
                         source_protocol='activitypub', as2=UNDO_FOLLOW_WRAPPED,
                         authed_as=ACTOR['id'],
                         received_at='2022-01-02T03:04:05+00:00')

    def test_inbox_reply_object(self, mock_head, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(REPLY_OBJECT),
                           type='comment',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           deleted=False,
                           )

    def test_inbox_reply_object_wrapped(self, mock_head, mock_get, mock_post):
        self._test_inbox_reply(REPLY_OBJECT_WRAPPED, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(REPLY_OBJECT),
                           type='comment',
                           notify=[self.user.key],
                           users=[self.swentel_key],
                           deleted=False,
                           )

    def test_inbox_reply_create_activity(self, mock_head, mock_get, mock_post):
        create = {
            **REPLY,
            'actor': 'https://mas.to/users/swentel',
        }
        self._test_inbox_reply(create, mock_head, mock_get, mock_post)

        self.assert_object('http://mas.to/reply/id',
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(REPLY_OBJECT),
                           type='comment',
                           notify=[self.user.key],
                           users=[self.swentel_key],
                           deleted=False,
                           )

    def _test_inbox_reply(self, reply, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/post')
        mock_get.side_effect = (
            (list(mock_get.side_effect) if mock_get.side_effect else [
                # source actor, webfinger
                self.as2_resp(ACTOR),
                self.as2_resp(ACTOR),
                requests_response(status=404),
            ]) + [
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

    def test_inbox_reply_protocol_subdomain(self, mock_head, mock_get, mock_post):
        mock_get.return_value = self.as2_resp(ACTOR)

        Fake.fetchable['fake:post'] = as2.to_as1({
            **NOTE_OBJECT,
            'id': 'fake:post',
        })
        reply = {
            **REPLY_OBJECT,
            'id': 'http://mas.to/reply',
            'inReplyTo': 'fake:post',
        }

        got = self.post('/ap/fake:user/inbox', json=reply,
                        base_url='https://fa.brid.gy/')
        self.assertEqual(202, got.status_code)
        self.assert_equals(
            [('fake:post:target', {
                'objectType': 'activity',
                'verb': 'post',
                'id': 'http://mas.to/reply#bridgy-fed-create',
                'published': '2022-01-02T03:04:05+00:00',
                'object': as2.to_as1(reply),
                'actor': as2.to_as1(ACTOR),
            })], Fake.sent)

    def test_inbox_reply_to_self_domain(self, mock_head, mock_get, mock_post):
        mock_get.return_value = WEBMENTION_DISCOVERY

        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        got = self.post('/user.com/inbox', json={
            **REPLY_OBJECT,
            'inReplyTo': 'http://localhost/user.com',
        })
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        self.assert_req(
            mock_post,
            'https://user.com/webmention',
            headers={'Accept': '*/*'},
            allow_redirects=False,
            data={
                'source': f'https://ap.brid.gy/convert/web/{REPLY_OBJECT["id"]}%23bridgy-fed-create',
                'target': 'https://user.com/',
            },
        )

    def test_inbox_reply_to_in_blocklist(self, mock_head, mock_get, mock_post):
        mock_get.return_value = HTML
        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        got = self.post('/user.com/inbox', json={
            **REPLY_OBJECT,
            'inReplyTo': 'https://twitter.com/foo',
        })
        self.assertEqual(204, got.status_code, got.get_data(as_text=True))
        mock_post.assert_not_called()

    def test_individual_inbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/user.com/inbox', *mocks)

    def test_ap_sharedInbox_create_obj(self, *mocks):
        self._test_inbox_create_obj('/ap/sharedInbox', *mocks)

    def _test_inbox_create_obj(self, path, mock_head, mock_get, mock_post):
        author = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        Follower.get_or_create(to=author, from_=self.user)
        bar = self.make_user('fake:bar', cls=Fake, obj_id='fake:bar')
        Follower.get_or_create(to=self.make_user('https://other/person',
                                                 cls=ActivityPub),
                               from_=bar)
        baz = self.make_user('fake:baz', cls=Fake, obj_id='fake:baz')
        Follower.get_or_create(to=author, from_=baz)
        baj = self.make_user('fake:baj', cls=Fake, obj_id='fake:baj')
        Follower.get_or_create(to=author, from_=baj, status='inactive')

        mock_head.return_value = requests_response(url='http://target')
        mock_get.side_effect = [  # source actor, webfinger
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
        ]
        mock_post.return_value = requests_response()

        got = self.post(path, json=NOTE)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        expected_obj = {
            **as2.to_as1(NOTE_OBJECT),
            'author': {'id': ACTOR['id']},
            'cc': [
                {'id': 'https://mas.to/author/followers'},
                {'id': 'https://masto.foo/@other'},
                {'id': 'target'},
            ],
        }
        self.assert_object(
            NOTE_OBJECT['id'],
            source_protocol='activitypub',
            our_as1=expected_obj,
            type='note',
            copies=[Target(protocol='fake', uri='fake:o:ap:http://mas.to/note/id')],
            users=[ndb.Key(ActivityPub, ACTOR['id'])],
            feed=[self.user.key],
            deleted=False,
        )

    def test_repost_of_indieweb(self, mock_head, mock_get, mock_post):
        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
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

        expected_as1 = as2.to_as1({
            **REPOST,
            'actor': ACTOR,
            'object': {
                'id': 'https://user.com/orig',
                'type': 'Note',
                'content': '☕ just a normal post',
            },
        })
        self.assert_object(REPOST_FULL['id'],
                           source_protocol='activitypub',
                           our_as1=expected_as1,
                           users=[self.swentel_key],
                           type='share',
                           )
    def test_shared_inbox_repost_of_fediverse(self, mock_head, mock_get, mock_post):
        to = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR,
                            enabled_protocols=['fake'])
        Follower.get_or_create(to=to, from_=self.user)
        baz = self.make_user('fake:baz', cls=Fake, obj_id='fake:baz',
                             enabled_protocols=['activitypub'])
        Follower.get_or_create(to=to, from_=baz)
        baj = self.make_user('fake:baj', cls=Fake, obj_id='fake:baj',
                             enabled_protocols=['activitypub'])
        Follower.get_or_create(to=to, from_=baj, status='inactive')

        obj = self.store_object(id=NOTE_OBJECT['id'], source_protocol='activitypub',
                                copies=[Target(protocol='fake', uri='fake:o:ap:note')])
        mock_get.return_value = self.as2_resp(NOTE_OBJECT)

        got = self.post('/ap/sharedInbox', json=REPOST)
        self.assertEqual(202, got.status_code, got.get_data(as_text=True))

        mock_post.assert_not_called()  # no webmention

        copy = Target(protocol='fake',
                      uri='fake:o:ap:https://mas.to/users/alice/statuses/654/activity')
        self.assert_object(REPOST['id'],
                           source_protocol='activitypub',
                           as2=REPOST,
                           copies=[copy],
                           users=[self.swentel_key],
                           feed=[self.user.key],
                           type='share',
                           ignore=['our_as1'],
                           )

    def test_inbox_no_user(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            requests_response(status=404),
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
                           our_as1=as2.to_as1({
                               **LIKE_WITH_ACTOR,
                               'object': 'http://nope.com/post',
                           }),
                           type='like',
                           notify=[self.user.key],
                           users=[self.masto_actor_key],
                           )

    def test_inbox_private(self, *mocks):
        self._test_inbox_with_to_ignored(['https://mas.to/author/followers'], *mocks)

    def test_inbox_unlisted(self, *mocks):
        self._test_inbox_with_to_ignored(['@unlisted'], *mocks)

    def test_inbox_dm(self, *mocks):
        self._test_inbox_with_to_ignored(['http://localhost/web/user.com'], *mocks)

    def _test_inbox_with_to_ignored(self, to, mock_head, mock_get, mock_post):
        author = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        Follower.get_or_create(to=author, from_=self.user)
        orig_obj_count = Object.query().count()

        mock_head.return_value = requests_response(url='http://target')

        not_public = copy.deepcopy(NOTE)
        not_public['object']['to'] = to

        got = self.post('/user.com/inbox', json=not_public)
        self.assertEqual(204, got.status_code, got.get_data(as_text=True))

        self.assertEqual(orig_obj_count, Object.query().count())

    def test_follow_bot_user_enables_protocol(self, _, mock_get, __):
        # bot user
        self.make_user('efake.brid.gy', cls=Web, ap_subdomain='efake')

        user = self.make_user('https://mas.to/users/swentel', cls=ActivityPub,
                              obj_as2=ACTOR)
        self.assertFalse(user.is_enabled(ExplicitFake))

        # actor gets reloaded
        mock_get.return_value = self.as2_resp(ACTOR)

        id = 'https://inst/follow'
        _, code = ActivityPub.receive(Object(id=id, as2={
            'type': 'Follow',
            'id': id,
            'actor': 'https://mas.to/users/swentel',
            'object': 'https://efake.brid.gy/efake.brid.gy',
        }), authed_as='https://mas.to/users/swentel')
        self.assertEqual(204, code)

        self.assertEqual(['https://mas.to/users/swentel'],
                         ExplicitFake.created_for)
        user = user.key.get()
        self.assertTrue(user.is_enabled(ExplicitFake))

    def test_inbox_dm_yes_to_bot_user_enables_protocol(self, *mocks):
        # bot user
        self.make_user('efake.brid.gy', cls=Web)

        user = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        self.assertFalse(user.is_enabled(ExplicitFake))

        got = self.post('/ap/sharedInbox', json={
            'type': 'Create',
            'id': 'https://mas.to/dm#create',
            'to': ['https://efake.brid.gy/efake.brid.gy'],
            'actor': ACTOR['id'],
            'object': {
                'type': 'Note',
                'id': 'https://mas.to/dm',
                'attributedTo': ACTOR['id'],
                'to': ['https://efake.brid.gy/efake.brid.gy'],
                'content': 'yes',
            },
        })
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        user = user.key.get()
        self.assertTrue(user.is_enabled(ExplicitFake))

    def test_inbox_actor_blocklisted(self, mock_head, mock_get, mock_post):
        got = self.post('/ap/sharedInbox', json={
            'type': 'Delete',
            'id': 'http://inst/foo#delete',
            'actor': 'http://localhost:3000/foo',
            'object': 'http://inst/foo',
        })
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        self.assertIsNone(Object.get_by_id('http://localhost:3000/foo'))
        self.assertIsNone(Object.get_by_id('http://inst/foo#delete'))
        self.assertIsNone(Object.get_by_id('http://inst/foo'))

    def test_inbox_like(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/post')
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            requests_response(status=404),
            requests_response(test_web.NOTE_HTML),
            requests_response(test_web.NOTE_HTML),
            WEBMENTION_DISCOVERY,
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', json=LIKE)
        self.assertEqual(202, got.status_code)

        self.assertIn(self.as2_req('https://mas.to/me'), mock_get.mock_calls)
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
                           our_as1=as2.to_as1(LIKE_WITH_ACTOR),
                           type='like',
                           )

    def test_inbox_like_creates_user(self, mock_get, *_):
        mock_get.return_value = self.as2_resp(LIKE_ACTOR)
        self.test_inbox_like()
        self.assert_user(ActivityPub, 'https://mas.to/me', obj_as2=LIKE_ACTOR)

    def test_inbox_like_no_object_error(self, *_):
        user = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        got = self.post('/ap/sharedInbox', json={
            'id': 'https://mas.to/like',
            'type': 'Like',
            'actor': ACTOR['id'],
            'object': None,
        })
        self.assertEqual(299, got.status_code)

    def test_inbox_follow_accept_with_id(self, *mocks):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT, *mocks)

        follow = {
            **FOLLOW_WITH_ACTOR,
            'url': 'https://mas.to/users/swentel#followed-user.com',
            'object': 'user.com'
        }
        self.assert_object('https://mas.to/follow',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(follow),
                           type='follow',
                           )

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
        follow['object']['id'] = 'user.com'
        self.assert_object('https://mas.to/follow',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(follow),
                           type='follow',
                           )

    def test_inbox_follow_accept_inner_follow_to(self, *mocks):
        follow = {
            'type': 'Follow',
            'id': 'https://mas.to/follow',
            'actor': 'https://mas.to/users/swentel',
            'object': 'http://localhost/user.com',
            'to': ['http://localhost/user.com'],
        }

        accept = {
            '@context': as2.CONTEXT,
            'type': 'Accept',
            'id': 'https://localhost/r/user.com/followers#accept-https://mas.to/follow',
            'actor': 'http://localhost/user.com',
            'object': {
                'type': 'Follow',
                'id': 'https://mas.to/follow',
                'actor': 'https://mas.to/users/swentel',
                'object': 'http://localhost/user.com',
                'url': 'https://mas.to/users/swentel#followed-user.com',
                'to': ['http://localhost/user.com']
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public']
        }
        self._test_inbox_follow_accept(follow, accept, *mocks)

    def test_inbox_follow_accept_shared_inbox(self, mock_head, mock_get, mock_post):
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT,
                                       mock_head, mock_get, mock_post,
                                       inbox_path='/ap/sharedInbox')

        url = 'https://mas.to/users/swentel#followed-user.com'
        follow = {
            **FOLLOW_WITH_ACTOR,
            'url': url,
            'object': 'user.com',
        }
        self.assert_object('https://mas.to/follow',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(follow),
                           type='follow',
                           )

    def test_inbox_follow_accept_webmention_fails(self, mock_head, mock_get,
                                                  mock_post):
        mock_post.side_effect = [
            requests_response(),         # AP Accept
            requests.ConnectionError(),  # webmention
        ]
        self._test_inbox_follow_accept(FOLLOW_WRAPPED, ACCEPT,
                                       mock_head, mock_get, mock_post)

        url = 'https://mas.to/users/swentel#followed-user.com'
        follow = {
            **FOLLOW_WITH_ACTOR,
            'url': url,
            'object': 'user.com',
        }
        self.assert_object('https://mas.to/follow',
                           users=[self.swentel_key],
                           notify=[self.user.key],
                           source_protocol='activitypub',
                           our_as1=as2.to_as1(follow),
                           type='follow',
                           )

    def _test_inbox_follow_accept(self, follow_as2, accept_as2, mock_head,
                                  mock_get, mock_post, inbox_path='/user.com/inbox'):
        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
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
            'source': 'https://ap.brid.gy/convert/web/https://mas.to/follow',
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

        self.assert_user(ActivityPub, 'https://mas.to/users/swentel', obj_as2=ACTOR)
        self.assert_user(Web, 'user.com', last_webmention_in=NOW,
                         has_hcard=True, has_redirects=True)

    def test_inbox_follow_use_instead_strip_www(self, mock_head, mock_get, mock_post):
        self.make_user('www.user.com', cls=Web, use_instead=self.user.key)

        mock_head.return_value = requests_response(url='https://www.user.com/')
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
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

    def test_inbox_follow_web_brid_gy_subdomain(self, mock_head, mock_get, mock_post):
        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
            # target user
            test_web.ACTOR_HTML_RESP,
            # target post webmention discovery
            requests_response('<html></html>'),
        ]
        mock_post.return_value = requests_response()

        got = self.post('/user.com/inbox', base_url='https://web.brid.gy/', json={
            **FOLLOW_WRAPPED,
            'object': 'https://web.brid.gy/user.com',
        })
        self.assertEqual(202, got.status_code)

        # check that AP Accept uses web.brid.gy, not fed.brid.gy
        args, kwargs = mock_post.call_args_list[0]
        self.assert_equals(('http://mas.to/inbox',), args)
        self.assert_equals({
            'type': 'Accept',
            'id': 'https://localhost/r/user.com/followers#accept-https://mas.to/follow',
            'actor': 'http://localhost/user.com',
            'object': {
                'type': 'Follow',
                'id': 'https://mas.to/follow',
                'object': 'http://localhost/user.com',
                'actor': 'https://mas.to/users/swentel',
                'url': 'https://mas.to/users/swentel#followed-user.com',
            },
        }, json_loads(kwargs['data']), ignore=['to', '@context'])

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
            from_=self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR),
            status='inactive')

        mock_head.return_value = requests_response(url='https://user.com/')
        mock_get.side_effect = [
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

        follower_key = ActivityPub.get_or_create(ACTOR['id'])
        follower = Follower.get_or_create(to=self.user, from_=follower_key,
                                          status='inactive')

        undo_follow = copy.deepcopy(UNDO_FOLLOW_WRAPPED)
        undo_follow['object']['object'] = {'id': undo_follow['object']['object']}
        got = self.post('/user.com/inbox', json=undo_follow)
        self.assertEqual(202, got.status_code)
        self.assertEqual('inactive', follower.key.get().status)

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_inbox_unsupported_type(self, mock_create_task, *_):
        got = self.post('/user.com/inbox', json={
            '@context': as2.CONTEXT,
            'id': 'https://xoxo.zone/users/aaronpk#follows/40',
            'type': 'Arrive',
            'actor': ACTOR['id'],
            'object': 'http://mas.to/place',
        })
        self.assertEqual(204, got.status_code)
        mock_create_task.assert_not_called()

    def test_inbox_bad_object_url(self, mock_head, mock_get, mock_post):
        # https://console.cloud.google.com/errors/detail/CMKn7tqbq-GIRA;time=P30D?project=bridgy-federated
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
            requests_response(status=404),
            requests_response(status=404),
        ]

        id = 'https://mas.to/users/tmichellemoore#likes/56486252'
        bad_url = 'http://localhost/r/Testing \u2013 Brid.gy \u2013 Post to Mastodon 3'
        bad = {
            '@context': as2.CONTEXT,
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
                           )
        self.assertIsNone(Object.get_by_id(bad_url))

    def test_inbox_verify_sig_fetch_key(self, _, mock_get, __):
        # actor with a public key
        mock_get.return_value = self.as2_resp(self.key_id_obj.as2)

        # valid signature
        note = {**NOTE, 'actor': 'http://mas.to/key/id'}
        body = json_dumps(note)
        headers = sign('/ap/sharedInbox', body, key_id='http://mas.to/key/id')
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(204, resp.status_code, resp.get_data(as_text=True))
        mock_get.assert_has_calls((
            self.as2_req('http://mas.to/key/id'),
        ))

    def test_inbox_verify_sig_fetch_key_fails(self, _, mock_get, __):
        # https://console.cloud.google.com/errors/detail/COLzgISI47vpMg?project=bridgy-federated
        # bad keyId, requests would raise InvalidURL
        mock_get.side_effect = InvalidURL('foo')

        body = json_dumps(NOTE)
        headers = sign('/ap/sharedInbox', body,
                       key_id='https://ÐºÑÑÑ ÑÐ¸Ñ.Ð¾Ð½Ð»Ð°Ð¹Ð½/oleg')
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))

    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_stored_key(self, *_):
        body = json_dumps({**NOTE, 'actor': 'http://mas.to/key/id'})
        headers = sign('/ap/sharedInbox', body, key_id='http://mas.to/key/id')

        # valid signature, stored Object has no key
        self.key_id_obj.as2 = {**ACTOR, 'publicKey': {}}
        self.key_id_obj.put()
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))

    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_stored_key_our_as1(self, *_):
        # valid signature, key id's Object has our_as1 instead of as2
        self.make_user(id=ACTOR['id'], cls=ActivityPub, obj_as1=as2.to_as1(ACTOR))

        body = json_dumps(NOTE)
        headers = sign('/ap/sharedInbox', body, key_id=ACTOR['id'])
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(204, resp.status_code, resp.get_data(as_text=True))

    @patch('common.logger.info', side_effect=logging.info)
    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_no_keyId(self, mock_common_log, *_):
        body = json_dumps(NOTE)
        headers = sign('/ap/sharedInbox', body, key_id='PLACEHOLDER')

        resp = self.client.post('/ap/sharedInbox', data=body, headers={
            **headers,
            'signature': headers['signature'].replace('keyId="PLACEHOLDER",', ''),
        })
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'sig missing keyId'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: sig missing keyId',
                                        exc_info=None)

    @patch('common.logger.info', side_effect=logging.info)
    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_content_changed(self, mock_common_log, *_):
        self.key_id_obj.put()
        headers = sign('/ap/sharedInbox', json_dumps(NOTE),
                       key_id='http://mas.to/key/id')

        resp = self.client.post('/ap/sharedInbox', json={**NOTE, 'content': 'z'},
                                headers=headers)
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'Invalid Digest'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: Invalid Digest', exc_info=None)

    @patch('common.logger.info', side_effect=logging.info)
    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_header_changed(self, mock_common_log, *_):
        self.key_id_obj.put()
        body = json_dumps({**NOTE, 'actor': 'http://mas.to/key/id'})
        headers = sign('/ap/sharedInbox', body, key_id='http://mas.to/key/id')

        resp = self.client.post('/ap/sharedInbox', data=body,
                                headers={**headers, 'Date': 'X'})
        self.assertEqual(401, resp.status_code)
        self.assertEqual({'error': 'sig failed'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: sig failed', exc_info=None)

    @patch('common.logger.info', side_effect=logging.info)
    @patch('oauth_dropins.webutil.appengine_info.DEBUG', False)
    def test_inbox_verify_sig_missing_sig(self, mock_common_log, _, __, ___):
        resp = self.client.post('/ap/sharedInbox', json=NOTE)
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'error': 'No HTTP Signature'}, resp.json)
        mock_common_log.assert_any_call('Returning 401: No HTTP Signature',
                                        exc_info=None)

    def test_inbox_verify_http_signature_follow_owner(self, _, __, ___):
        self.user.obj.our_as1 = None
        self.user.obj.as2 = ACTOR_BASE
        self.user.obj.put()
        actor = self.user.obj.key.id()

        self.assertNotEqual(self.user.key.id(), self.key_id_obj.key.id())
        self.key_id_obj.as2['publicKey']['owner'] = actor
        self.key_id_obj.put()

        body = json_dumps(NOTE)
        headers = sign('/ap/sharedInbox', body, key_id='http://mas.to/key/id')

        with app.test_request_context('/ap/sharedInbox', method='POST',
                                      data=body, headers=headers):
            self.assertEqual(actor, ActivityPub.verify_signature(None))

    def test_inbox_ignore_forward_with_ld_sig(self, _, __, ___):
        self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        got = self.client.post('/user.com/inbox', json={
            'type': 'Create',
            'id': 'http://mas.to/like',
            'actor': 'http://mas.to/other',
            'object': {'id': 'http://mas.to/post'},
            'signature': {
                'type': 'RsaSignature2017',
                'creator': 'http://mas.to/other#main-key',
                'created': '2024-05-20T01:52:09Z',
                'signatureValue': '...',
            },
        })

        self.assertEqual(202, got.status_code, got.text)
        self.assertIn('Ignoring LD Signature', got.text)
        self.assertIsNone(Object.get_by_id('http://inst/post'))
        self.assertIsNone(memcache.memcache.get('receive-http://inst/post'))


    def test_inbox_http_sig_is_not_actor_author(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            self.as2_resp({**ACTOR, 'id': 'https://mas.to/alice'}),
            self.as2_resp(ACTOR),  # swentel
        ]

        body = json_dumps({
            **NOTE,
            'actor': 'https://mas.to/alice',
        })
        headers = sign('/ap/sharedInbox', body, key_id=ACTOR['id'])
        got = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(299, got.status_code, got.get_data(as_text=True))

    def test_inbox_NO_AUTH_DOMAINS(self, *_):
        id = 'https://a.gup.pe/a-group'
        self.store_object(id=id, as2={
            'publicKey': {
                'owner': id,
                'publicKeyPem': self.user.public_pem().decode(),
            }})

        body = json_dumps(NOTE)
        headers = sign('/ap/sharedInbox', body, key_id=id)

        with self.assertLogs() as logs:
            got = self.client.post('/ap/sharedInbox', data=body, headers=headers)

        self.assertEqual(204, got.status_code)
        self.assertIn("we don't know how to authorize a.gup.pe activities",
                      ' '.join(logs.output))

    def test_delete_actor(self, *mocks):
        actor = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)
        follower = Follower.get_or_create(to=self.user, from_=actor)
        followee = Follower.get_or_create(to=actor, from_=Fake(id='fake:user'))

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
        mock_get.return_value = requests_response(status=410)

        got = self.post('/ap/sharedInbox', json=DELETE)
        self.assertEqual(202, got.status_code)
        self.assertTrue(Object.get_by_id(DELETE['object']).deleted)

    def test_delete_actor_empty_deleted_object(self, _, mock_get, ___):
        actor = self.make_user(DELETE['actor'], cls=ActivityPub)
        actor.obj.deleted=True
        actor.obj.put()

        got = self.post('/ap/sharedInbox', json=DELETE)
        self.assertEqual(202, got.status_code)
        mock_get.assert_not_called()

    def test_delete_note(self, _, mock_get, ___):
        self.make_user('https://mas.to/users/swentel', cls=ActivityPub, obj_as2=ACTOR)
        obj = Object(id='http://mas.to/obj', as2=NOTE, source_protocol='activitypub')
        obj.put()

        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
        ]

        delete = {
            **DELETE,
            'object': 'http://mas.to/obj',
        }
        resp = self.post('/ap/sharedInbox', json=delete)
        self.assertEqual(204, resp.status_code)
        self.assertTrue(obj.key.get().deleted)

    def test_update_note(self, *mocks):
        Object(id='https://mas.to/note', as2={}).put()
        self._test_update(*mocks)

    def test_update_unknown(self, *mocks):
        self._test_update(*mocks)

    def _test_update(self, _, mock_get, ___):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            requests_response(status=404),
        ]

        resp = self.post('/ap/sharedInbox', json=UPDATE_NOTE)
        self.assertEqual(204, resp.status_code)

        note_as1 = as2.to_as1({
            **UPDATE_NOTE['object'],
            'author': {'id': 'https://mas.to/users/swentel'},
        })
        self.assert_object('https://mas.to/note',
                           type='note',
                           our_as1=note_as1,
                           users=[self.swentel_key],
                           source_protocol='activitypub',
                           deleted=False,
                           )

    def test_inbox_webmention_discovery_connection_fails(self, mock_head,
                                                         mock_get, mock_post):
        mock_get.side_effect = [
            # source actor, webfinger
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            requests_response(status=404),
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
            # source actor, webfinger
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            self.as2_resp(LIKE_WITH_ACTOR['actor']),
            requests_response(status=404),
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
                           our_as1=as2.to_as1(LIKE_WITH_ACTOR),
                           type='like',
                           )

    def test_inbox_id_already_seen(self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            HTML,
        ]

        obj_key = Object(id=FOLLOW_WRAPPED['id'], as2={}).put()

        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(202, got.status_code)
        self.assertEqual(1, Follower.query().count())

        # second time should use in memory cache
        obj_key.delete()
        got = self.post('/user.com/inbox', json=FOLLOW_WRAPPED)
        self.assertEqual(204, got.status_code)
        self.assertEqual(1, Follower.query().count())

    @patch('activitypub.PROTOCOLS', new={'fake': Fake, 'other': OtherFake})
    def test_inbox_server_actor_create_with_propagate(
            self, mock_head, mock_get, mock_post):
        actor = self.as2_resp(add_key({
            'id': 'https://mas.to/actor',
            'type': 'Person',
        }))

        mock_get.side_effect = [
            actor,
            actor,
            self.as2_resp(NOTE),
        ]

        got = self.post('/user.com/inbox', json={
            '@context': as2.CONTEXT,
            'id': 'http://mas.to/like',
            'type': 'Like',
            'object': 'https://mas.to/note/as2',
            'actor': 'https://mas.to/actor',
        })
        self.assertEqual(204, got.status_code)

        actor = ActivityPub.get_by_id('https://mas.to/actor')
        self.assertCountEqual(['other', 'fake'], actor.enabled_protocols)

    @patch('activitypub.PROTOCOLS', new={'fake': Fake, 'other': OtherFake})
    def test_inbox_existing_server_actor_adds_enabled_protocols(
            self, mock_head, mock_get, mock_post):
        server_actor = self.make_user('https://mas.to/actor', cls=ActivityPub,
                                      enabled_protocols=['ui'], obj_as2=add_key({
                                          'id': 'https://mas.to/actor',
                                          'type': 'Person',
                                      }))

        mock_get.return_value = self.as2_resp(NOTE)
        got = self.post('/user.com/inbox', json={
            '@context': as2.CONTEXT,
            'id': 'http://mas.to/like',
            'type': 'Like',
            'object': 'https://mas.to/note/as2',
            'actor': 'https://mas.to/actor',
        })
        self.assertEqual(204, got.status_code)

        actor = ActivityPub.get_by_id('https://mas.to/actor')
        self.assertCountEqual(['ui', 'fake', 'other'], actor.enabled_protocols)

    # https://github.com/snarfed/bridgy-fed/security/advisories/GHSA-37r7-jqmr-3472
    def test_inbox_actor_auth_check_activity_id_different_domain(
            self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
            self.as2_resp(NOTE),
        ]

        with self.assertLogs() as logs:
            got = self.post('/user.com/inbox', json={
                'id': 'http://no.pe/like',
                'type': 'Like',
                'actor': 'https://mas.to/users/swentel',
                'object': 'https://mas.to/note/as2',
            })

        self.assertEqual(403, got.status_code)
        self.assertIn('Auth: actor and activity on different domains',
                      ' '.join(logs.output))

    # https://github.com/snarfed/bridgy-fed/security/advisories/GHSA-37r7-jqmr-3472
    def test_inbox_actor_auth_check_object_id_different_domain(
            self, mock_head, mock_get, mock_post):
        mock_get.side_effect = [
            self.as2_resp(ACTOR),
            self.as2_resp(ACTOR),
        ]

        with self.assertLogs() as logs:
            got = self.post('/user.com/inbox', json={
                'id': 'http://mas.to/create',
                'type': 'Create',
                'actor': 'https://mas.to/users/swentel',
                'object': {
                    **NOTE_OBJECT,
                    'id': 'https://no.pe/note',
                },
            })

        self.assertEqual(403, got.status_code)
        self.assertIn('Auth: actor and object on different domains',
                      ' '.join(logs.output))

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
            to=self.make_user('https://other/person', cls=ActivityPub),
            from_=self.user)
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('http://baz', cls=ActivityPub, obj_as2=ACTOR),
            follow=follow)
        Follower.get_or_create(
            to=self.user,
            from_=self.make_user('fake:baj', cls=Fake,
                                 obj_as2={**ACTOR, 'id': 'fake:baj'}),
            status='inactive')

        self.user.enabled_protocols.append('efake')
        self.user.put()
        Follower.get_or_create(  # not enabled for activitypub
            to=self.user,
            from_=self.make_user('efake:biff', cls=ExplicitFake,
                                 obj_as2={**ACTOR, 'id': 'efake:biff'}))

    def test_followers_collection_fake(self, *_):
        self.make_user('fake:foo', cls=Fake, enabled_protocols=['activitypub'])

        resp = self.client.get('/ap/fake:foo/followers',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://fa.brid.gy/ap/fake:foo/followers',
            'type': 'Collection',
            'summary': "fake:foo's followers",
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://fa.brid.gy/ap/fake:foo/followers',
                'items': [],
            },
        }, resp.json)

    def test_followers_collection(self, *_):
        self.store_followers()

        resp = self.client.get('/user.com/followers')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': 'http://localhost/user.com/followers',
            'type': 'Collection',
            'summary': "user.com's followers",
            'totalItems': 3,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'http://localhost/user.com/followers',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    def test_followers_collection_protocol_bot_user(self, *_):
        self.user = self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky')
        self.store_followers()

        resp = self.client.get('/bsky.brid.gy/followers',
                               base_url='https://bsky.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': 'https://bsky.brid.gy/bsky.brid.gy/followers',
            'type': 'Collection',
            'summary': "bsky.brid.gy's followers",
            'totalItems': 3,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://bsky.brid.gy/bsky.brid.gy/followers',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('models.PAGE_SIZE', 2)
    def test_followers_collection_page(self, *_):
        self.store_followers()
        before = (datetime.now(UTC) + timedelta(seconds=1)
                  ).replace(tzinfo=None).isoformat()
        next = Follower.query(Follower.from_ == ActivityPub(id='http://baz').key,
                              Follower.to == self.user.key,
                              ).get().updated.isoformat()

        resp = self.client.get(f'/user.com/followers?before={before}')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': f'http://localhost/user.com/followers?before={before}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/user.com/followers',
            'next': f'http://localhost/user.com/followers?before={next}',
            'prev': f'http://localhost/user.com/followers?after={before}',
            'items': [ACTOR],
        }, resp.json)

    def test_followers_collection_page_protocol_bot_user(self, *_):
        self.user = self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky')
        self.store_followers()

        before = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        resp = self.client.get(f'/bsky.brid.gy/followers?before={before}',
                               base_url='https://bsky.brid.gy')
        self.assertEqual(200, resp.status_code)

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
            from_=self.make_user('https://other/person', cls=ActivityPub))
        Follower.get_or_create(
            to=self.make_user('http://baz', cls=ActivityPub, obj_as2=ACTOR),
            from_=self.user, follow=follow)
        Follower.get_or_create(
            to=self.make_user('http://ba/j', cls=ActivityPub),
            from_=self.user,
            status='inactive')

    def test_following_collection(self, *_):
        self.store_following()

        resp = self.client.get('/user.com/following')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
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

    def test_following_collection_protocol_bot_user(self, *_):
        self.user = self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky')
        self.store_following()

        resp = self.client.get('/bsky.brid.gy/following',
                               base_url='https://bsky.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': 'https://bsky.brid.gy/bsky.brid.gy/following',
            'type': 'Collection',
            'summary': "bsky.brid.gy's following",
            'totalItems': 2,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://bsky.brid.gy/bsky.brid.gy/following',
                'items': [ACTOR, ACTOR],
            },
        }, resp.json)

    @patch('models.PAGE_SIZE', 1)
    def test_following_collection_page(self, *_):
        self.store_following()
        after = datetime(1900, 1, 1).isoformat()
        prev = Follower.query(Follower.to == ActivityPub(id='http://bar').key,
                              Follower.from_ == self.user.key,
                              ).get().updated.isoformat()

        resp = self.client.get(f'/user.com/following?after={after}')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': f'http://localhost/user.com/following?after={after}',
            'type': 'CollectionPage',
            'partOf': 'http://localhost/user.com/following',
            'prev': f'http://localhost/user.com/following?after={prev}',
            'next': f'http://localhost/user.com/following?before={after}',
            'items': [ACTOR],
        }, resp.json)

    def test_following_collection_page_protocol_bot_user(self, *_):
        self.user = self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky')
        self.store_following()

        before = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        resp = self.client.get(f'/bsky.brid.gy/following?before={before}',
                               base_url='https://bsky.brid.gy')
        self.assertEqual(200, resp.status_code)

    def test_following_collection_head(self, *_):
        resp = self.client.head(f'/user.com/following')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('', resp.get_data(as_text=True))

    def test_following_collection_opted_out(self, *_):
        self.user.obj.our_as1['summary'] = '#nobridge'
        self.user.obj.put()
        self.user.put()
        resp = self.client.get(f'/user.com/following', base_url='https://web.brid.gy')

    def test_following_collection_protocol_not_enabled(self, *_):
        resp = self.client.get(f'/ap/efake:alice/following',
                               base_url='https://efake.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_outbox_fake_empty(self, *_):
        self.make_user('fake:foo', cls=Fake, enabled_protocols=['activitypub'])
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

    def test_outbox_protocol_bot_user_empty(self, *_):
        self.make_user('bsky.brid.gy', cls=Web, ap_subdomain='bsky')
        resp = self.client.get(f'/bsky.brid.gy/outbox',
                               base_url='https://bsky.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': 'https://bsky.brid.gy/bsky.brid.gy/outbox',
            'summary': "bsky.brid.gy's outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': 'https://bsky.brid.gy/bsky.brid.gy/outbox',
                'items': [],
            },
        }, resp.json)

    def store_outbox_objects(self, user):
        for i, obj in enumerate([REPLY, MENTION, LIKE, DELETE]):
            self.store_object(id=obj['id'], users=[user.key], as2=obj)

    # TODO once we're serving outboxes again
    # https://github.com/snarfed/bridgy-fed/issues/1248
    @skip
    @patch('models.PAGE_SIZE', 2)
    def test_outbox_fake_objects(self, *_):
        user = self.make_user('fake:foo', cls=Fake)
        self.store_outbox_objects(user)

        resp = self.client.get(f'/ap/fake:foo/outbox',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)

        after = Object.get_by_id(LIKE['id']).updated.isoformat()
        self.assert_equals({
            '@context': as2.CONTEXT,
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

    # TODO once we're serving outboxes again
    # https://github.com/snarfed/bridgy-fed/issues/1248
    @skip
    @patch('models.PAGE_SIZE', 2)
    def test_outbox_fake_objects_page(self, *_):
        user = self.make_user('fake:foo', cls=Fake)
        self.store_outbox_objects(user)

        after = datetime(1900, 1, 1).isoformat()
        resp = self.client.get(f'/ap/fake:foo/outbox?after={after}',
                               base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)

        prev = Object.get_by_id(MENTION['id']).updated.isoformat()
        self.assert_equals({
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

    def test_outbox_opted_out(self, *_):
        self.user.obj.our_as1['summary'] = '#nobridge'
        self.user.obj.put()
        self.user.put()
        resp = self.client.get(f'/ap/user.com/outbox',
                               base_url='https://web.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_outbox_protocol_not_enabled(self, *_):
        resp = self.client.get(f'/ap/efake:alice/outbox',
                               base_url='https://efake.brid.gy')
        self.assertEqual(404, resp.status_code)

    # TODO: bring back once we figure out how to get Mastodon to support this and
    # Pleroma and Akkoma not to DDoS us
    # https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    @skip
    def test_featured_empty(self, *_):
        self.make_user('fake:foo', cls=Fake, enabled_protocols=['activitypub'])
        resp = self.client.get(f'/ap/fake:foo/featured', base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({
            '@context': as2.CONTEXT,
            'id': 'https://fa.brid.gy/ap/fake:foo/featured',
            'type': 'OrderedCollection',
            'totalItems': 0,
            'orderedItems': [],
        }, resp.json)

    # TODO: bring back once we figure out how to get Mastodon to support this and
    # Pleroma and Akkoma not to DDoS us
    # https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    @skip
    def test_featured_with_items(self, *_):
        Object(id='fake:a', our_as1={'objectType': 'note', 'foo': 'bar'}).put()
        Fake.fetchable = {'fake:b': {'objectType': 'article', 'baz': 'biff'}}

        actor_as1 = {
            'objectType': 'person',
            'featured': {
                'totalItems': 2,
                'items': ['fake:a', 'fake:b'],
            },
        }
        user = self.make_user('fake:foo', cls=Fake, enabled_protocols=['activitypub'],
                              obj_as1=actor_as1)

        resp = self.client.get(f'/ap/fake:foo/featured', base_url='https://fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assert_equals({
            '@context': as2.CONTEXT,
            'id': 'https://fa.brid.gy/ap/fake:foo/featured',
            'type': 'OrderedCollection',
            'totalItems': 2,
            'orderedItems': [{
                'type': 'Note',
                'id': 'https://fa.brid.gy/convert/ap/fake:a',
                'foo': 'bar',
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
            }, {
                'type': 'Article',
                'id': 'https://fa.brid.gy/convert/ap/fake:b',
                'baz': 'biff',
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
            }],
        }, resp.json, ignore=['@context'])

    def test_featured_activitypub_not_enabled(self, *_):
        obj = self.store_object(id='did:plc:user', raw={'foo': 'baz'})
        self.make_user('did:plc:user', cls=ATProto, obj_key=obj.key)
        got = self.client.get('/ap/did:plc:user/featured',
                              base_url='https://bsky.brid.gy/')
        self.assertEqual(404, got.status_code)

    def test_migrate_out(self, _, mock_get, mock_post):
        mock_get.return_value = self.as2_resp({
            **ACTOR,
            'alsoKnownAs': ['http://localhost/user.com'],
        })
        mock_post.return_value = requests_response()

        self.store_followers()
        ActivityPub.migrate_out(self.user, 'http://in.st/to')

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assert_equals(('http://mas.to/inbox',), args)
        self.assert_equals({
            'type': 'Move',
            'id': 'http://localhost/user.com#move-http://in.st/to',
            'actor': 'http://localhost/user.com',
            'object': 'http://localhost/user.com',
            'target': 'http://in.st/to',
        }, json_loads(kwargs['data']), ignore=['to', '@context'])

        obj_as1 = self.user.obj_key.get().as1
        self.assertEqual('http://in.st/to', obj_as1['movedTo'])
        self.assertIn('http://in.st/to', obj_as1['alsoKnownAs'])

    def test_migrate_out_bad_user_id(self, *_):
        with self.assertRaises(ValueError):
            ActivityPub.migrate_out(self.user, 'at://did:xyz')

    def test_migrate_out_user_not_enabled(self, *_):
        eve = self.make_user('efake:eve', cls=ExplicitFake)
        with self.assertRaises(ValueError):
            ActivityPub.migrate_out(eve, 'https://in.st/eve')

    def test_migrate_out_activitypub_user(self, *_):
        eve = self.make_user('http://ev/e', cls=ActivityPub)
        with self.assertRaises(ValueError):
            ActivityPub.migrate_out(eve, 'https://in.st/eve')

    def test_migrate_out_no_alias_in_to_actor(self, _, mock_get, __):
        mock_get.return_value = self.as2_resp(ACTOR)

        with self.assertRaises(ValueError):
            ActivityPub.migrate_out(self.user, 'http://in.st/to')

        mock_get.return_value = self.as2_resp({
            **ACTOR,
            'alsoKnownAs': ['oth', 'er'],
        })

        with self.assertRaises(ValueError):
            ActivityPub.migrate_out(self.user, 'http://in.st/to')

    def test_check_can_migrate_out(self, _, mock_get, mock_post):
        mock_get.return_value = self.as2_resp({
            **ACTOR,
            'alsoKnownAs': ['http://localhost/user.com'],
        })

        # shouldn't raise
        ActivityPub.check_can_migrate_out(self.user, 'http://in.st/to')

    def test_check_can_migrate_out_no_alias_in_to_actor(self, _, mock_get, __):
        mock_get.return_value = self.as2_resp(ACTOR)

        self.user.enabled_protocols = ['activitypub']
        with self.assertRaises(ValueError):
            ActivityPub.check_can_migrate_out(self.user, 'http://in.st/to')

        mock_get.return_value = self.as2_resp({
            **ACTOR,
            'alsoKnownAs': ['oth', 'er'],
        })

        with self.assertRaises(ValueError):
            ActivityPub.check_can_migrate_out(self.user, 'http://in.st/to')

    def test_migrate_in(self, _, mock_get, mock_post):
        ActivityPub._migrate_in(self.user, 'http://in.st/alice')
        user = self.user.key.get()
        # this doesn't actually test that we called put(). it still passes if we
        # remove that in _migrate_in. not sure why.
        self.assertEqual(['http://in.st/alice'],
                         ActivityPub.convert(user.obj_key.get())['alsoKnownAs'])


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

    def test_id_uri(self):
        self.assertEqual('http://inst/me', ActivityPub(id='http://inst/me').id_uri())

    def test_owns_id(self):
        self.assertIsNone(ActivityPub.owns_id('http://foo'))
        self.assertIsNone(ActivityPub.owns_id('https://bar/baz'))

        for id in ('', 'xy', 'x y', 'https:///', 'at://did:plc:foo/bar/123',
                   'e45fab982', 'https://twitter.com/foo', 'https://fed.brid.gy/foo',
                   'https://ap.brid.gy/foo'):
            with self.subTest(id=id):
                self.assertFalse(ActivityPub.owns_id(id))

    def test_owns_handle(self):
        for addr in ('user@instance', 'user@instance.com', 'user.com@instance.com',
                     'user@instance', 'user@sub.do.main'):
            with self.subTest(handle=addr):
                self.assertEqual(False, ActivityPub.owns_handle(addr))

            handle = '@' + addr
            with self.subTest(handle=handle):
                self.assertTrue(ActivityPub.owns_handle(handle))

        for handle in ('instance', 'instance.com', '@user', '@user.com',
                       'http://user.com', '@user@web.brid.gy', '@user@localhost'):
            with self.subTest(handle=handle):
                self.assertEqual(False, ActivityPub.owns_handle(handle))

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

    def test_handle_as_domain(self):
        self.assertEqual(
            'a.b.c', ActivityPub(webfinger_addr='@a@b.c').handle_as_domain)

        actor = Object(id='x', as2={
            'id': 'http://b.c/@a',
            'preferredUsername': 'z',
        })
        self.assertEqual('z.b.c', ActivityPub(obj_key=actor.put()).handle_as_domain)

    def test_bridged_web_url_for(self):
        self.assertIsNone(ActivityPub.bridged_web_url_for(
            ActivityPub(id='http://inst/user')))

        self.assertEqual('http://localhost/user.com',
                         ActivityPub.bridged_web_url_for(self.user))

        self.assertEqual('https://bsky.brid.gy/ap/did:plc:user',
                         ActivityPub.bridged_web_url_for(ATProto(id='did:plc:user')))

    def test_user_page_path_ignore_prefers_id(self):
        user = self.make_user(id='http://inst.com/@user', cls=ActivityPub)
        self.assertEqual('/ap/@user@inst.com', user.user_page_path(prefer_id=True))

    def test_check_supported(self):
        # sending DMs should be allowed
        dm = Object(our_as1={
            'objectType': 'note',
            'id': 'fake:dm',
            'actor': 'fake:alice',
            'to': ['http://inst/bob'],
            'content': 'hi',
        })

        with self.assertRaises(NoContent):
            ActivityPub.check_supported(dm, 'receive')

        ActivityPub.check_supported(dm, 'send')

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

    def test_postprocess_as2_object_image_bare_string_url(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'attachment': [{'url': 'http://r/foo'}],
            'image': 'http://r/foo',
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'image': 'http://r/foo',
        }))

    def test_postprocess_as2_create_activity_image_bare_string_url(self):
        self.assert_equals({
            'type': 'Create',
            'object': {
                'id': 'http://localhost/r/xyz',
                'attachment': [{'url': 'http://r/foo'}],
                'image': ['http://r/foo'],
                'to': [as2.PUBLIC_AUDIENCE],
            },
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'type': 'Create',
            'object': {
                'id': 'xyz',
                'image': ['http://r/foo'],
            },
        }))

    def test_postprocess_as2_note(self):
        self.assert_equals({
            'id': 'http://localhost/r/xyz',
            'type': 'Note',
            'content': '<p>foo</p>',
            'contentMap': {'en': '<p>foo</p>'},
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'id': 'xyz',
            'type': 'Note',
            'content': 'foo',
            'content_is_html': True,  # should be removed
        }))

    def test_postprocess_as2_note_update_contentMap(self):
        self.assert_equals({
            'type': 'Note',
            'content': '<p>foo</p>',
            'contentMap': {'en': '<p>foo</p>'},
            'to': [as2.PUBLIC_AUDIENCE],
        }, postprocess_as2({
            'type': 'Note',
            'content': 'foo',
            'contentMap': {'en': 'foo'},
        }))

    def test_postprocess_as2_hashtag(self):
        """https://github.com/snarfed/bridgy-fed/issues/45"""
        self.assert_equals({
            'tag': [
                {'type': 'Hashtag', 'name': '#bar', 'href': 'bar'},
                {'type': 'Hashtag', 'name': '#baz', 'href': '/hashtag/baz'},
                {'type': 'Hashtag', 'name': '#biff', 'href': 'http://foo/tag/biff'},
                {'type': 'Mention', 'href': 'foo'},
            ],
            'to': [as2.PUBLIC_AUDIENCE],
            'cc': ['foo'],
        }, postprocess_as2({
            'tag': [
                {'name': 'bar', 'href': 'bar'},
                {'type': 'Tag', 'name': '#baz'},
                # should leave href alone
                {'type': 'Tag', 'name': '#biff', 'href': 'http://foo/tag/biff'},
                # should leave alone entirely
                {'type': 'Mention', 'href': 'foo'},
            ],
        }))

    def test_postprocess_as2_plain_text_content_links_hashtags_mentions(self):
        expected = '<p>foo <a class="mention h-card" href="http://inst/bar">@bar</a> <a class="hashtag" rel="tag" href="http://inst/baz">#baz</a></p>'
        self.assert_equals({
            'content': expected,
            'contentMap': {'en': expected},
            'tag': [{
                'type': 'Mention',
                'href': 'http://inst/bar',
            }, {
                'type': 'Tag',
                'href': 'http://inst/baz',
            }],
            'to': [as2.PUBLIC_AUDIENCE],
            'cc': ['http://inst/bar'],
        }, postprocess_as2({
            'content': 'foo @bar #baz',
            'tag': [{
                'type': 'Mention',
                'href': 'http://inst/bar',
                'startIndex': 4,
                'length': 4,
            }, {
                'type': 'Tag',
                'href': 'http://inst/baz',
                'startIndex': 9,
                'length': 4,
            }],
        }))

    def test_postprocess_as2_moves_link_attachments_to_content(self):
        # https://github.com/snarfed/bridgy-fed/issues/958
        self.assert_equals({
            'type': 'Note',
            'content': '<p><a href="http://a/link">check it out</a><br><br><a href="http://another/link">another/link</a></p>',
            'contentMap': {
                'en': '<p><a href="http://a/link">check it out</a><br><br><a href="http://another/link">another/link</a></p>',
            },
        }, postprocess_as2({
            'type': 'Note',
            'attachment': [{
                'type': 'Link',
                'href': 'http://a/link',
                'name': 'check it out',
            }, {
                'type': 'Link',
                'href': 'http://another/link',
            }],
        }), ignore=['to'])

    def test_postprocess_as2_appends_link_attachments_to_content(self):
        # https://github.com/snarfed/bridgy-fed/issues/958
        self.assert_equals({
            'type': 'Note',
            'content': '<p>original<br><br><a href="http://a/link">a/link</a></p>',
            'contentMap': {
                'en': '<p>original<br><br><a href="http://a/link">a/link</a></p>',
            },
        }, postprocess_as2({
            'type': 'Note',
            'content': 'original',
            'attachment': [{
                'type': 'Link',
                'href': 'http://a/link',
            }],
        }), ignore=['to'])

    def test_postprocess_as2_reply_includes_original_posts_mentions(self):
        note = {
            'type': 'Note',
            'id': 'http://inst/note',
            'content': 'foo @bar',
            'tag': [{
                'type': 'Mention',
                'href': 'http://inst/bar',
                'startIndex': 4,
                'length': 4,
            }, {
                'type': 'Mention',
                'href': 'http://inst/baz',
            }, {
                'type': 'Mention',
                'href': 'http://inst/foo',
            }],
        }
        reply = {
            'content': 'ok',
            'inReplyTo': 'http://inst/note',
            'tag': [{
                'type': 'Mention',
                'href': 'http://inst/foo',
            }],
        }

        self.assert_equals({
            'content': '<p>ok</p>',
            'inReplyTo': 'http://inst/note',
            'tag': [
                {'type': 'Mention', 'href': 'http://inst/foo'},
                {'type': 'Mention', 'href': 'http://inst/bar'},
                {'type': 'Mention', 'href': 'http://inst/baz'},
            ],
        }, postprocess_as2(reply, orig_obj=note), ignore=['contentMap', 'to', 'cc'])

    def test_postprocess_as2_actor_manuallyApprovesFollowers(self):
        got = postprocess_as2_actor(as2.from_as1({
            'objectType': 'person',
            'id': 'http://foo/bar',
        }), user=self.user)
        self.assertFalse(got['manuallyApprovesFollowers'])

    def test_postprocess_as2_actor_url_attachments(self):
        got = postprocess_as2_actor(as2.from_as1({
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
        }), user=self.user)

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

    def test_postprocess_as2_actor_strips_acct_url(self):
        self.assert_equals('http://localhost/r/http://user.com/',
                           postprocess_as2_actor({
            'type': 'Person',
            'url': [
                'http://user.com/',
                'acct:foo@bar',
                {
                    'type': 'Link',
                    'rel': 'canonical',
                    'href': 'acct:baz',
                },
            ],
        }, user=self.user)['url'])

    def test_postprocess_as2_actor_url_dict_with_href(self):
        got = postprocess_as2_actor({
            'type': 'Person',
            'url': {
                'type': 'Link',
                'href': 'http://user.com/',
            },
        }, user=self.user)
        self.assertEqual('http://localhost/r/http://user.com/', got['url'])

        got = postprocess_as2_actor({
            'type': 'Person',
            'url': [
                {
                    'type': 'Link',
                    'href': 'http://user.com/',
                },
                'http://other.com/',
            ],
        }, user=self.user)
        self.assertEqual(['http://localhost/r/http://user.com/', 'http://other.com/'],
                         got['url'])

    def test_postprocess_as2_actor_doesnt_duplicate_security_context(self):
        self.assert_equals([SECURITY_CONTEXT], postprocess_as2_actor({
            '@context': [SECURITY_CONTEXT],
        }, user=self.user)['@context'])

    def test_postprocess_as2_actor_preserves_preferredUsername(self):
        # preferredUsername stays y.z despite user's username. since Mastodon
        # queries Webfinger for preferredUsername@fed.brid.gy
        # https://github.com/snarfed/bridgy-fed/issues/77#issuecomment-949955109
        self.assertEqual('user.com', postprocess_as2_actor({
            'type': 'Person',
            'url': 'https://user.com/about-me',
            'preferredUsername': 'nick',
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'nick',
                'value': '<a rel="me" href="https://user.com/about-me"><span class="invisible">https://</span>user.com/about-me</a>',
            }],
        }, user=self.user)['preferredUsername'])

    def test_postprocess_as2_actor_preferredUsername_is_domain(self):
        self.user.has_redirects = True
        self.user.put()

        self.user.obj.our_as1 = None
        self.user.obj.as2 = {
            'type': 'Person',
            'url': ['acct:eve@user.com'],
        }
        self.user.obj.put()

        # preferredUsername stays y.z despite user's username
        self.assertEqual('user.com', postprocess_as2_actor({
            'type': 'Person',
        }, user=self.user)['preferredUsername'])

    def test_postprocess_as2_user_wrapped_id(self):
        for id in 'http://fed.brid.gy/user.com', 'http://fed.brid.gy/www.user.com':
            got = postprocess_as2_actor(as2.from_as1({
                'objectType': 'person',
                'id': id,
            }), user=self.user)
            self.assert_equals('http://localhost/user.com', got['id'])

    # TODO: bring back once we figure out how to get Mastodon to support this and
    # Pleroma and Akkoma not to DDoS us
    # https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    @skip
    def test_postprocess_as2_featured_id(self):
        got = postprocess_as2_actor(as2.from_as1({
            'objectType': 'person',
            'id': 'http://foo/bar',
            'featured': {'baz': 'biff'},
        }), user=self.user)
        self.assert_equals({
            'type': 'OrderedCollection',
            'id': 'http://foo/bar/featured',
            'baz': 'biff',
        }, got['featured'])

    def test_postprocess_as2_mentions_into_cc(self):
        obj = copy.deepcopy(MENTION_OBJECT)
        del obj['cc']
        self.assertEqual(['https://masto.foo/@other'],
                         postprocess_as2(obj)['cc'])

    def test_postprocess_as2_object_to_cc_into_activity(self):
        got = postprocess_as2({
            '@context': as2.CONTEXT,
            'type': 'Create',
            'object': {
                'to': ['abc'],
                'cc': ['def', 'xyz'],
            },
        })
        self.assertEqual(['abc', 'https://www.w3.org/ns/activitystreams#Public'],
                         got['to'])
        self.assertEqual(['def', 'xyz'], got['cc'])

    def test_postprocess_as2_dm_note(self):
        dm = {
            'objectType': 'note',
            'author': 'web.brid.gy',
            'content': '<p>hello world</p>',
            'contentMap': {'en': '<p>hello world</p>'},
            'to': ['http://inst/user'],
        }
        self.assertEqual(dm, postprocess_as2(copy.deepcopy(dm)))

    def test_postprocess_as2_dm_note_with_mention_tag(self):
        dm = {
            'objectType': 'note',
            'author': 'web.brid.gy',
            'content': '<p>hello world</p>',
            'contentMap': {'en': '<p>hello world</p>'},
            'tags': [{
                'objectType': 'mention',
                'url': 'https://inst/user',
            }],
            'to': ['http://inst/user'],
        }
        self.assertEqual(dm, postprocess_as2(copy.deepcopy(dm)))

    def test_postprocess_as2_dm_create(self):
        dm = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'https://inst/dm#create',
            'actor': 'web.brid.gy',
            'object': {
                'objectType': 'note',
                'id': 'https://inst/dm',
                'author': 'web.brid.gy',
                'content': '<p>hello world</p>',
                'contentMap': {'en': '<p>hello world</p>'},
                'to': ['http://inst/user'],
            },
            'to': ['http://inst/user'],
        }
        self.assertEqual({
            **dm,
            'id': 'https://web.brid.gy/r/https://inst/dm#create',
        }, postprocess_as2(copy.deepcopy(dm)))

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

    @patch('requests.get')
    def test_signed_get_too_many_redirects(self, mock_get):
        mock_get.return_value = requests_response(
            status=302, redirected_url='http://second', allow_redirects=False)

        with self.assertRaises(requests.TooManyRedirects):
            activitypub.signed_get('https://first')

    @patch('requests.post', return_value=requests_response(status=200))
    def test_signed_post_from_user_is_activitypub_use_instance_actor(self, mock_post):
        activitypub.signed_post('https://url', from_user=ActivityPub(id='http://fed'))

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('https://url',), args)
        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(instance_actor().private_pem(), rsa_key.exportKey())

    @patch('requests.post')
    def test_signed_post_ignores_redirect(self, mock_post):
        mock_post.side_effect = [
            requests_response(status=302, redirected_url='http://second',
                              allow_redirects=False),
        ]

        resp = activitypub.signed_post('https://first', from_user=self.user)
        mock_post.assert_called_once()
        self.assertEqual(302, resp.status_code)

    @patch('requests.get', return_value=AS2)
    def test_fetch_direct(self, mock_get):
        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
        self.assertEqual(AS2_OBJ, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_direct_list(self, mock_get):
        mock_get.return_value = self.as2_resp([AS2_OBJ])
        obj = Object(id='http://orig')
        self.assertFalse(ActivityPub.fetch(obj))
        self.assertIsNone(obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_direct_ld_content_type(self, mock_get):
        mock_get.return_value = requests_response(AS2_OBJ, headers={
            'Content-Type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
        })
        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
        self.assertEqual(AS2_OBJ, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    @patch('requests.get')
    def test_fetch_via_html(self, mock_get):
        mock_get.side_effect = [HTML_WITH_AS2, AS2]
        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
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

    @patch('requests.get')
    def test_fetch_multiply_valued_type(self, mock_get):
        # BandWagon sends this, eg https://bandwagon.fm/683df9a103137839d85d1579
        # https://console.cloud.google.com/errors/detail/COLtjYq7gMveSA?project=bridgy-federated
        event_article = {
            'type': ['Event', 'Article'],
            'id': 'http://foo/bar',
        }
        mock_get.return_value = self.as2_resp(event_article)

        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
        self.assertEqual(event_article, obj.as2)

    @patch('requests.get')
    def test_fetch_hydrate_actor_featured(self, mock_get):
        actor = {
            **ACTOR,
            'featured': 'http://feat/ured',
        }
        featured = {'foo': 'bar'}
        mock_get.side_effect = [self.as2_resp(actor), self.as2_resp(featured)]

        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
        self.assertEqual({**actor, 'featured': {'foo': 'bar'}}, obj.as2)

        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
            self.as2_req('http://feat/ured', headers=as2.CONNEG_HEADERS),
        ))

    @patch('requests.get')
    def test_fetch_actor_featured_already_hydrated(self, mock_get):
        actor = {
            **ACTOR,
            'featured': {'foo': 'bar'},
        }
        mock_get.return_value = self.as2_resp(actor)

        obj = Object(id='http://orig')
        self.assertTrue(ActivityPub.fetch(obj))
        self.assertEqual(actor, obj.as2)

        mock_get.assert_called_once()
        mock_get.assert_has_calls((
            self.as2_req('http://orig'),
        ))

    def test_convert(self):
        obj = Object()
        self.assertEqual({}, ActivityPub.convert(obj))

        obj.our_as1 = {}
        self.assertEqual({}, ActivityPub.convert(obj))

        obj.as2 = {'baz': 'biff'}
        self.assert_equals({'baz': 'biff'}, ActivityPub.convert(obj))

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
        self.assertEqual({
            '@context': as2.CONTEXT,
            'id': 'https://fa.brid.gy/convert/ap/fake:like',
            'type': 'Like',
            'actor': 'https://fa.brid.gy/ap/fake:user',
            'object': 'https://mas.to/thing',
            'to': [as2.PUBLIC_AUDIENCE],
        }, ActivityPub.convert(obj))

    def test_convert_actor_as2(self):
        self.assert_equals(ACTOR, ActivityPub.convert(Object(as2=ACTOR)))

    @patch('requests.get')
    def test_convert_actor_as1_from_user(self, mock_get):
        mock_get.return_value = test_web.ACTOR_HTML_RESP

        obj = Object(our_as1={
            'objectType': 'person',
            'id': 'https://user.com/',
        })
        self.assert_equals(
            {
                **ACTOR_BASE,
                'type': 'Person',
                'discoverable': True,
                'indexable': True,
            }, ActivityPub.convert(obj, from_user=self.user),
            ignore=['@context', 'endpoints', 'followers', 'following',
                    'publicKey', 'summary', 'alsoKnownAs', 'attachment'])

    def test_convert_actor_as1_no_from_user(self):
        obj = Object(our_as1=ACTOR_AS1)
        self.assert_equals(ACTOR, common.unwrap(ActivityPub.convert(obj)),
                           ignore=['to', 'attachment', 'publicKey'])

    def test_convert_actor_as1_proxy_link(self):
        obj = Object(id='fake:id', our_as1=ACTOR_AS1, source_protocol='fake')
        converted = ActivityPub.convert(obj)
        self.assert_equals([{
            'type': 'Link',
            'rel': 'canonical',
            'href': 'fake:id',
        }], converted['url'])

    def test_convert_actor_as1_skip_proxy_link_for_brid_gy_ids(self):
        obj = Object(id='https://web.brid.gy/foo', our_as1=ACTOR_AS1,
                     source_protocol='web')
        self.assertNotIn('url', ActivityPub.convert(obj))

    def test_convert_follow_as1_no_from_user(self):
        # prevent HTTP fetches to infer protocol
        self.store_object(id='https://mas.to/follow', source_protocol='activitypub')
        self.store_object(id='https://user.com/', source_protocol='web')

        obj = Object(our_as1=as2.to_as1(FOLLOW))
        self.assert_equals(FOLLOW, common.unwrap(ActivityPub.convert(obj)),
                           ignore=['to', 'publicKey'])

    def test_convert_profile_update_as1_no_from_user(self):
        obj = Object(our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'object': ACTOR_AS1,
        })
        self.assert_equals({
            'type': 'Update',
            'object': ACTOR,
        }, common.unwrap(ActivityPub.convert(obj)),
            ignore=['to', 'attachment', 'publicKey'])

    def test_convert_compact_actor_attributedTo_author(self):
        obj = Object(our_as1={
            'actor': {'id': 'baj'},
            'author': [{'id': 'bar'}],
            'object': {'author': {'id': 'biff'}},
        })
        self.assert_equals({
            'actor': 'baj',
            'attributedTo': 'bar',
            'object': {'attributedTo': 'biff'},
        }, ActivityPub.convert(obj), ignore=['to'])

    def test_convert_actor_as1_source_links(self):
        self.make_user('efake.brid.gy', cls=Web, ap_subdomain='efake')
        user = self.make_user(cls=ExplicitFake, id='efake:user',
                              obj_as1={'objectType': 'person'})

        self.assert_equals(
            '🌉 <a href="https://fed.brid.gy/efake/efake:handle:user">bridged</a> from 📣 <a href="web:efake:user">efake:handle:user</a>, follow <a class="h-card u-author mention" rel="me" href="https://efake.brid.gy/efake.brid.gy" title="@efake.brid.gy@efake.brid.gy">@efake.brid.gy</a> to interact',
            ActivityPub.convert(user.obj, from_user=user)['summary'])

    def test_convert_adds_context_to_as2(self):
        obj = Object(as2={
            'type': 'Update',
            'object': ACTOR,
        })
        # use assertEquals so that we don't ignore @context
        self.assertEqual({
            '@context': as2.CONTEXT + [SECURITY_CONTEXT],
            'type': 'Update',
            'object': ACTOR,
        }, ActivityPub.convert(obj))

    def test_convert_to_cc(self):
        self.assert_equals({
            '@context': as2.CONTEXT,
            'to': ['http://localhost/alice.com',
                   'https://www.w3.org/ns/activitystreams#Public'],
            'cc': ['http://localhost/bob.com'],
        }, ActivityPub.convert(Object(our_as1={
            'to': ['alice.com'],
            'cc': ['bob.com'],
        })))

    def test_convert_quote_post(self):
        obj = Object(id='at://did:alice/app.bsky.feed.post/123', bsky={
            '$type': 'app.bsky.feed.post',
            'text': 'foo bar',
            'embed': {
                '$type': 'app.bsky.embed.record',
                'record': {
                    'cid': 'bafyreih...',
                    'uri': 'at://did:bob/app.bsky.feed.post/456'
                }
            },
        })

        self.assert_equals({
            'type': 'Note',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:alice/app.bsky.feed.post/123',
            'url': 'http://localhost/r/https://bsky.app/profile/did:alice/post/123',
            'content': '<p>foo bar<span class="quote-inline"><br><br>RE: <a href="https://bsky.app/profile/did:bob/post/456">https://bsky.app/profile/did:bob/post/456</a></span></p>',
            'attributedTo': 'did:alice',
            '_misskey_quote': 'https://bsky.brid.gy/convert/ap/at://did:bob/app.bsky.feed.post/456',
            'quoteUrl': 'https://bsky.brid.gy/convert/ap/at://did:bob/app.bsky.feed.post/456',
            'tag': [{
                'type': 'Link',
                'mediaType': as2.CONTENT_TYPE_LD_PROFILE,
                'href': 'https://bsky.brid.gy/convert/ap/at://did:bob/app.bsky.feed.post/456',
                'name': 'RE: https://bsky.app/profile/did:bob/post/456',
            }],
        }, ActivityPub.convert(obj), ignore=['contentMap', 'to'])

    @patch('requests.get', return_value=requests_response())
    def test_convert_bluesky_external_embed_to_link_in_content(self, _):
        # https://github.com/snarfed/bridgy-fed/issues/1637
        self.assert_equals({
            'type': 'Note',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:bob/app.bsky.feed.post/456',
            'url': 'http://localhost/r/https://bsky.app/profile/did:bob/post/456',
            'attributedTo': 'did:bob',
            'content': '<p>foo bar<br><br><a href="http://a.li/nc">a linc</a></p>',
        }, ActivityPub.convert(Object(id='at://did:bob/app.bsky.feed.post/456', bsky={
            "$type": "app.bsky.feed.post",
            "text": "foo bar",
            "embed": {
                "$type": "app.bsky.embed.external",
                "external": {
                    "description": "baz biff",
                    "title": "a linc",
                    "uri": "http://a.li/nc",
                },
            },
        })), ignore=['@context', 'contentMap', 'to'])

    def test_convert_mention_non_bridged_id_uses_profile_url(self):
        self.store_object(id='did:plc:5zspv27pk4iqtrl2ql2nykjh', raw={'foo': 'bar'})
        self.make_user(id='did:plc:5zspv27pk4iqtrl2ql2nykjh', cls=ATProto)
        obj = Object(our_as1={
            'objectType': 'note',
            'content': 'hello @snarfed2.bsky.social',
            'tags': [{
                'objectType': 'mention',
                'url': 'did:plc:5zspv27pk4iqtrl2ql2nykjh',
                'displayName': '@snarfed2.bsky.social',
                'startIndex': 6,
                'length': 21,
            }],
        })
        self.assertEqual({
            '@context': as2.CONTEXT,
            'type': 'Note',
            'content': '<p>hello <a class="mention h-card" href="https://bsky.app/profile/did:plc:5zspv27pk4iqtrl2ql2nykjh">@snarfed2.bsky.social</a></p>',
            'contentMap': {'en': '<p>hello <a class="mention h-card" href="https://bsky.app/profile/did:plc:5zspv27pk4iqtrl2ql2nykjh">@snarfed2.bsky.social</a></p>'},
            'tag': [{
                'type': 'Mention',
                'name': '@snarfed2.bsky.social',
                'href': 'https://bsky.app/profile/did:plc:5zspv27pk4iqtrl2ql2nykjh',
            }],
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
            'cc': ['https://bsky.app/profile/did:plc:5zspv27pk4iqtrl2ql2nykjh'],
        }, ActivityPub.convert(obj))

    def test_convert_pinned_post_featured_collection_ids(self):
        obj = Object(our_as1={
            'objectType': 'person',
            'featured': {
                'items': [
                    'at://did:fo:o/app.bsky.feed.post/bar',
                    'fake:post',
                ],
            },
        })
        self.assert_equals({
            'type': 'Person',
            'featured': {
                'type': 'OrderedCollection',
                'orderedItems': [
                    'https://bsky.brid.gy/convert/ap/at://did:fo:o/app.bsky.feed.post/bar',
                    'https://fa.brid.gy/convert/ap/fake:post',
                ],
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        }, ActivityPub.convert(obj), ignore=['@context', 'discoverable', 'indexable'])

    def test_convert_adds_fep_fffd_canonical_link(self):
        obj = Object(id='fake:post:123', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'Hello world',
        })
        converted = ActivityPub.convert(obj)
        self.assertEqual([{
            'type': 'Link',
            'rel': 'canonical',
            'href': 'fake:post:123'
        }], converted['url'])

    def test_convert_fep_fffd_preserves_existing_url_string(self):
        obj = Object(id='fake:post:456', source_protocol='web', our_as1={
            'objectType': 'note',
            'content': 'Hello',
            'url': 'fake:url:456',
        })
        converted = ActivityPub.convert(obj)
        self.assertEqual([
            'http://localhost/r/fake:url:456',
            {
                'type': 'Link',
                'rel': 'canonical',
                'href': 'fake:post:456'
            },
        ], converted['url'])

    def test_convert_fep_fffd_preserves_existing_url_list(self):
        obj = Object(id='fake:post:789', source_protocol='web', our_as1={
            'objectType': 'note',
            'content': 'Multiple URLs',
            'url': ['fake:1', 'fake:2'],
        })
        converted = ActivityPub.convert(obj)
        self.assertEqual([
            'http://localhost/r/fake:1',
            'http://localhost/r/fake:2',
            {
                'type': 'Link',
                'rel': 'canonical',
                'href': 'fake:post:789'
            },
        ], converted['url'])

    def test_convert_fep_fffd_skips_ap_objects(self):
        obj = Object(id='https://mastodon.social/id',
                     source_protocol='activitypub',
                     our_as1={
                         'objectType': 'note',
                         'content': 'From ActivityPub',
                         'url': 'https://mastodon.social/url',
                     })
        converted = ActivityPub.convert(obj)
        self.assertEqual('https://mastodon.social/url', converted['url'])

    def test_convert_fep_fffd_skips_crud_activities(self):
        obj = Object(id='fake:update', source_protocol='fake',
                     our_as1={
                         'objectType': 'update',
                         'content': 'an update',
                     })
        converted = ActivityPub.convert(obj)
        self.assertNotIn('url', converted)

    def test_convert_fep_fffd_no_object_id(self):
        obj = Object(source_protocol='web', our_as1={
            'objectType': 'note',
            'content': 'No ID',
        })
        converted = ActivityPub.convert(obj)
        self.assertNotIn('url', converted)

    def test_postprocess_as2_idempotent(self):
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

    def test_handle_as(self):
        user = ActivityPub(obj=Object(id='a', as2={
            **ACTOR,
            'preferredUsername': 'me',
        }))
        self.assertEqual('@me@mas.to', user.handle_as(ActivityPub))
        self.assertEqual('@me@mas.to', user.handle)

        user.obj.as2 = ACTOR
        self.assertEqual('@swentel@mas.to', user.handle_as(ActivityPub))
        self.assertEqual('@swentel@mas.to', user.handle)

        user = ActivityPub(id='https://mas.to/users/alice')
        self.assertEqual('@alice@mas.to', user.handle_as(ActivityPub))
        self.assertEqual('@alice@mas.to', user.handle)

        user = self.make_user('http://a', cls=ActivityPub, obj_as2={
            'id': 'https://mas.to/users/foo',
            'preferredUsername': 'me',
        })
        self.assertEqual('me.mas.to.ap.brid.gy', user.handle_as('atproto'))

    def test_web_url_composite_url_object(self):
        actor_as2 = {
            'type': 'Person',
            'url': 'https://techhub.social/@foo',
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'Twitter',
                'value': '<span class="h-card"><a href="https://techhub.social/@foo" class="u-url mention">@<span>foo</span></a></span>',
            }],
        }
        user = self.make_user('http://foo/person', cls=ActivityPub, obj_as2=actor_as2)
        self.assertEqual('https://techhub.social/@foo', user.web_url())

    def test_web_url(self):
        user = self.make_user('http://foo/person', cls=ActivityPub)
        self.assertEqual('http://foo/person', user.web_url())

        user.obj = Object(id='a', as2=copy.deepcopy(ACTOR))  # no url
        self.assertEqual('http://foo/person', user.web_url())

        user.obj.as2['url'] = ['http://my/url']
        self.assertEqual('http://my/url', user.web_url())

    @patch('requests.get', side_effect=[
        TestCase.as2_resp({
            'type': 'Person',
            'id': 'http://foo.com/user',
            'preferredUsername': 'alice',
        }),
        requests_response({'subject': 'acct:ms-alice@bar.com'}),
        requests_response({'subject': 'acct:ms-alice@bar.com'}),
    ])
    def test_reload_profile_resolve_webfinger_subject(self, mock_get):
        user = self.make_user('http://foo.com/user', cls=ActivityPub)
        user.reload_profile()

        self.assertEqual('@ms-alice@bar.com', user.handle)
        mock_get.assert_has_calls((
            self.as2_req('http://foo.com/user'),
            self.req('https://foo.com/.well-known/webfinger?resource=acct:alice@foo.com'),
            self.req('https://bar.com/.well-known/webfinger?resource=acct:ms-alice@bar.com'),
        ))

    @patch('requests.get', return_value= TestCase.as2_resp({
        'type': 'Person',
        'id': 'http://foo.com/user',
    }))
    def test_reload_profile_no_preferred_username(self, mock_get):
        user = self.make_user('http://foo.com/user', cls=ActivityPub)
        user.reload_profile()

        self.assertIsNone(user.handle)
        mock_get.assert_called_once()
        mock_get.assert_has_calls((
            self.as2_req('http://foo.com/user'),
        ))

    @patch('requests.get', side_effect=[
        TestCase.as2_resp({
            'type': 'Person',
            'id': 'http://foo.com/user',
            'preferredUsername': 'alice',
        }),
        requests_response(status=500),
    ])
    def test_reload_profile_first_webfinger_fails(self, mock_get):
        user = self.make_user('http://foo.com/user', cls=ActivityPub)
        user.reload_profile()

        self.assertEqual('@alice@foo.com', user.handle)
        mock_get.assert_has_calls((
            self.as2_req('http://foo.com/user'),
            self.req('https://foo.com/.well-known/webfinger?resource=acct:alice@foo.com'),
        ))

    @patch('requests.get', side_effect=[
        TestCase.as2_resp({
            'type': 'Person',
            'id': 'http://foo.com/user',
            'preferredUsername': 'alice',
        }),
        requests_response({'subject': 'acct:ms-alice@bar.com'}),
        requests_response({'subject': 'acct:different-subject@baz.com'}),
    ])
    def test_reload_profile_second_webfinger_subject_mismatch(self, mock_get):
        """If the second webfinger call returns a different subject, we should abort."""
        user = self.make_user('http://foo.com/user', cls=ActivityPub)
        user.reload_profile()

        # Should fall back to original handle, not set webfinger_subject
        self.assertEqual('@alice@foo.com', user.handle)
        self.assertIsNone(user.webfinger_addr)
        mock_get.assert_has_calls((
            self.as2_req('http://foo.com/user'),
            self.req('https://foo.com/.well-known/webfinger?resource=acct:alice@foo.com'),
            self.req('https://bar.com/.well-known/webfinger?resource=acct:ms-alice@bar.com'),
        ))

    def test_server_actor_override_status(self):
        actor = self.make_user('http://inst/person', cls=ActivityPub,
                               obj_as2={'id': 'http://inst/actor'})
        self.assertIsNone(actor.status)

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
            'attributedTo': ACTOR['id'],
        }
        self.assertEqual('http://mas.to/inbox', ActivityPub.target_for(obj))

        del obj.as2['attributedTo']
        obj.as2['actor'] = copy.deepcopy(ACTOR)
        obj.as2['actor']['url'] = [obj.as2['actor'].pop('id')]
        self.assertEqual('http://mas.to/inbox', ActivityPub.target_for(obj))

    @patch('requests.get')
    def test_target_for_object_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(ACTOR)

        obj = Object(as2={
            **NOTE_OBJECT,
            'attributedTo': 'http://the/author',
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
        self.assertIsNone(ActivityPub.target_for(obj))
        self.assertIsNone(ActivityPub.target_for(obj, shared=True))

    def test_target_for_actor_endpoints_null(self):
        obj = Object(as2={
            'type': 'Person',
            'endpoints': None,
        })
        self.assertIsNone(ActivityPub.target_for(obj))
        self.assertIsNone(ActivityPub.target_for(obj, shared=True))

    @patch('requests.post')
    def test_send_blocklisted(self, mock_post):
        self.assertFalse(ActivityPub.send(Object(as2=NOTE),
                                          'https://fed.brid.gy/ap/sharedInbox',
                                          from_user=self.user))
        mock_post.assert_not_called()

    @patch('requests.post')
    def test_send_no_from_user(self, mock_post):
        self.assertFalse(ActivityPub.send(Object(as2=NOTE),
                                          ACTOR['inbox'],
                                          from_user=None))
        mock_post.assert_not_called()

    @patch('requests.post', return_value=requests_response())
    def test_send_convert_ids(self, mock_post):
        like = Object(our_as1={
            'id': 'fake:like',
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
            'actor': 'fake:user',
        })
        self.assertTrue(ActivityPub.send(like, 'https://inbox', from_user=self.user))

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual(('https://inbox',), args)
        self.assertEqual({
            '@context': as2.CONTEXT,
            'id': 'https://fa.brid.gy/convert/ap/fake:like',
            'type': 'Like',
            'object': 'https://fa.brid.gy/convert/ap/fake:post',
            'actor': 'https://fa.brid.gy/ap/fake:user',
            'to': [as2.PUBLIC_AUDIENCE],
        }, json_loads(kwargs['data']))

    @patch('requests.post', return_value=requests_response())
    def test_send_dm(self, mock_post):
        bot = self.make_user('web.brid.gy', cls=Web)
        user = self.make_user(ACTOR['id'], cls=ActivityPub, obj_as2=ACTOR)

        dm = Object(id='https://internal.brid.gy/dm', source_protocol='web', our_as1={
            'objectType': 'note',
            'author': 'web.brid.gy',
            'content': 'hello world',
            'to': [ACTOR['id']],
        })
        dm.put()
        self.assertTrue(ActivityPub.send(dm, ACTOR['inbox'], from_user=bot))

        self.assertEqual(1, len(mock_post.call_args_list))
        args, kwargs = mock_post.call_args_list[0]
        self.assertEqual((ACTOR['inbox'],), args)
        self.assertEqual({
            '@context': as2.CONTEXT,
            'type': 'Note',
            'id': 'http://localhost/r/https://internal.brid.gy/dm',
            'attributedTo': 'https://web.brid.gy/web.brid.gy',
            'content': '<p>hello world</p>',
            'contentMap': {'en': '<p>hello world</p>'},
            'url': [{
                'href': 'https://internal.brid.gy/dm',
                'rel': 'canonical',
                'type': 'Link',
            }],
            'to': [ACTOR['id']],
        }, json_loads(kwargs['data']))

    def test_nodeinfo(self):
        # just check that it doesn't crash
        self.client.get('/.well-known/nodeinfo')
        self.client.get('/nodeinfo.json')

    def test_instance_info(self):
        # just check that it doesn't crash
        self.client.get('/api/v1/instance')

    def test_as2_request_type(self):
        for accept, expected in (
                (as2.CONTENT_TYPE_LD_PROFILE, as2.CONTENT_TYPE_LD_PROFILE),
                (as2.CONTENT_TYPE_LD, as2.CONTENT_TYPE_LD_PROFILE),
                (as2.CONTENT_TYPE, as2.CONTENT_TYPE),
                # TODO: handle eventually; this should return non-None
                (activitypub.CONNEG_HEADERS_AS2_HTML['Accept'], None),
                ('', None),
                ('*/*', None),
                ('text/html', None),
        ):
            with (self.subTest(accept=accept),
                  app.test_request_context('/', headers={'Accept': accept})):
                self.assertEqual(expected, activitypub.as2_request_type())
