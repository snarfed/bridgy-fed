# coding=utf-8
"""Unit tests for webmention.py."""
import copy
from unittest import mock, skip
from urllib.parse import urlencode

import feedparser
from granary import as2, atom, microformats2
from httpsig.sign import HeaderSigner
from oauth_dropins.webutil import appengine_config, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

import activitypub
from app import app
from common import (
    CONTENT_TYPE_HTML,
    redirect_unwrap,
)
from models import Follower, Object, Target, User
from webmention import TASKS_LOCATION, Webmention
from .test_activitypub import LIKE
from . import testutil

ACTOR_HTML = """\
<html>
<body class="h-card">
<a class="p-name u-url" rel="me" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
ACTOR_MF2 = {
    'type': ['h-card'],
    'properties': {
        'url': ['https://user.com/'],
        'name': ['Ms. ☕ Baz'],
    },
}
ACTOR_AS1_UNWRAPPED = {
    'objectType': 'person',
    'displayName': 'Ms. ☕ Baz',
    'url': 'https://user.com/',
    'urls': [{'value': 'https://user.com/', 'displayName': 'Ms. ☕ Baz'}],
}
ACTOR_AS2 = {
    'type': 'Person',
    'id': 'http://localhost/user.com',
    'url': 'http://localhost/r/https://user.com/',
    'name': 'Ms. ☕ Baz',
    'preferredUsername': 'user.com',
}
ACTOR_AS2_FULL = {
    **ACTOR_AS2,
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'preferredUsername': 'user.com',
    'attachment': [{
        'name': 'Web site',
        'type': 'PropertyValue',
        'value': '<a rel="me" href="https://user.com/">user.com</a>',
    }],
    'inbox': 'http://localhost/user.com/inbox',
    'outbox': 'http://localhost/user.com/outbox',
    'following': 'http://localhost/user.com/following',
    'followers': 'http://localhost/user.com/followers',
    'endpoints': {
        'sharedInbox': 'http://localhost/inbox',
    },
}
ACTOR_AS2_FULL_UNWRAPPED = {
    **ACTOR_AS2_FULL,
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'id': 'https://user.com/',
    'url': 'https://user.com/',
    'preferredUsername': 'user.com',
    'attachment': [{
        'name': 'Web site',
        'type': 'PropertyValue',
        'value': '<a rel="me" href="https://user.com/">user.com</a>',
    }],
    # TODO: fix
    'inbox': 'https://user.com/inbox/',
    'outbox': 'https://user.com/outbox/',
    'following': 'https://user.com/following/',
    'followers': 'https://user.com/followers/',
    'endpoints': {
        'sharedInbox': 'http://localhost/inbox',
    },
}

REPOST_HTML = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/repost"></a>
<a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
REPOST_AS2 = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Announce',
    'id': 'http://localhost/r/https://user.com/repost',
    'url': 'http://localhost/r/https://user.com/repost',
    'name': 'reposted!',
    'object': 'https://mas.to/toot/id',
    'to': [as2.PUBLIC_AUDIENCE],
    'cc': [
        'https://mas.to/author',
        'https://mas.to/bystander',
        'https://mas.to/recipient',
        as2.PUBLIC_AUDIENCE,
    ],
    'actor': 'http://localhost/user.com',
}
REPOST_AS1_UNWRAPPED = {
    'objectType': 'activity',
    'verb': 'share',
    'id': 'https://user.com/repost',
    'url': 'https://user.com/repost',
    'displayName': 'reposted!',
    'object': 'https://mas.to/toot/id',
    'actor': ACTOR_AS1_UNWRAPPED,
}
WEBMENTION_REL_LINK = requests_response(
    '<html><head><link rel="webmention" href="/webmention"></html>')
WEBMENTION_NO_REL_LINK = requests_response('<html></html>')


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user('user.com')
        self.toot_html = requests_response("""\
<html>
<meta>
<link href='https://mas.to/toot/atom' rel='alternate' type='application/atom+xml'>
<link href='https://mas.to/toot/id' rel='alternate' type='application/activity+json'>
</meta>
</html>
""", url='https://mas.to/toot', content_type=CONTENT_TYPE_HTML)
        self.toot_as2_data = {
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'id': 'https://mas.to/toot/id',
            'content': 'Lots of ☕ words...',
            'actor': {'url': 'https://mas.to/author'},
            'to': ['https://mas.to/recipient', as2.PUBLIC_AUDIENCE],
            'cc': ['https://mas.to/bystander', as2.PUBLIC_AUDIENCE],
        }
        self.toot_as2 = requests_response(
            self.toot_as2_data, url='https://mas.to/toot/id',
            content_type=as2.CONTENT_TYPE + '; charset=utf-8')

        self.reply_html = """\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="https://user.com/reply"></a>
<p class="e-content p-name">
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://mas.to/toot">foo ☕ bar</a>
<a href="http://localhost/"></a>
</p>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
</div>
</body>
</html>
"""
        self.reply = requests_response(self.reply_html, content_type=CONTENT_TYPE_HTML,
                                       url='https://user.com/reply')
        self.reply_mf2 = util.parse_mf2(self.reply_html, url='https://user.com/reply')
        self.reply_as1 = microformats2.json_to_object(self.reply_mf2['items'][0])

        self.repost = requests_response(REPOST_HTML, content_type=CONTENT_TYPE_HTML,
                                        url='https://user.com/repost')
        self.repost_mf2 = util.parse_mf2(REPOST_HTML, url='https://user.com/repost')
        self.repost_as1 = microformats2.json_to_object(self.repost_mf2['items'][0])

        self.like_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/like"></a>
<a class="u-like-of" href="https://mas.to/toot"></a>
<!--<a class="u-like-of p-name" href="https://mas.to/toot">liked!</a>-->
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.like = requests_response(self.like_html, content_type=CONTENT_TYPE_HTML,
                                      url='https://user.com/like')
        self.like_mf2 = util.parse_mf2(self.like_html, url='https://user.com/like')

        self.actor = self.as2_resp({
            'objectType' : 'Person',
            'displayName': 'Mrs. ☕ Foo',
            'id': 'https://mas.to/mrs-foo',
            'inbox': 'https://mas.to/inbox',
        })

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/https://user.com/reply#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/https://user.com/reply',
                'url': 'http://localhost/r/https://user.com/reply',
                'name': 'foo ☕ bar',
                'content': """\
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://mas.to/toot">foo ☕ bar</a>
<a href="http://localhost/"></a>""",
                'inReplyTo': 'https://mas.to/toot/id',
                'to': [as2.PUBLIC_AUDIENCE],
                'cc': [
                    'https://mas.to/author',
                    'https://mas.to/recipient',
                    'https://mas.to/bystander',
                    as2.PUBLIC_AUDIENCE,
                ],
                'attributedTo': ACTOR_AS2,
                'tag': [{
                    'type': 'Mention',
                    'href': 'https://mas.to/author',
                }],
            },
        }
        self.as2_update = copy.deepcopy(self.as2_create)
        self.as2_update['type'] = 'Update'
        # we should generate this if it's not already in mf2 because Mastodon
        # requires it for updates
        self.as2_update['object']['updated'] = util.now().isoformat()

        self.follow_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/follow"></a>
<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.follow = requests_response(
            self.follow_html, content_type=CONTENT_TYPE_HTML)
        self.follow_mf2 = util.parse_mf2(self.follow_html, url='https://user.com/follow')
        self.follow_as1 = microformats2.json_to_object(self.follow_mf2['items'][0])
        self.follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': 'http://localhost/r/https://user.com/follow',
            'url': 'http://localhost/r/https://user.com/follow',
            'object': 'https://mas.to/mrs-foo',
            'actor': 'http://localhost/user.com',
            'to': [as2.PUBLIC_AUDIENCE],
        }

        self.follow_fragment_html = """\
<html>
<body>
<article class=h-entry id=1>
<h1>Ignored</h1>
</article>
<article class=h-entry id=2>
<a class="u-url" href="https://user.com/follow#2"></a>
<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</article>
</body>
</html>
"""
        self.follow_fragment = requests_response(
            self.follow_fragment_html, content_type=CONTENT_TYPE_HTML)
        self.follow_fragment_mf2 = util.parse_mf2(
            self.follow_fragment_html, url='https://user.com/follow', id='2')
        self.follow_fragment_as1 = microformats2.json_to_object(
            self.follow_fragment_mf2['items'][0])
        self.follow_fragment_as2 = copy.deepcopy(self.follow_as2)
        self.follow_fragment_as2.update({
            'id': 'http://localhost/r/https://user.com/follow#2',
            'url': 'http://localhost/r/https://user.com/follow#2',
        })

        self.create_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/post"></a>
<p class="e-content p-name">hello i am a post</p>
<a class="p-author h-card" href="https://user.com/">
  <p class="p-name">Ms. ☕ <span class="p-nickname">Baz</span></p>
</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.create = requests_response(
            self.create_html, content_type=CONTENT_TYPE_HTML)
        self.create_mf2 = util.parse_mf2(self.create_html, url='https://user.com/create')
        self.create_as1 = microformats2.json_to_object(self.create_mf2['items'][0])
        self.create_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/https://user.com/post#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/https://user.com/post',
                'url': 'http://localhost/r/https://user.com/post',
                'name': 'hello i am a post',
                'content': 'hello i am a post',
                'attributedTo': ACTOR_AS2,
                'to': [as2.PUBLIC_AUDIENCE],
            },
        }
        self.update_as2 = copy.deepcopy(self.create_as2)
        self.update_as2['type'] = 'Update'
        self.update_as2['object']['updated'] = util.now().isoformat()

        self.not_fediverse = requests_response("""\
<html>
<body>foo</body>
</html>
""", url='http://not/fediverse', content_type=CONTENT_TYPE_HTML)
        self.activitypub_gets = [self.reply, self.not_fediverse, self.toot_as2,
                                 self.actor]

        self.author = requests_response(ACTOR_HTML, url='https://user.com/',
                                        content_type=CONTENT_TYPE_HTML)

    def assert_deliveries(self, mock_post, inboxes, data):
        self.assertEqual(len(inboxes), len(mock_post.call_args_list))
        calls = {call[0][0]: call for call in mock_post.call_args_list}

        for inbox in inboxes:
            got = json_loads(calls[inbox][1]['data'])
            got.get('object', {}).pop('publicKey', None)
            self.assert_equals(data, got, inbox)

    def test_fetch(self, mock_get, mock_post):
        obj = Object()
        mock_get.return_value = self.reply
        Webmention.fetch(obj, 'https://user.com/post')
        self.assert_equals(self.reply_as1, obj.as1)

    @skip
    def test_fetch_bad_source_url(self, mock_get, mock_post):
        with self.assertRaises(ValueError):
            Webmention.fetch(Object(), 'bad')

    def test_fetch_error(self, mock_get, mock_post):
        mock_get.return_value = requests_response(self.reply_html, status=405)
        with self.assertRaises(BadGateway) as e:
            Webmention.fetch(Object(), 'https://foo')

    def test_send(self, mock_get, mock_post):
        mock_get.return_value = WEBMENTION_REL_LINK
        mock_post.return_value = requests_response()

        obj = Object(id='http://mas.to/like#ok', as2=LIKE)
        with app.test_request_context('/'):
            self.assertTrue(Webmention.send(obj, 'https://user.com/post'))

        self.assert_req(mock_get, 'https://user.com/post')
        args, kwargs = mock_post.call_args
        self.assertEqual(('https://user.com/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/render?id=http%3A%2F%2Fmas.to%2Flike%23ok',
            'target': 'https://user.com/post',
        }, kwargs['data'])

    def test_send_no_endpoint(self, mock_get, mock_post):
        mock_get.return_value = WEBMENTION_NO_REL_LINK
        obj = Object(id='http://mas.to/like#ok', as2=LIKE)

        with app.test_request_context('/'):
            self.assertFalse(Webmention.send(obj, 'https://user.com/post'))

        self.assert_req(mock_get, 'https://user.com/post')
        mock_post.assert_not_called()

    @skip
    def test_send_bad_source_url(self, mock_get, mock_post):
        with self.assertRaises(ValueError):
            Webmention.send(Object(), 'bad')

    def test_send_bad_source_url(self, mock_get, mock_post):
        got = self.client.post('/webmention', data=b'')
        self.assertEqual(400, got.status_code)

        mock_get.side_effect = ValueError('foo bar')
        got = self.client.post('/webmention', data={'source': 'bad'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_source_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html, status=405,
                              content_type=CONTENT_TYPE_HTML),
        )

        got = self.client.post('/webmention', data={'source': 'https://user.com/post'})
        self.assertEqual(502, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_no_source_entry(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body>
<p>nothing to see here except <a href="http://localhost/">link</a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = self.client.post( '/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('https://user.com/post'),))

    def test_no_targets(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body class="h-entry">
<p class="e-content">no one to send to! <a href="http://localhost/"></a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('https://user.com/post'),))

    def test_bad_target_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('https://mas.to/toot', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            ValueError('foo bar'),
        )

        got = self.client.post('/webmention', data={'source': 'https://user.com/reply'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_target_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('https://mas.to/toot', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            requests.Timeout('foo bar'))

        got = self.client.post('/webmention', data={'source': 'https://user.com/reply'})
        self.assertEqual(502, got.status_code)

    def test_target_fetch_has_no_content_type(self, mock_get, mock_post):
        html = self.reply_html.replace(
            '</body>',
            "<link href='http://as2' rel='alternate' type='application/activity+json'></body")
        mock_get.side_effect = (
            requests_response(self.reply_html),
            requests_response(self.reply_html, content_type='None'),
        )
        got = self.client.post('/webmention', data={'source': 'https://user.com/reply'})
        self.assertEqual(502, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_no_backlink(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>', ''),
                                    content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('https://user.com/reply'),))

    def test_backlink_without_trailing_slash(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>',
                                    '<a href="http://localhost"></a>'),
            content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

    def test_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_create, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        self.assert_object('https://user.com/reply',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           delivered=['https://mas.to/inbox'],
                           mf2=self.reply_mf2,
                           as1=self.reply_as1,
                           type='comment',
                           labels=['user'],
                           )

    def test_update_reply(self, mock_get, mock_post):
        mf2 = {
            'items': [{
                'properties': {
                    'content': ['other'],
                },
            }],
        }
        with app.test_request_context('/'):
            Object(id='https://user.com/reply', status='complete', mf2=mf2).put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_update, json_loads(kwargs['data']))

    def test_redo_repost_isnt_update(self, mock_get, mock_post):
        """Like and Announce shouldn't use Update, they should just resend as is."""
        with app.test_request_context('/'):
            Object(id='https://user.com/repost', mf2={}, status='complete').put()

        mock_get.side_effect = [self.repost, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

    def test_skip_update_if_content_unchanged(self, mock_get, mock_post):
        """https://github.com/snarfed/bridgy-fed/issues/78"""
        with app.test_request_context('/'):
            Object(id='https://user.com/reply', status='complete', mf2=self.reply_mf2['items'][0],
                   delivered=[Target(uri='https://mas.to/inbox', protocol='activitypub')]
                   ).put()
        mock_get.side_effect = self.activitypub_gets

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_post.assert_not_called()

    def test_create_reply_attributed_to_id_only(self, mock_get, mock_post):
        """Based on PeerTube's AS2.

        https://github.com/snarfed/bridgy-fed/issues/40
        """
        del self.toot_as2_data['actor']
        self.toot_as2_data['attributedTo'] = {
            'type': 'Person',
            'id': 'https://mas.to/author',
        }

        mock_get.side_effect = [self.reply, self.not_fediverse, self.toot_as2,
                                self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_create, json_loads(kwargs['data']))

    def test_create_repost(self, mock_get, mock_post):
        mock_get.side_effect = [self.repost, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/repost'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        for args, kwargs in mock_get.call_args_list[1:]:
            with self.subTest(url=args[0]):
                rsa_key = kwargs['auth'].header_signer._rsa._key
                self.assertEqual(self.user.private_pem(), rsa_key.exportKey())
        self.assert_object('https://user.com/repost',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.repost_mf2,
                           as1=self.repost_as1,
                           delivered=['https://mas.to/inbox'],
                           type='share',
                           object_ids=['https://mas.to/toot'],
                           labels=['user', 'activity'],
                           )

    def test_link_rel_alternate_as2(self, mock_get, mock_post):
        mock_get.side_effect = [
            self.reply,
            self.not_fediverse,
            self.toot_html,
            self.toot_as2,
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/toot/id', headers=as2.CONNEG_HEADERS),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_create, json_loads(kwargs['data']))

    def test_create_default_url_to_wm_source(self, mock_get, mock_post):
        """Source post has no u-url. AS2 id should default to webmention source."""
        missing_url = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [missing_url, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

    def test_create_author_only_url(self, mock_get, mock_post):
        """Mf2 author property is just a URL. We should run full authorship.

        https://indieweb.org/authorship
        """
        repost = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
<a class="u-author" href="https://user.com/"></a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost, self.author, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=201)

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(201, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

    @mock.patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_create_post_make_task(self, mock_create_task, mock_get, _):
        mock_get.side_effect = [self.create, self.actor]

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(202, got.status_code)
        mock_create_task.assert_called_with(
            parent=f'projects/{APP_ID}/locations/{TASKS_LOCATION}/queues/webmention',
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': '/_ah/queue/webmention',
                    'body': urlencode({'source': 'https://user.com/post'}).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            },
        )

    @staticmethod
    def make_followers():
        Follower.get_or_create('user.com', 'https://mastodon/aaa')
        Follower.get_or_create('user.com', 'https://mastodon/bbb',
                               last_follow={'actor': {
                                   'publicInbox': 'https://public/inbox',
                                   'inbox': 'https://unused',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ccc',
                               last_follow={'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ddd',
                               last_follow={'actor': {
                                   'inbox': 'https://inbox',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ggg',
                               status='inactive',
                               last_follow={'actor': {
                                   'inbox': 'https://unused/2',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/hhh',
                               last_follow={'actor': {
                                   # dupe of eee; should be de-duped
                                   'inbox': 'https://inbox',
                               }})

    def test_create_post_run_task_new(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')
        self.make_followers()

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/post'),
        ))
        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
        self.assert_deliveries(mock_post, inboxes, self.create_as2)

        self.assert_object(f'https://user.com/post',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.create_mf2,
                           as1=self.create_as1,
                           delivered=inboxes,
                           type='note',
                           labels=['user'],
                           )

    def test_create_post_run_task_resume(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        with app.test_request_context('/'):
            Object(id='https://user.com/post', domains=['user.com'], status='in progress',
                   mf2=self.create_mf2['items'][0],
                   delivered=[Target(uri='https://skipped/inbox', protocol='activitypub')],
                   undelivered=[Target(uri='https://shared/inbox', protocol='activitypub')],
                   failed=[Target(uri='https://public/inbox', protocol='activitypub')],
                   ).put()

        self.make_followers()
        # already sent, should be skipped
        Follower.get_or_create('user.com', 'https://mastodon/eee',
                               last_follow={'actor': {
                                   'inbox': 'https://skipped/inbox',
                               }})

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/post'),
        ))

        inboxes = ['https://inbox', 'https://public/inbox', 'https://shared/inbox']
        self.assert_deliveries(mock_post, inboxes, self.create_as2)

        self.assert_object(f'https://user.com/post',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.create_mf2,
                           as1=self.create_as1,
                           delivered=inboxes + ['https://skipped/inbox'],
                           type='note',
                           labels=['user'],
                           )

    def test_create_post_run_task_update(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        with app.test_request_context('/'):
            Object(id='https://user.com/post', domains=['user.com'], status='in progress',
                   mf2={**self.create_mf2, 'content': 'different'},
                   delivered=[Target(uri='https://delivered/inbox', protocol='activitypub')],
                   undelivered=[Target(uri='https://shared/inbox', protocol='activitypub')],
                   failed=[Target(uri='https://public/inbox', protocol='activitypub')],
                   ).put()

        self.make_followers()

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/post'),
        ))
        self.assertEqual(4, len(mock_post.call_args_list), mock_post.call_args_list)

        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox',
                   'https://delivered/inbox')
        self.assert_deliveries(mock_post, inboxes, self.update_as2)

        self.assert_object(f'https://user.com/post',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.create_mf2,
                           as1=self.create_as1,
                           delivered=inboxes,
                           type='note',
                           labels=['user'],
                           )

    def test_create_with_image(self, mock_get, mock_post):
        create_html = self.create_html.replace(
            '</body>', '<img class="u-photo" src="http://im/age" />\n</body>')
        mock_get.side_effect = [
            requests_response(create_html, content_type=CONTENT_TYPE_HTML),
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz ')

        Follower.get_or_create(
            'user.com', 'https://mastodon/aaa',
            last_follow={'actor': {'inbox': 'https://inbox'}})

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        self.assertEqual(('https://inbox',), mock_post.call_args[0])
        create = copy.deepcopy(self.create_as2)
        create['object'].update({
            'image': {'url': 'http://im/age', 'type': 'Image'},
            'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
        })
        self.assert_equals(create, json_loads(mock_post.call_args[1]['data']))

    def test_follow(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())
        self.assert_object('https://user.com/follow',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.follow_mf2,
                           as1=self.follow_as1,
                           delivered=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                           )

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual('https://mas.to/mrs-foo user.com', followers[0].key.id())
        self.assertEqual('user.com', followers[0].src)
        self.assertEqual('https://mas.to/mrs-foo', followers[0].dest)
        self.assertEqual(self.follow_as2, followers[0].last_follow)

    def test_follow_no_actor(self, mock_get, mock_post):
        self.user.actor_as2 = ACTOR_AS2
        self.user.put()

        html = self.follow_html.replace(
            '<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>', '')
        follow = requests_response(html, content_type=CONTENT_TYPE_HTML)

        mock_get.side_effect = [follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.follow_as2, json_loads(kwargs['data']))

    def test_follow_fragment(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow_fragment, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/follow#2',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow#2'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        args, kwargs = mock_post.call_args
        self.assert_equals(('https://mas.to/inbox',), args)
        self.assert_equals(self.follow_fragment_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assert_equals(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assert_equals(self.user.private_pem(), rsa_key.exportKey())
        self.assert_object('https://user.com/follow#2',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           mf2=self.follow_fragment_mf2,
                           as1=self.follow_fragment_as1,
                           delivered=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                           )

        followers = Follower.query().fetch()
        self.assert_equals(1, len(followers))
        self.assert_equals('https://mas.to/mrs-foo user.com', followers[0].key.id())
        self.assert_equals('user.com', followers[0].src)
        self.assert_equals('https://mas.to/mrs-foo', followers[0].dest)

    def test_error_fragment_missing(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow_fragment]

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/follow#3',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(400, got.status_code)

    def test_error(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response(
            'abc xyz', status=405, url='https://mas.to/inbox')

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        body = got.get_data(as_text=True)
        self.assertEqual(502, got.status_code, body)
        self.assertIn(
            '405 Client Error: None for url: https://mas.to/inbox ; abc xyz',
            body)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())
        self.assert_object('https://user.com/follow',
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='failed',
                           mf2=self.follow_mf2,
                           as1=self.follow_as1,
                           failed=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                          )

    def test_repost_blocklisted_error(self, mock_get, mock_post):
        """Reposts of non-fediverse (ie blocklisted) sites aren't yet supported."""
        repost_html = REPOST_HTML.replace('https://mas.to/toot', 'https://twitter.com/foo')
        repost_resp = requests_response(repost_html, content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost_resp]

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)

    @mock.patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_update_profile_make_task(self, mock_create_task, mock_get, _):
        mock_get.side_effect = [self.author]

        got = self.client.post('/webmention', data={
            'source': 'https://user.com/',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(202, got.status_code)
        mock_create_task.assert_called_with(
            parent=f'projects/{APP_ID}/locations/{TASKS_LOCATION}/queues/webmention',
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': '/_ah/queue/webmention',
                    'body': urlencode({'source': 'https://user.com/'}).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            },
        )

    def test_update_profile_run_task(self, mock_get, mock_post):
        mock_get.side_effect = [self.author]
        mock_post.return_value = requests_response('abc xyz')
        Follower.get_or_create('user.com', 'https://mastodon/ccc',
                               last_follow={'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ddd',
                               last_follow={'actor': {
                                   'inbox': 'https://inbox',
                               }})

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_get.assert_has_calls((
            self.req('https://user.com/'),
        ))

        id = 'https://user.com/#update-2022-01-02T03:04:05+00:00'
        wrapped_id = f'http://localhost/r/{id}'
        self.assert_deliveries(mock_post, ('https://shared/inbox', 'https://inbox'), {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Update',
            'id': wrapped_id,
            'url': wrapped_id,
            'actor': 'http://localhost/user.com',
            'object': {
                **ACTOR_AS2_FULL,
                'updated': util.now().isoformat(),
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        })

        got_as2 = Object.get_by_id(id).as2
        self.assert_object(id,
                           domains=['user.com'],
                           source_protocol='webmention',
                           status='complete',
                           as2=got_as2,
                           delivered=['https://inbox', 'https://shared/inbox'],
                           type='update',
                           object_ids=['https://user.com/'],
                           labels=['user', 'activity'],
                           )

        del got_as2['object']['publicKey']
        del got_as2['to']
        self.assert_equals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': id,
            'url': id,
            'type': 'Update',
            'object': ACTOR_AS2_FULL_UNWRAPPED,
        }, got_as2)

    def test_no_user(self, mock_get, mock_post):
        mock_get.side_effect = [requests_response(self.reply_html)]
        got = self.client.post('/webmention', data={'source': 'https://no-user/post'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())
