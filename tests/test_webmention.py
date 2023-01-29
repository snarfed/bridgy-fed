# coding=utf-8
"""Unit tests for webmention.py.

TODO: test error handling
"""
import copy
from unittest import mock
from urllib.parse import urlencode

import feedparser
from granary import as2, atom, microformats2
from httpsig.sign import HeaderSigner
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

import activitypub
from common import (
    CONNEG_HEADERS_AS2_HTML,
    CONTENT_TYPE_HTML,
    default_signature_user,
    redirect_unwrap,
)
from models import Follower, Object, User
import webmention
from webmention import TASKS_LOCATION
from . import testutil

ACTOR_HTML = """\
<html>
<body class="h-card">
<a class="p-name u-url" rel="me" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
ACTOR_MF2 = {
    'type': ['h-card'],
    'properties': {
        'url': ['https://orig'],
        'name': ['Ms. ☕ Baz'],
    },
}
ACTOR_AS1_UNWRAPPED = {
    'objectType': 'person',
    'displayName': 'Ms. ☕ Baz',
    'url': 'https://orig',
    'urls': [{'value': 'https://orig', 'displayName': 'Ms. ☕ Baz'}],
}
ACTOR_AS2 = {
    'type': 'Person',
    'id': 'http://localhost/orig',
    'url': 'http://localhost/r/https://orig',
    'name': 'Ms. ☕ Baz',
    'preferredUsername': 'orig',
}
ACTOR_AS2_FULL = {
    **ACTOR_AS2,
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'preferredUsername': 'orig',
    'attachment': [{
        'name': 'Ms. ☕ Baz',
        'type': 'PropertyValue',
        'value': '<a rel="me" href="https://orig">orig</a>',
    }],
    'inbox': 'http://localhost/orig/inbox',
    'outbox': 'http://localhost/orig/outbox',
    'following': 'http://localhost/orig/following',
    'followers': 'http://localhost/orig/followers',
    'endpoints': {
        'sharedInbox': 'http://localhost/inbox',
    },
}

REPOST_HTML = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/repost"></a>
<a class="u-repost-of p-name" href="https://orig/post">reposted!</a>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
REPOST_AS2 = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Announce',
    'id': 'http://localhost/r/http://a/repost',
    'url': 'http://localhost/r/http://a/repost',
    'name': 'reposted!',
    'object': 'tag:orig,2017:as2',
    'to': [as2.PUBLIC_AUDIENCE],
    'cc': [
        'https://orig/author',
        'https://orig/recipient',
        as2.PUBLIC_AUDIENCE,
        'https://orig/bystander',
    ],
    'actor': ACTOR_AS2,
}


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.get_or_create('a')

        self.orig_html_as2 = requests_response("""\
<html>
<meta>
<link href='https://orig/atom' rel='alternate' type='application/atom+xml'>
<link href='https://orig/as2' rel='alternate' type='application/activity+json'>
</meta>
</html>
""", url='https://orig/post', content_type=CONTENT_TYPE_HTML)
        self.orig_html_atom = requests_response("""\
<html>
<meta>
<link href='https://orig/atom' rel='alternate' type='application/atom+xml'>
</meta>
</html>
""", url='https://orig/post', content_type=CONTENT_TYPE_HTML)
        self.orig_atom = requests_response("""\
<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <id>tag:fed.brid.gy,2017-08-22:orig-post</id>
  <link rel="salmon" href="https://orig/salmon"/>
  <content type="html">baz ☕ baj</content>
</entry>
""", content_type=atom.CONTENT_TYPE)
        self.orig_as2_data = {
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'id': 'tag:orig,2017:as2',
            'content': 'Lots of ☕ words...',
            'actor': {'url': 'https://orig/author'},
            'to': ['https://orig/recipient', as2.PUBLIC_AUDIENCE],
            'cc': ['https://orig/bystander', as2.PUBLIC_AUDIENCE],
        }
        self.orig_as2 = requests_response(
            self.orig_as2_data, url='https://orig/as2',
            content_type=as2.CONTENT_TYPE + '; charset=utf-8')

        self.reply_html = """\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="http://a/reply"></a>
<p class="e-content p-name">
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://orig/post">foo ☕ bar</a>
<a href="http://localhost/"></a>
</p>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
</div>
</body>
</html>
"""
        self.reply = requests_response(
            self.reply_html, content_type=CONTENT_TYPE_HTML)
        self.reply_mf2 = util.parse_mf2(self.reply_html, url='http://a/reply')
        self.reply_as1 = microformats2.json_to_object(self.reply_mf2['items'][0])

        self.repost_html = REPOST_HTML
        self.repost = requests_response(
            self.repost_html, content_type=CONTENT_TYPE_HTML)
        self.repost_mf2 = util.parse_mf2(self.repost_html, url='http://a/repost')
        self.repost_as1 = microformats2.json_to_object(self.repost_mf2['items'][0])
        self.repost_as2 = REPOST_AS2

        self.like_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/like"></a>
<a class="u-like-of" href="https://orig/post"></a>
<!--<a class="u-like-of p-name" href="https://orig/post">liked!</a>-->
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.like = requests_response(
            self.like_html, content_type=CONTENT_TYPE_HTML)
        self.like_mf2 = util.parse_mf2(self.like_html, url='http://a/like')

        self.actor = requests_response({
            'objectType' : 'Person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }, content_type=as2.CONTENT_TYPE)

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/http://a/reply#bridgy-fed-create',
            'actor': {
                'id': 'http://localhost/a',
                'url': 'http://localhost/r/https://a/',
                'preferredUsername': 'a',
            },
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/http://a/reply',
                'url': 'http://localhost/r/http://a/reply',
                'name': 'foo ☕ bar',
                'content': """\
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://orig/post">foo ☕ bar</a>
<a href="http://localhost/"></a>""",
                'inReplyTo': 'tag:orig,2017:as2',
                'to': [as2.PUBLIC_AUDIENCE],
                'cc': [
                    'https://orig/author',
                    'https://orig/recipient',
                    as2.PUBLIC_AUDIENCE,
                    'https://orig/bystander',
                ],
                'attributedTo': [ACTOR_AS2],
                'tag': [{
                    'type': 'Mention',
                    'href': 'https://orig/author',
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
<a class="u-url" href="http://a/follow"></a>
<a class="u-follow-of" href="http://followee"></a>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.follow = requests_response(
            self.follow_html, content_type=CONTENT_TYPE_HTML)
        self.follow_mf2 = util.parse_mf2(self.follow_html, url='http://a/follow')
        self.follow_as1 = microformats2.json_to_object(self.follow_mf2['items'][0])
        self.follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': 'http://localhost/r/http://a/follow',
            'url': 'http://localhost/r/http://a/follow',
            'object': 'http://followee',
            'actor': ACTOR_AS2,
            'to': [as2.PUBLIC_AUDIENCE],
        }

        self.follow_fragment_html = """\
<html>
<body>
<article class=h-entry id=1>
<h1>Ignored</h1>
</article>
<article class=h-entry id=2>
<a class="u-url" href="http://a/follow#2"></a>
<a class="u-follow-of" href="http://followee"></a>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</article>
</body>
</html>
"""
        self.follow_fragment = requests_response(
            self.follow_fragment_html, content_type=CONTENT_TYPE_HTML)
        self.follow_fragment_mf2 = util.parse_mf2(
            self.follow_fragment_html, url='http://a/follow', id='2')
        self.follow_fragment_as1 = microformats2.json_to_object(
            self.follow_fragment_mf2['items'][0])
        self.follow_fragment_as2 = copy.deepcopy(self.follow_as2)
        self.follow_fragment_as2.update({
            'id': 'http://localhost/r/http://a/follow#2',
            'url': 'http://localhost/r/http://a/follow#2',
        })

        self.create_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://orig/post"></a>
<p class="e-content p-name">hello i am a post</p>
<a class="p-author h-card" href="https://orig">
  <p class="p-name">Ms. ☕ <span class="p-nickname">Baz</span></p>
</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.create = requests_response(
            self.create_html, content_type=CONTENT_TYPE_HTML)
        self.create_mf2 = util.parse_mf2(self.create_html, url='http://a/create')
        self.create_as1 = microformats2.json_to_object(self.create_mf2['items'][0])
        self.create_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/https://orig/post#bridgy-fed-create',
            'actor': {
                'id': 'http://localhost/orig',
                'url': 'http://localhost/r/https://orig/',
                'preferredUsername': 'orig',
            },
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/https://orig/post',
                'url': 'http://localhost/r/https://orig/post',
                'name': 'hello i am a post',
                'content': 'hello i am a post',
                'attributedTo': [ACTOR_AS2],
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
        self.activitypub_gets = [self.reply, self.not_fediverse, self.orig_as2,
                                 self.actor]

        self.author = requests_response(ACTOR_HTML, url='https://orig/',
                                        content_type=CONTENT_TYPE_HTML)

    def assert_object(self, id, **props):
        got = Object.get_by_id(id)
        assert got, id

        # sort keys in JSON properties
        for prop in 'as1', 'as2', 'bsky', 'mf2':
            if prop in props:
                props[prop] = json_dumps(json_loads(props[prop]), sort_keys=True)
            got_val = getattr(got, prop, None)
            if got_val:
                setattr(got, prop, json_dumps(json_loads(got_val), sort_keys=True))

        self.assert_entities_equal(Object(id=id, **props), got,
                                   ignore=['created', 'updated'])

    def assert_deliveries(self, mock_post, inboxes, data):
        self.assertEqual(len(inboxes), len(mock_post.call_args_list))
        calls = {call[0][0]: call for call in mock_post.call_args_list}

        for inbox in inboxes:
            with self.subTest(inbox=inbox):
                got = json_loads(calls[inbox][1]['data'])
                got.get('object', {}).pop('publicKey', None)
                self.assertEqual(data, got)

    def test_bad_source_url(self, mock_get, mock_post):
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

        got = self.client.post('/webmention', data={'source': 'http://a/post'})
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
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_no_targets(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body class="h-entry">
<p class="e-content">no one to send to! <a href="http://localhost/"></a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_bad_target_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('https://orig/post', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            ValueError('foo bar'),
        )

        got = self.client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_target_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('https://orig/post', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            requests.Timeout('foo bar'))

        got = self.client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(502, got.status_code)

    def test_target_fetch_has_no_content_type(self, mock_get, mock_post):
        html = self.reply_html.replace(
            '</body>',
            "<link href='http://as2' rel='alternate' type='application/activity+json'></body")
        mock_get.side_effect = (
            requests_response(self.reply_html),
            # http://not/fediverse
            requests_response(self.reply_html, content_type='None'),
        )
        got = self.client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(502, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_no_backlink(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>', ''),
                                    content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_backlink_without_trailing_slash(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>',
                                    '<a href="http://localhost"></a>'),
            content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

    def test_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://orig/post'),
            self.as2_req('https://orig/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        self.assert_object('http://a/reply',
                           domains=['a'],
                           source_protocol='activitypub',
                           status='complete',
                           ap_delivered=['https://foo.com/inbox'],
                           ap_undelivered=[],
                           ap_failed=[],
                           mf2=json_dumps(self.reply_mf2),
                           as1=json_dumps(self.reply_as1),
                           )

    def test_update_reply(self, mock_get, mock_post):
        Object(id='http://a/reply', status='complete', as1='{}').put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_update, json_loads(kwargs['data']))

    def test_redo_repost_isnt_update(self, mock_get, mock_post):
        """Like and Announce shouldn't use Update, they should just resend as is."""
        Object(id='http://a/repost', status='complete', as1='{}').put()

        mock_get.side_effect = [self.repost, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.repost_as2, json_loads(kwargs['data']))

    def test_skip_update_if_content_unchanged(self, mock_get, mock_post):
        """https://github.com/snarfed/bridgy-fed/issues/78"""
        Object(id='http://a/reply', status='complete',
               as1=json_dumps(self.reply_as1)).put()
        mock_get.side_effect = self.activitypub_gets

        got = self.client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_post.assert_not_called()

    def test_create_reply_attributed_to_id_only(self, mock_get, mock_post):
        """Based on PeerTube's AS2.

        https://github.com/snarfed/bridgy-fed/issues/40
        """
        del self.orig_as2_data['actor']
        self.orig_as2_data['attributedTo'] = [{
            'type': 'Person',
            'id': 'https://orig/author',
        }]
        orig_as2_resp = requests_response(
            self.orig_as2_data, content_type=as2.CONTENT_TYPE + '; charset=utf-8')

        mock_get.side_effect = [self.reply, self.not_fediverse, orig_as2_resp,
                                self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://orig/post'),
            self.as2_req('https://orig/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

    def test_create_repost(self, mock_get, mock_post):
        mock_get.side_effect = [self.repost, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/repost'),
            self.as2_req('https://orig/post'),
            self.as2_req('https://orig/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.repost_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        for args, kwargs in mock_get.call_args_list[1:]:
            with self.subTest(url=args[0]):
                rsa_key = kwargs['auth'].header_signer._rsa._key
                self.assertEqual(default_signature_user().private_pem(),
                                 rsa_key.exportKey())

        self.assert_object('http://a/repost',
                           domains=['a'],
                           source_protocol='activitypub',
                           status='complete',
                           mf2=json_dumps(self.repost_mf2),
                           as1=json_dumps(self.repost_as1),
                           ap_delivered=['https://foo.com/inbox'],
                           )

    def test_link_rel_alternate_as2(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.not_fediverse,
                                self.orig_html_as2, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://orig/post'),
            self.as2_req('https://orig/as2', headers=as2.CONNEG_HEADERS),
            self.as2_req('https://orig/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

    def test_create_default_url_to_wm_source(self, mock_get, mock_post):
        """Source post has no u-url. AS2 id should default to webmention source."""
        missing_url = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://orig/post">reposted!</a>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [missing_url, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assert_equals(self.repost_as2, json_loads(kwargs['data']))

    def test_create_author_only_url(self, mock_get, mock_post):
        """Mf2 author property is just a URL. We should run full authorship.

        https://indieweb.org/authorship
        """
        repost = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://orig/post">reposted!</a>
<a class="u-author" href="https://orig"></a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost, self.author, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=201)

        got = self.client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(201, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assert_equals(self.repost_as2, json_loads(kwargs['data']))

    @mock.patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_create_post_make_task(self, mock_create_task, mock_get, _):
        mock_get.side_effect = [self.create, self.actor]

        got = self.client.post('/webmention', data={
            'source': 'https://orig/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(202, got.status_code)
        mock_create_task.assert_called_with(
            parent=f'projects/{APP_ID}/locations/{TASKS_LOCATION}/queues/webmention',
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': '/_ah/queue/webmention',
                    'body': urlencode({'source': 'https://orig/post'}).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            },
        )

    def test_create_post_run_task(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        # Object(id='https://orig/post', domains=['orig'],
        #        status='complete', mf2=json_dumps(self.create_mf2),
        #        as1=json_dumps(self.create_as1)).put()

        # different_create_mf2 = copy.deepcopy(self.create_mf2)
        # different_create_mf2['items'][0]['properties']['content'][0]['value'] += ' different'
        # different_create_as1 = copy.deepcopy(self.create_as1)
        # different_create_as1['content'] += ' different'
        # Object(id='https://orig/post', domains=['orig'],
        #          status='complete', source_protocol='activitypub',
        #          mf2=json_dumps(different_create_mf2),
        #          as1=json_dumps(different_create_as1)).put()

        Follower.get_or_create('orig', 'https://mastodon/aaa')
        Follower.get_or_create('orig', 'https://mastodon/bbb',
                               last_follow=json_dumps({'actor': {
                                   'publicInbox': 'https://public/inbox',
                                   'inbox': 'https://unused',
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ccc',
                               last_follow=json_dumps({'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ddd',
                               last_follow=json_dumps({'actor': {
                                   'inbox': 'https://inbox',
                               }}))
        # TODO
        # # already sent, should be skipped
        # Follower.get_or_create('orig', 'https://mastodon/eee',
        #                        last_follow=json_dumps({'actor': {
        #                            'inbox': 'https://skipped/inbox',
        #                        }}))
        # changed, should still be sent
        Follower.get_or_create('orig', 'https://mastodon/fff',
                               last_follow=json_dumps({'actor': {
                                   'inbox': 'https://updated/inbox',
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ggg',
                               status='inactive',
                               last_follow=json_dumps({'actor': {
                                   'inbox': 'https://unused/2',
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/hhh',
                               last_follow=json_dumps({'actor': {
                                   # dupe of eee; should be de-duped
                                   'inbox': 'https://inbox',
                               }}))

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://orig/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://orig/post'),
        ))

        inboxes = ('https://inbox', 'https://public/inbox',
                   'https://shared/inbox', 'https://updated/inbox')
        self.assert_deliveries(mock_post, inboxes, self.create_as2)
                    # TODO
                    # self.update_as2 if inbox == 'https://updated/inbox' else

        self.assert_object(f'https://orig/post',
                           domains=['orig'],
                           source_protocol='activitypub',
                           status='complete',
#(different_create_mf2 if inbox == 'https://updated/inbox' else
                           mf2=json_dumps(self.create_mf2),
                           as1=json_dumps(self.create_as1),
                           ap_delivered=inboxes,
                           )
#(different_create_as1 if inbox == 'https://updated/inbox' else
    def test_create_with_image(self, mock_get, mock_post):
        create_html = self.create_html.replace(
            '</body>', '<img class="u-photo" src="http://im/age" />\n</body>')
        mock_get.side_effect = [
            requests_response(create_html, content_type=CONTENT_TYPE_HTML),
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz ')

        Follower.get_or_create(
            'orig', 'https://mastodon/aaa',
            last_follow=json_dumps({'actor': {'inbox': 'https://inbox'}}))

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://orig/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        self.assertEqual(('https://inbox',), mock_post.call_args[0])
        create = copy.deepcopy(self.create_as2)
        create['object'].update({
            'image': {'url': 'http://im/age', 'type': 'Image'},
            'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
        })
        self.assertEqual(create, json_loads(mock_post.call_args[1]['data']))

    def test_follow(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/follow'),
            self.as2_req('http://followee/'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        self.assert_object('http://a/follow',
                           domains=['a'],
                           source_protocol='activitypub',
                           status='complete',
                           mf2=json_dumps(self.follow_mf2),
                           as1=json_dumps(self.follow_as1),
                           ap_delivered=['https://foo.com/inbox'],
                           )

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual('https://foo.com/about-me a', followers[0].key.id())
        self.assertEqual('a', followers[0].src)
        self.assertEqual('https://foo.com/about-me', followers[0].dest)
        self.assertEqual(self.follow_as2, json_loads(followers[0].last_follow))

    def test_follow_no_actor(self, mock_get, mock_post):
        self.user.actor_as2 = json_dumps(self.follow_as2['actor'])
        self.user.put()

        html = self.follow_html.replace(
            '<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>', '')
        follow = requests_response(html, content_type=CONTENT_TYPE_HTML)

        mock_get.side_effect = [follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        expected = self.follow_as2
        expected['actor'] = 'http://localhost/a'
        self.assertEqual(expected, json_loads(kwargs['data']))

    def test_follow_fragment(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow_fragment, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/webmention', data={
            'source': 'http://a/follow#2',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/follow#2'),
            self.as2_req('http://followee/'),
        ))

        args, kwargs = mock_post.call_args
        self.assert_equals(('https://foo.com/inbox',), args)
        self.assert_equals(self.follow_fragment_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assert_equals(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assert_equals(self.user.private_pem(), rsa_key.exportKey())

        self.assert_object('http://a/follow#2',
                           domains=['a'],
                           source_protocol='activitypub',
                           status='complete',
                           mf2=json_dumps(self.follow_fragment_mf2),
                           as1=json_dumps(self.follow_fragment_as1),
                           ap_delivered=['https://foo.com/inbox'],
                           )

        followers = Follower.query().fetch()
        self.assert_equals(1, len(followers))
        self.assert_equals('https://foo.com/about-me a', followers[0].key.id())
        self.assert_equals('a', followers[0].src)
        self.assert_equals('https://foo.com/about-me', followers[0].dest)

    def test_error_fragment_missing(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow_fragment]

        got = self.client.post('/webmention', data={
            'source': 'http://a/follow#3',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(400, got.status_code)

    def test_error(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response(
            'abc xyz', status=405, url='https://foo.com/inbox')

        got = self.client.post('/webmention', data={
            'source': 'http://a/follow',
            'target': 'https://fed.brid.gy/',
        })
        body = got.get_data(as_text=True)
        self.assertEqual(502, got.status_code, body)
        self.assertIn(
            '405 Client Error: None for url: https://foo.com/inbox ; abc xyz',
            body)

        mock_get.assert_has_calls((
            self.req('http://a/follow'),
            self.as2_req('http://followee/'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(as2.CONTENT_TYPE, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        self.assert_object('http://a/follow',
                           domains=['a'],
                           source_protocol='activitypub',
                           status='failed',
                           mf2=json_dumps(self.follow_mf2),
                           as1=json_dumps(self.follow_as1),
                           ap_failed=['https://foo.com/inbox'],
                          )

    def test_repost_blocklisted_error(self, mock_get, mock_post):
        """Reposts of non-fediverse (ie blocklisted) sites aren't yet supported."""
        repost_html = REPOST_HTML.replace('https://orig/post', 'https://twitter.com/foo')
        repost_resp = requests_response(repost_html, content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost_resp]

        got = self.client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)

    @mock.patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_update_profile_make_task(self, mock_create_task, mock_get, _):
        mock_get.side_effect = [self.author]

        got = self.client.post('/webmention', data={
            'source': 'https://orig/',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(202, got.status_code)
        mock_create_task.assert_called_with(
            parent=f'projects/{APP_ID}/locations/{TASKS_LOCATION}/queues/webmention',
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': '/_ah/queue/webmention',
                    'body': urlencode({'source': 'https://orig/'}).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            },
        )

    def test_update_profile_run_task(self, mock_get, mock_post):
        mock_get.side_effect = [self.author]
        mock_post.return_value = requests_response('abc xyz')
        Follower.get_or_create('orig', 'https://mastodon/ccc',
                               last_follow=json_dumps({'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ddd',
                               last_follow=json_dumps({'actor': {
                                   'inbox': 'https://inbox',
                               }}))

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://orig/',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_get.assert_has_calls((
            self.req('https://orig/'),
        ))

        self.assert_deliveries(mock_post, ('https://shared/inbox', 'https://inbox'), {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Update',
            'id': 'http://localhost/r/https://orig/#update-2022-01-02T03:04:05+00:00',
            'actor': 'http://localhost/orig',
            'object': {
                **ACTOR_AS2_FULL,
                'updated': util.now().isoformat(),
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        })

        expected_as1 = {
            'id': 'https://orig/#update-2022-01-02T03:04:05+00:00',
            'objectType': 'activity',
            'verb': 'update',
            'object': ACTOR_AS1_UNWRAPPED,
        }
        self.assert_object(f'https://orig/',
                           domains=['orig'],
                           source_protocol='activitypub',
                           status='complete',
                           mf2=json_dumps(ACTOR_MF2),
                           as1=json_dumps(expected_as1),
                           ap_delivered=['https://inbox', 'https://shared/inbox'],
                           )
