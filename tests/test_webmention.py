# coding=utf-8
"""Unit tests for webmention.py.

TODO: test error handling
"""
import copy
from unittest import mock
from urllib.parse import urlencode

from django_salmon import magicsigs, utils
import feedparser
from granary import atom, microformats2
from httpsig.sign import HeaderSigner
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

import activitypub
from app import app
from common import (
    AS2_PUBLIC_AUDIENCE,
    CONNEG_HEADERS_AS2,
    CONNEG_HEADERS_AS2_HTML,
    CONTENT_TYPE_AS2,
    CONTENT_TYPE_ATOM,
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_MAGIC_ENVELOPE,
    HEADERS,
)
from models import Follower, MagicKey, Response
import webmention
from . import testutil

REPOST_HTML = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/repost"></a>
<a class="u-repost-of p-name" href="http://orig/post">reposted!</a>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
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
    'cc': [
        AS2_PUBLIC_AUDIENCE,
        'http://orig/author',
        'http://orig/recipient',
        'http://orig/bystander',
    ],
    'actor': {
        'type': 'Person',
        'id': 'http://localhost/orig',
        'url': 'http://localhost/r/http://orig',
        'name': 'Ms. ☕ Baz',
        'preferredUsername': 'orig',
    },
}

client = app.test_client()


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):
    def setUp(self):
        super(WebmentionTest, self).setUp()
        self.key = MagicKey.get_or_create('a')
        app.testing = True

        self.orig_html_as2 = requests_response("""\
<html>
<meta>
<link href='http://orig/atom' rel='alternate' type='application/atom+xml'>
<link href='http://orig/as2' rel='alternate' type='application/activity+json'>
</meta>
</html>
""", url='http://orig/post', content_type=CONTENT_TYPE_HTML)
        self.orig_html_atom = requests_response("""\
<html>
<meta>
<link href='http://orig/atom' rel='alternate' type='application/atom+xml'>
</meta>
</html>
""", url='http://orig/post', content_type=CONTENT_TYPE_HTML)
        self.orig_atom = requests_response("""\
<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <id>tag:fed.brid.gy,2017-08-22:orig-post</id>
  <link rel="salmon" href="http://orig/salmon"/>
  <content type="html">baz ☕ baj</content>
</entry>
""", content_type=CONTENT_TYPE_ATOM)
        self.orig_as2_data = {
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'id': 'tag:orig,2017:as2',
            'content': 'Lots of ☕ words...',
            'actor': {'url': 'http://orig/author'},
            'to': ['http://orig/recipient'],
            'cc': ['http://orig/bystander', AS2_PUBLIC_AUDIENCE],
        }
        self.orig_as2 = requests_response(
            self.orig_as2_data, url='http://orig/as2',
            content_type=CONTENT_TYPE_AS2 + '; charset=utf-8')

        self.reply_html = """\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="http://a/reply"></a>
<p class="e-content p-name">
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>
<a href="http://localhost/"></a>
</p>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
</div>
</body>
</html>
"""
        self.reply = requests_response(
            self.reply_html, content_type=CONTENT_TYPE_HTML)
        self.reply_mf2 = util.parse_mf2(self.reply_html, url='http://a/reply')

        self.repost_html = REPOST_HTML
        self.repost = requests_response(
            self.repost_html, content_type=CONTENT_TYPE_HTML)
        self.repost_mf2 = util.parse_mf2(self.repost_html, url='http://a/repost')
        self.repost_as2 = REPOST_AS2

        self.like_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/like"></a>
<a class="u-like-of" href="http://orig/post"></a>
<!--<a class="u-like-of p-name" href="http://orig/post">liked!</a>-->
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.like = requests_response(
            self.like_html, content_type=CONTENT_TYPE_HTML)
        self.like_mf2 = util.parse_mf2(self.like_html, url='http://a/like')

        self.actor = requests_response({
            'objectType' : 'person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }, content_type=CONTENT_TYPE_AS2)

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/http://a/reply#bridgy-fed-create',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/http://a/reply',
                'url': 'http://localhost/r/http://a/reply',
                'name': 'foo ☕ bar',
                'content': """\
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>
<a href="http://localhost/"></a>""",
                'inReplyTo': 'tag:orig,2017:as2',
                'cc': [
                    AS2_PUBLIC_AUDIENCE,
                    'http://orig/author',
                    'http://orig/recipient',
                    'http://orig/bystander',
                ],
                'attributedTo': [{
                    'type': 'Person',
                    'id': 'http://localhost/orig',
                    'url': 'http://localhost/r/http://orig',
                    'preferredUsername': 'orig',
                    'name': 'Ms. ☕ Baz',
                }],
                'tag': [{
                    'type': 'Mention',
                    'href': 'http://orig/author',
                }],
            },
        }
        self.as2_update = copy.deepcopy(self.as2_create)
        self.as2_update['type'] = 'Update'

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
        self.follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': 'http://localhost/r/http://a/follow',
            'url': 'http://localhost/r/http://a/follow',
            'object': 'http://followee',
            'actor': {
                'id': 'http://localhost/orig',
                'name': 'Ms. ☕ Baz',
                'preferredUsername': 'orig',
                'type': 'Person',
                'url': 'http://localhost/r/https://orig',
            },
            'cc': ['https://www.w3.org/ns/activitystreams#Public'],
        }

        self.create_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://orig/post"></a>
<p class="e-content p-name">hello i am a post</p>
<a class="p-author h-card" href="https://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.create = requests_response(
            self.create_html, content_type=CONTENT_TYPE_HTML)
        self.create_mf2 = util.parse_mf2(self.create_html, url='http://a/create')
        self.create_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/http://orig/post#bridgy-fed-create',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/http://orig/post',
                'url': 'http://localhost/r/http://orig/post',
                'name': 'hello i am a post',
                'content': 'hello i am a post',
                'attributedTo': [{
                    'type': 'Person',
                    'id': 'http://localhost/orig',
                    'url': 'http://localhost/r/https://orig',
                    'name': 'Ms. ☕ Baz',
                    'preferredUsername': 'orig',
                }],
                'cc': ['https://www.w3.org/ns/activitystreams#Public'],
            },
        }

        self.not_fediverse = requests_response("""\
<html>
<body>foo</body>
</html>
""", url='http://not/fediverse', content_type=CONTENT_TYPE_HTML)
        self.activitypub_gets = [self.reply, self.not_fediverse, self.orig_as2,
                                 self.actor]

    def verify_salmon(self, mock_post):
        args, kwargs = mock_post.call_args
        self.assertEqual(('http://orig/salmon',), args)
        self.assertEqual(CONTENT_TYPE_MAGIC_ENVELOPE,
                         kwargs['headers']['Content-Type'])

        env = utils.parse_magic_envelope(kwargs['data'])
        assert magicsigs.verify(env['data'], env['sig'].encode(), key=self.key)

        return env['data']

    def test_bad_source_url(self, mock_get, mock_post):
        got = client.post('/webmention', data=b'')
        self.assertEqual(400, got.status_code)

        mock_get.side_effect = ValueError('foo bar')
        got = client.post('/webmention', data={'source': 'bad'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Response.query().count())

    def test_no_source_entry(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body>
<p>nothing to see here except <a href="http://localhost/">link</a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = client.post( '/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Response.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_no_targets(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body class="h-entry">
<p class="e-content">no one to send to! <a href="http://localhost/"></a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = client.post('/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        self.assertEqual(0, Response.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_bad_target_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('http://orig/post', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            ValueError('foo bar'))

        got = client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Response.query().count())

    def test_source_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html.replace('http://orig/post', 'bad'),
                              content_type=CONTENT_TYPE_HTML),
            requests.Timeout('foo bar'))

        got = client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(502, got.status_code)

    def test_source_fetch_has_no_content_type(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html),
            requests_response(self.reply_html, content_type='None')
        )
        got = client.post('/webmention', data={'source': 'http://a/post'})
        self.assertEqual(502, got.status_code)
        self.assertEqual(0, Response.query().count())

    def test_no_backlink(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>', ''),
                                    content_type=CONTENT_TYPE_HTML)

        got = client.post('/webmention', data={
            'source': 'http://a/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Response.query().count())

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_activitypub_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://not/fediverse', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/reply http://orig/as2')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.reply_mf2, json_loads(resp.source_mf2))

        # TODO: if i do this, maybe switch to separate HttpRequest model and
        # foreign key
        # self.assertEqual([self.as2_create], resp.request_statuses)
        # self.assertEqual([self.as2_create], resp.requests)
        # self.assertEqual(['abc xyz'], resp.responses)

    def test_activitypub_update_reply(self, mock_get, mock_post):
        Response(id='http://a/reply http://orig/as2', status='complete').put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_update, json_loads(kwargs['data']))

    def test_activitypub_create_reply_attributed_to_id_only(self, mock_get, mock_post):
        """Based on PeerTube's AS2.

        https://github.com/snarfed/bridgy-fed/issues/40
        """
        del self.orig_as2_data['actor']
        self.orig_as2_data['attributedTo'] = [{
            'type': 'Person',
            'id': 'http://orig/author',
        }]
        orig_as2_resp = requests_response(
            self.orig_as2_data, content_type=CONTENT_TYPE_AS2 + '; charset=utf-8')

        mock_get.side_effect = [self.reply, self.not_fediverse, orig_as2_resp,
                                self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://not/fediverse', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

    def test_activitypub_update_reply(self, mock_get, mock_post):
        Response(id='http://a/reply http://orig/as2', status='complete').put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_update, json_loads(kwargs['data']))

    def test_activitypub_create_repost(self, mock_get, mock_post):
        mock_get.side_effect = [self.repost, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/repost'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.repost_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/repost http://orig/as2')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.repost_mf2, json_loads(resp.source_mf2))

    def test_activitypub_link_rel_alternate_as2(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.not_fediverse,
                                self.orig_html_as2, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://not/fediverse', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/as2', headers=CONNEG_HEADERS_AS2),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, json_loads(kwargs['data']))

    def test_activitypub_create_default_url_to_wm_source(self, mock_get, mock_post):
        """Source post has no u-url. AS2 id should default to webmention source."""
        missing_url = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="http://orig/post">reposted!</a>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [missing_url, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assert_equals(self.repost_as2, json_loads(kwargs['data']))

    def test_activitypub_create_author_only_url(self, mock_get, mock_post):
        """Mf2 author property is just a URL. We should run full authorship.

        https://indieweb.org/authorship
        """
        repost = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="http://orig/post">reposted!</a>
<a class="u-author" href="http://orig"></a>
<a href="http://localhost/"></a>
</body>
</html>
""", content_type=CONTENT_TYPE_HTML)
        author = requests_response("""\
<html>
<body class="h-card">
<a class="p-name u-url" rel="me" href="http://orig">Ms. ☕ Baz</a>
<img class="u-photo" src="/pic" />
</body>
</html>
""", url='http://orig', content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost, author, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=201)

        got = client.post('/webmention', data={
            'source': 'http://a/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(201, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)

        repost_as2 = copy.deepcopy(self.repost_as2)
        repost_as2['actor']['image'] = repost_as2['actor']['icon'] = \
            {'type': 'Image', 'url': 'http://orig/pic'},
        self.assert_equals(repost_as2, json_loads(kwargs['data']))

    def test_activitypub_create_post(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')

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
        Follower.get_or_create('orig', 'https://mastodon/eee',
                               status='inactive',
                               last_follow=json_dumps({'actor': {
                                   'inbox': 'https://unused/2',
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/fff',
                               last_follow=json_dumps({'actor': {
                                   # dupe of eee; should be de-duped
                                   'inbox': 'https://inbox',
                               }}))

        got = client.post('/webmention', data={
            'source': 'http://orig/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://orig/post'),
        ))

        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
        self.assertEqual(len(inboxes), len(mock_post.call_args_list))
        for call, inbox in zip(mock_post.call_args_list, inboxes):
            self.assertEqual((inbox,), call[0])
            self.assertEqual(self.create_as2, json_loads(call[1]['data']))

        for inbox in inboxes:
            resp = Response.get_by_id('http://orig/post %s' % inbox)
            self.assertEqual('out', resp.direction, inbox)
            self.assertEqual('activitypub', resp.protocol, inbox)
            self.assertEqual('complete', resp.status, inbox)
            self.assertEqual(self.create_mf2, json_loads(resp.source_mf2), inbox)

    def test_activitypub_create_with_image(self, mock_get, mock_post):
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

        got = client.post('/webmention', data={
            'source': 'http://orig/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        self.assertEqual(('https://inbox',), mock_post.call_args[0])
        create = copy.deepcopy(self.create_as2)
        create['object'].update({
            'image': [{'url': 'http://im/age', 'type': 'Image'}],
            'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
        })
        self.assertEqual(create, json_loads(mock_post.call_args[1]['data']))

    def test_activitypub_follow(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = client.post('/webmention', data={
            'source': 'http://a/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/follow'),
            self.req('http://followee/', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/follow http://followee/')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.follow_mf2, json_loads(resp.source_mf2))

    def test_activitypub_error_no_salmon_fallback(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response(
            'abc xyz', status=405, url='https://foo.com/inbox')

        got = client.post('/webmention', data={
            'source': 'http://a/follow',
            'target': 'https://fed.brid.gy/',
        })
        body = got.get_data(as_text=True)
        self.assertEqual(502, got.status_code, body)
        self.assertEqual(
            '405 Client Error: None for url: https://foo.com/inbox ; abc xyz',
            body)

        mock_get.assert_has_calls((
            self.req('http://a/follow'),
            self.req('http://followee/', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.follow_as2, json_loads(kwargs['data']))

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/follow http://followee/')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('error', resp.status)
        self.assertEqual(self.follow_mf2, json_loads(resp.source_mf2))

    def test_salmon_reply(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.not_fediverse,
                                self.orig_html_atom, self.orig_atom]

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://not/fediverse', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/atom'),
        ))

        data = self.verify_salmon(mock_post)
        parsed = feedparser.parse(data)
        entry = parsed.entries[0]

        self.assertEqual('http://a/reply', entry['id'])
        self.assertIn({
            'rel': 'alternate',
            'href': 'http://a/reply',
            'type': 'text/html',
        }, entry['links'])
        self.assertEqual({
            'type': 'text/html',
            'href': 'http://orig/post',
            'ref': 'tag:fed.brid.gy,2017-08-22:orig-post',
        }, entry['thr_in-reply-to'])
        self.assertEqual("""\
<a class="u-in-reply-to" href="http://not/fediverse"></a><br />
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a><br />
<a href="http://localhost/"></a>""",
            entry.content[0]['value'])

        resp = Response.get_by_id('http://a/reply http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.reply_mf2, json_loads(resp.source_mf2))

    def test_salmon_like(self, mock_get, mock_post):
        mock_get.side_effect = [self.like, self.orig_html_atom, self.orig_atom]

        got = client.post('/webmention', data={
            'source': 'http://a/like',
            'target': 'http://orig/post',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('http://a/like'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/atom'),
        ))

        data = self.verify_salmon(mock_post)
        parsed = feedparser.parse(data)
        entry = parsed.entries[0]

        self.assertEqual('http://a/like', entry['id'])
        self.assertIn({
            'rel': 'alternate',
            'href': 'http://a/like',
            'type': 'text/html',
        }, entry['links'])
        self.assertEqual('http://orig/post', entry['activity_object'])

        resp = Response.get_by_id('http://a/like http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.like_mf2, json_loads(resp.source_mf2))

    def test_salmon_get_salmon_from_webfinger(self, mock_get, mock_post):
        orig_atom = requests_response("""\
<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <author>
    <name>ryan</name>
    <email>ryan@orig</email>
  </author>
  <id>tag:fed.brid.gy,2017-08-22:orig-post</id>
</entry>
""")
        webfinger = requests_response({
            'subject': 'acct:ryan@orig',
            'links': [{
                'rel': 'salmon',
                'href': 'http://orig/@ryan/salmon',
            }],
        })
        mock_get.side_effect = [self.reply, self.not_fediverse,
                                self.orig_html_atom, orig_atom, webfinger]

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_any_call(
            'http://orig/.well-known/webfinger?resource=acct:ryan@orig',
            headers=HEADERS, stream=True, timeout=util.HTTP_TIMEOUT)
        self.assertEqual(('http://orig/@ryan/salmon',), mock_post.call_args[0])

    def test_salmon_no_target_atom(self, mock_get, mock_post):
        orig_no_atom = requests_response("""\
<html>
<body>foo</body>
</html>""", 'http://orig/url')
        mock_get.side_effect = [self.reply, self.not_fediverse, orig_no_atom]

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        })
        self.assertEqual(400, got.status_code)
        self.assertIn('Target post http://orig/url has no Atom link',
                      got.get_data(as_text=True))

        resp = Response.get_by_id('http://a/reply http://orig/url')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('error', resp.status)

    def test_salmon_relative_atom_href(self, mock_get, mock_post):
        orig_relative = requests_response("""\
<html>
<meta>
<link href='atom/1' rel='alternate' type='application/atom+xml'>
</meta>
</html>""", 'http://orig/url')
        mock_get.side_effect = [self.reply, self.not_fediverse, orig_relative,
                                self.orig_atom]

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_any_call('http://orig/atom/1', headers=HEADERS,
                                 stream=True, timeout=util.HTTP_TIMEOUT)
        data = self.verify_salmon(mock_post)

    def test_salmon_relative_atom_href_with_base(self, mock_get, mock_post):
        orig_base = requests_response("""\
<html>
<meta>
<base href='/base/'>
<link href='atom/1' rel='alternate' type='application/atom+xml'>
</meta>
</html>""", 'http://orig/url')
        mock_get.side_effect = [self.reply, self.not_fediverse, orig_base,
                                self.orig_atom]

        got = client.post('/webmention', data={
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_any_call('http://orig/base/atom/1', headers=HEADERS,
                                 stream=True, timeout=util.HTTP_TIMEOUT)
        data = self.verify_salmon(mock_post)
