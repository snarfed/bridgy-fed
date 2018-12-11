# coding=utf-8
"""Unit tests for webmention.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import json
import urllib
import urllib2

from django_salmon import magicsigs, utils
import feedparser
from granary import atom, microformats2
from httpsig.sign import HeaderSigner
import mf2py
import mock
from mock import call
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
import requests

import activitypub
from common import (
    AS2_PUBLIC_AUDIENCE,
    CONNEG_HEADERS_AS2,
    CONNEG_HEADERS_AS2_HTML,
    CONTENT_TYPE_AS2,
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_MAGIC_ENVELOPE,
    HEADERS,
)
from models import Follower, MagicKey, Response
import testutil
import webmention
from webmention import app


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):

    def setUp(self):
        super(WebmentionTest, self).setUp()
        self.key = MagicKey.get_or_create('a')

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
""")
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
        self.reply_mf2 = mf2py.parse(self.reply_html, url='http://a/reply')

        self.repost_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/repost"></a>
<a class="u-repost-of p-name" href="http://orig/post">reposted!</a>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.repost = requests_response(
            self.repost_html, content_type=CONTENT_TYPE_HTML)
        self.repost_mf2 = mf2py.parse(self.repost_html, url='http://a/repost')
        self.repost_as2 = {
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
        self.like_mf2 = mf2py.parse(self.like_html, url='http://a/like')

        self.actor = requests_response({
            'objectType' : 'person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }, content_type=CONTENT_TYPE_AS2)
        self.activitypub_gets = [self.reply, self.orig_as2, self.actor]

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://localhost/r/http://a/reply',
                'url': 'http://localhost/r/http://a/reply',
                'name': 'foo ☕ bar',
                'content': '<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>\n<a href="http://localhost/"></a>',
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
        self.follow_mf2 = mf2py.parse(self.follow_html, url='http://a/follow')
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

        self.actor = requests_response({
            'objectType' : 'person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }, content_type=CONTENT_TYPE_AS2)
        self.activitypub_gets = [self.reply, self.orig_as2, self.actor]

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
        self.create_mf2 = mf2py.parse(self.create_html, url='http://a/create')
        self.create_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
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

        self.actor = requests_response({
            'objectType' : 'person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }, content_type=CONTENT_TYPE_AS2)
        self.activitypub_gets = [self.reply, self.orig_as2, self.actor]

    def verify_salmon(self, mock_post):
        args, kwargs = mock_post.call_args
        self.assertEqual(('http://orig/salmon',), args)
        self.assertEqual(CONTENT_TYPE_MAGIC_ENVELOPE,
                         kwargs['headers']['Content-Type'])

        env = utils.parse_magic_envelope(kwargs['data'])
        data = utils.decode(env['data'])
        assert magicsigs.verify(None, data, env['sig'], key=self.key)

        return data

    def test_no_source_entry(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body>
<p>nothing to see here except <a href="http://localhost/">link</a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/post',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(400, got.status_int)

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_no_targets(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body class="h-entry">
<p class="e-content">no one to send to! <a href="http://localhost/"></a></p>
</body>
</html>""", content_type=CONTENT_TYPE_HTML)

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/post',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_no_backlink(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>', ''),
                                    content_type=CONTENT_TYPE_HTML)

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/post',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(400, got.status_int)

        mock_get.assert_has_calls((self.req('http://a/post'),))

    def test_activitypub_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(203, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, kwargs['json'])

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/reply http://orig/as2')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.reply_mf2, json.loads(resp.source_mf2))

        # TODO: if i do this, maybe switch to separate HttpRequest model and
        # foreign key
        # self.assertEqual([self.as2_create], resp.request_statuses)
        # self.assertEqual([self.as2_create], resp.requests)
        # self.assertEqual(['abc xyz'], resp.responses)

    def test_activitypub_update_reply(self, mock_get, mock_post):
        Response(id='http://a/reply http://orig/as2', status='complete').put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_update, kwargs['json'])

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

        mock_get.side_effect = [self.reply, orig_as2_resp, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(203, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, kwargs['json'])

    def test_activitypub_update_reply(self, mock_get, mock_post):
        Response(id='http://a/reply http://orig/as2', status='complete').put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_update, kwargs['json'])

    def test_activitypub_create_repost(self, mock_get, mock_post):
        mock_get.side_effect = [self.repost, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/repost',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/repost'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.repost_as2, kwargs['json'])

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/repost http://orig/as2')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.repost_mf2, json.loads(resp.source_mf2))

    def test_activitypub_link_rel_alternate_as2(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.orig_html_as2, self.orig_as2,
                                self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/as2', headers=CONNEG_HEADERS_AS2),
            self.req('http://orig/author', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, kwargs['json'])

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

        got = app.get_response('/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/repost',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(203, got.status_int)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assert_equals(self.repost_as2, kwargs['json'])

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
""", content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost, author, self.orig_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=201)

        got = app.get_response('/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/repost',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(201, got.status_int)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)

        repost_as2 = copy.deepcopy(self.repost_as2)
        repost_as2['actor']['image'] = repost_as2['actor']['icon'] = \
            {'type': 'Image', 'url': 'http://orig/pic'},
        self.assert_equals(repost_as2, kwargs['json'])

    def test_activitypub_create_post(self, mock_get, mock_post):
        mock_get.side_effect = [self.create, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        Follower.get_or_create('orig', 'https://mastodon/aaa')
        Follower.get_or_create('orig', 'https://mastodon/bbb',
                               last_follow=json.dumps({'actor': {
                                   'publicInbox': 'https://public/inbox',
                                   'inbox': 'https://unused',
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ccc',
                               last_follow=json.dumps({'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }}))
        Follower.get_or_create('orig', 'https://mastodon/ddd',
                               last_follow=json.dumps({'actor': {
                                   'inbox': 'https://inbox',
                               }}))
        self.datastore_stub.Flush()

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://orig/post',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://orig/post'),
        ))

        inboxes = ('https://public/inbox', 'https://shared/inbox', 'https://inbox')
        for call, inbox in zip(mock_post.call_args_list, inboxes):
            self.assertEquals((inbox,), call[0])
            self.assertEquals(self.create_as2, call[1]['json'])

        for inbox in inboxes:
            resp = Response.get_by_id('http://orig/post %s' % inbox)
            self.assertEqual('out', resp.direction, inbox)
            self.assertEqual('activitypub', resp.protocol, inbox)
            self.assertEqual('complete', resp.status, inbox)
            self.assertEqual(self.create_mf2, json.loads(resp.source_mf2), inbox)

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
            last_follow=json.dumps({'actor': {'inbox': 'https://inbox'}}))
        self.datastore_stub.Flush()

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://orig/post',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        self.assertEquals(('https://inbox',), mock_post.call_args[0])
        create = copy.deepcopy(self.create_as2)
        create['object'].update({
            'image': [{'url': 'http://im/age', 'type': 'Image'}],
            'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
        })
        self.assertEquals(create, mock_post.call_args[1]['json'])

    def test_activitypub_follow(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/follow',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/follow'),
            self.req('http://followee', headers=CONNEG_HEADERS_AS2_HTML),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.follow_as2, kwargs['json'])

        headers = kwargs['headers']
        self.assertEqual(CONTENT_TYPE_AS2, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/follow http://followee')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.follow_mf2, json.loads(resp.source_mf2))

    def test_salmon_reply(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.orig_html_atom, self.orig_atom]

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'http://orig/post',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/reply'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/atom'),
        ))

        data = self.verify_salmon(mock_post)
        parsed = feedparser.parse(data)
        entry = parsed.entries[0]

        self.assertEquals('http://a/reply', entry['id'])
        self.assertIn({
            'rel': 'alternate',
            'href': 'http://a/reply',
            'type': 'text/html',
        }, entry['links'])
        self.assertEquals({
            'type': 'text/html',
            'href': 'http://orig/post',
            'ref': 'tag:fed.brid.gy,2017-08-22:orig-post'
        }, entry['thr_in-reply-to'])
        self.assertEquals(
            '<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a><br />\n<a href="http://localhost/"></a>',
            entry.content[0]['value'])

        resp = Response.get_by_id('http://a/reply http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.reply_mf2, json.loads(resp.source_mf2))

    def test_salmon_like(self, mock_get, mock_post):
        mock_get.side_effect = [self.like, self.orig_html_atom, self.orig_atom]

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/like',
                'target': 'http://orig/post',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            self.req('http://a/like'),
            self.req('http://orig/post', headers=CONNEG_HEADERS_AS2_HTML),
            self.req('http://orig/atom'),
        ))

        data = self.verify_salmon(mock_post)
        parsed = feedparser.parse(data)
        entry = parsed.entries[0]

        self.assertEquals('http://a/like', entry['id'])
        self.assertIn({
            'rel': 'alternate',
            'href': 'http://a/like',
            'type': 'text/html',
        }, entry['links'])
        self.assertEquals('http://orig/post', entry['activity_object'])

        resp = Response.get_by_id('http://a/like http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.like_mf2, json.loads(resp.source_mf2))

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
        mock_get.side_effect = [self.reply, self.orig_html_atom, orig_atom, webfinger]

        got = app.get_response('/webmention', method='POST', body=urllib.urlencode({
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_any_call(
            'http://orig/.well-known/webfinger?resource=acct:ryan@orig',
            headers=HEADERS, timeout=util.HTTP_TIMEOUT, verify=False)
        self.assertEqual(('http://orig/@ryan/salmon',), mock_post.call_args[0])

    def test_salmon_no_target_atom(self, mock_get, mock_post):
        orig_no_atom = requests_response("""\
<html>
<body>foo</body>
</html>""", 'http://orig/url')
        mock_get.side_effect = [self.reply, orig_no_atom]

        got = app.get_response('/webmention', method='POST', body=urllib.urlencode({
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        }))
        self.assertEquals(400, got.status_int)
        self.assertIn('Target post http://orig/url has no Atom link', got.body)

        self.assertIsNone(Response.get_by_id('http://a/reply http://orig/post'))
