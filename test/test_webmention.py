# coding=utf-8
"""Unit tests for webmention.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import json
import logging
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
import common
from models import MagicKey, Response
import testutil
import webmention
from webmention import app


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):

    def setUp(self):
        super(WebmentionTest, self).setUp()
        self.key = MagicKey.get_or_create('a')

        self.orig = requests_response("""\
<html>
<meta>
<link href='http://orig/atom' rel='alternate' type='application/atom+xml'>
</meta>
</html>
""", url='http://orig/post', content_type='text/html; charset=utf-8')

        self.orig_atom = requests_response("""\
<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <id>tag:fed.brid.gy,2017-08-22:orig-post</id>
  <link rel="salmon" href="http://orig/salmon"/>
  <content type="html">baz ☕ baj</content>
</entry>
""")


        self.reply_html = """\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="http://a/reply"></a>
<p class="e-content p-name">
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>
<a href="https://fed.brid.gy/"></a>
</p>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
</div>
</body>
</html>
"""
        self.reply = requests_response(
            self.reply_html, content_type='text/html; charset=utf-8')
        self.reply_mf2 = mf2py.parse(self.reply_html, url='http://a/reply')
        self.reply_obj = microformats2.json_to_object(self.reply_mf2['items'][0])

        self.repost_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/repost"></a>
<a class="u-repost-of p-name" href="http://orig/post">reposted!</a>
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
</body>
</html>
"""
        self.repost = requests_response(
            self.repost_html, content_type='text/html; charset=utf-8')
        self.repost_mf2 = mf2py.parse(self.repost_html, url='http://a/repost')

        self.like_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="http://a/like"></a>
<a class="u-like-of" href="http://orig/post"></a>
<!--<a class="u-like-of p-name" href="http://orig/post">liked!</a>-->
<a class="p-author h-card" href="http://orig">Ms. ☕ Baz</a>
</body>
</html>
"""
        self.like = requests_response(
            self.like_html, content_type='text/html; charset=utf-8')
        self.like_mf2 = mf2py.parse(self.like_html, url='http://a/like')

        self.article = requests_response({
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'content': 'Lots of ☕ words...',
            'actor': {
                'url': 'http://orig/author',
            },
        })
        self.actor = requests_response({
            'objectType' : 'person',
            'displayName': 'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        })
        self.activitypub_gets = [self.reply, self.article, self.actor]

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'object': {
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Note',
                'id': 'http://a/reply',
                'url': 'http://a/reply',
                'name': 'foo ☕ bar',
                'content': ' <a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a> <a href="https://fed.brid.gy/"></a> ',
                'inReplyTo': 'http://orig/post',
                'cc': [
                    common.AS2_PUBLIC_AUDIENCE,
                    'http://orig/post',
                ],
                'attributedTo': [{
                    'type': 'Person',
                    'url': 'http://orig',
                    'preferredUsername': 'me',
                    'name': 'Ms. ☕ Baz',
                }],
            },
        }
        self.as2_update = copy.deepcopy(self.as2_create)
        self.as2_update['type'] = 'Update'

    def verify_salmon(self, mock_post):
        args, kwargs = mock_post.call_args
        self.assertEqual(('http://orig/salmon',), args)
        self.assertEqual(common.MAGIC_ENVELOPE_CONTENT_TYPE,
                         kwargs['headers']['Content-Type'])

        env = utils.parse_magic_envelope(kwargs['data'])
        data = utils.decode(env['data'])
        assert magicsigs.verify(None, data, env['sig'], key=self.key)

        return data

    def test_activitypub_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            call('http://a/reply', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
            call('http://orig/post', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),
            call('http://orig/author', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual(self.as2_create, kwargs['json'])

        headers = kwargs['headers']
        self.assertEqual(activitypub.CONTENT_TYPE_AS, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/reply http://orig/post')
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
        Response(id='http://a/reply http://orig/post', status='complete').put()

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
        mock_get.side_effect = [self.repost, self.article, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/repost',
                'target': 'https://fed.brid.gy/',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            call('http://a/repost', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
            call('http://orig/post', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),
            call('http://orig/author', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Announce',
            'url': 'http://a/repost',
            'name': 'reposted!',
            'object': 'http://orig/post',
            'cc': [common.AS2_PUBLIC_AUDIENCE],
            'actor': {
                'type': 'Person',
                'url': 'http://orig',
                'name': 'Ms. ☕ Baz',
            },
        }, kwargs['json'])

        headers = kwargs['headers']
        self.assertEqual(activitypub.CONTENT_TYPE_AS, headers['Content-Type'])

        rsa_key = kwargs['auth'].header_signer._rsa._key
        self.assertEqual(self.key.private_pem(), rsa_key.exportKey())

        resp = Response.get_by_id('http://a/repost http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('activitypub', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.repost_mf2, json.loads(resp.source_mf2))

    def test_salmon_reply(self, mock_get, mock_post):
        mock_get.side_effect = [self.reply, self.orig, self.orig_atom]

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'http://orig/post',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            call('http://a/reply', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
            call('http://orig/post', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),
            call('http://orig/atom', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
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
            '<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a> <a href="https://fed.brid.gy/"></a>',
            entry.content[0]['value'])

        resp = Response.get_by_id('http://a/reply http://orig/post')
        self.assertEqual('out', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(self.reply_mf2, json.loads(resp.source_mf2))

    def test_salmon_like(self, mock_get, mock_post):
        mock_get.side_effect = [self.like, self.orig, self.orig_atom]

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/like',
                'target': 'http://orig/post',
            }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_has_calls((
            call('http://a/like', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
            call('http://orig/post', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),
            call('http://orig/atom', headers=common.HEADERS, timeout=util.HTTP_TIMEOUT),
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
        mock_get.side_effect = [self.reply, self.orig, orig_atom, webfinger]

        got = app.get_response('/webmention', method='POST', body=urllib.urlencode({
            'source': 'http://a/reply',
            'target': 'http://orig/post',
        }))
        self.assertEquals(200, got.status_int)

        mock_get.assert_any_call(
            'http://orig/.well-known/webfinger?resource=acct:ryan@orig',
            headers=common.HEADERS, timeout=util.HTTP_TIMEOUT, verify=False)
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

