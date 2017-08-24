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
import mock
from mock import call
from oauth_dropins.webutil import util
import requests

import activitypub
import common
import models
import testutil
import webmention
from webmention import app


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(testutil.TestCase):

    def setUp(self):
        super(WebmentionTest, self).setUp()
        self.reply_html = u"""\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="http://a/reply"></a>
<p class="e-content">
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>
</p>
</div>
</body>
</html>
"""
        self.reply = requests.Response()
        self.reply.status_code = 200
        self.reply._text = self.reply_html
        self.reply._content = self.reply_html.encode('utf-8')
        self.reply.encoding = 'utf-8'

        self.reply_atom = u"""\
<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
       xmlns:thr="http://purl.org/syndication/thread/1.0">
  <id>http://a/reply</id>
  <thr:in-reply-to ref="tag:fed.brid.gy,2017-08-22:orig-post">
    tag:fed.brid.gy,2017-08-22:orig-post
  </thr:in-reply-to>
  <content>foo ☕ bar</content>
  <title></title>
</entry>
"""

    def test_webmention_activitypub(self, mock_get, mock_post):
        article_as = {
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'content': u'Lots of ☕ words...',
            'actor': 'http://orig/author',
        }
        article = requests.Response()
        article.status_code = 200
        article._text = json.dumps(article_as)
        article._content = article._text.encode('utf-8')
        article.encoding = 'utf-8'

        actor_as = {
            'objectType' : 'person',
            'displayName': u'Mrs. ☕ Foo',
            'url': 'https://foo.com/about-me',
            'inbox': 'https://foo.com/inbox',
        }
        actor = requests.Response()
        actor.status_code = 200
        actor._text = json.dumps(actor_as)
        actor._content = actor._text.encode('utf-8')
        actor.encoding = 'utf-8'

        mock_get.side_effect = [self.reply, article, actor]

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
            call('http://orig/author', headers=activitypub.CONNEG_HEADER,
                 timeout=util.HTTP_TIMEOUT),))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual({
            'objectType': 'comment',
            'url': 'http://a/reply',
            'displayName': u'foo ☕ bar',
            'content': u' <a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a> ',
            'inReplyTo': [{'url': 'http://orig/post'}],
        }, kwargs['json'])

        expected_headers = copy.copy(common.HEADERS)
        expected_headers['Content-Type'] = activitypub.CONTENT_TYPE_AS
        self.assertEqual(expected_headers, kwargs['headers'])

    def test_webmention_salmon(self, mock_get, mock_post):
        target = requests.Response()
        target.status_code = 200
        target.headers['Content-Type'] = 'text/html'
        target._content = """\
<html>
<meta>
<link href='http://orig/atom' rel='alternate' type='application/atom+xml'>
</meta>
</html>
""".encode('utf-8')

        atom = requests.Response()
        atom.status_code = 200
        atom._content = """\
<?xml version="1.0"?>
<entry xmlns="http://www.w3.org/2005/Atom">
  <id>tag:fed.brid.gy,2017-08-22:orig-post</id>
  <link rel="salmon" href="http://orig/salmon"/>
  <content type="html">baz ☕ baj</content>
</entry>
""".encode('utf-8')

        mock_get.side_effect = [self.reply, target, atom]

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

        args, kwargs = mock_post.call_args
        self.assertEqual(('http://orig/salmon',), args)
        self.assertEqual(common.MAGIC_ENVELOPE_CONTENT_TYPE,
                         kwargs['headers']['Content-Type'])

        envelope = utils.parse_magic_envelope(kwargs['data'])
        assert envelope['sig']

        feed = utils.decode(envelope['data'])
        parsed = feedparser.parse(feed)
        entry = parsed.entries[0]

        self.assertEquals('http://a/reply', entry.id)
        self.assertIn({
            'rel': 'alternate',
            'href': 'http://a/reply',
            'type': 'text/html',
        }, entry.links)
        self.assertEquals({
            'type': 'text/html',
            'href': 'http://orig/post',
            'ref': 'tag:fed.brid.gy,2017-08-22:orig-post'
        }, entry['thr_in-reply-to'])
        self.assertEquals(
            u'<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>',
            entry.content[0]['value'])
