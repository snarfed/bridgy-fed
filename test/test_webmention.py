# coding=utf-8
"""Unit tests for webmention.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import json
import unittest
import urllib

import mock
import requests

import activitypub
import common
import webmention
from webmention import app


@mock.patch('requests.post')
@mock.patch('requests.get')
class WebmentionTest(unittest.TestCase):

    def test_webmention(self, mock_get, mock_post):
        reply_html = u"""
<html><body>
<div class="h-entry">
<p class="e-content">
<a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a>
</p>
</div>
</body></html>
"""
        reply = requests.Response()
        reply.status_code = 200
        reply._text = reply_html
        reply._content = reply._text.encode('utf-8')
        reply.encoding = 'utf-8'

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

        mock_get.side_effect = [reply, article, actor]

        got = app.get_response(
            '/webmention', method='POST', body=urllib.urlencode({
                'source': 'http://a/reply',
                'target': 'http://orig/post',
            }))
        self.assertEquals(200, got.status_int)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://foo.com/inbox',), args)
        self.assertEqual({
            'objectType': 'comment',
            'displayName': u'foo ☕ bar',
            'content': u' <a class="u-in-reply-to" href="http://orig/post">foo ☕ bar</a> ',
            'inReplyTo': [{'url': 'http://orig/post'}],
        }, kwargs['json'])

        expected_headers = copy.copy(common.HEADERS)
        expected_headers['Content-Type'] = activitypub.CONTENT_TYPE_AS
        self.assertEqual(expected_headers, kwargs['headers'])
