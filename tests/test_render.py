# coding=utf-8
"""Unit tests for render.py."""
from oauth_dropins.webutil.util import json_dumps

from app import application
from models import Response
from render import RenderHandler
from . import testutil


class RenderTest(testutil.TestCase):

    def setUp(self):
        super(RenderTest, self).setUp()
        RenderHandler.get.cache_clear()
        self.as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Note',
            'id': 'http://this/reply',
            'url': 'http://this/reply',
            'content': 'A ☕ reply',
            'inReplyTo': 'http://orig/post',
        }
        self.mf2 = {
            'type': ['h-entry'],
            'properties': {
                'uid': ['http://this/reply'],
                'url': ['http://this/reply'],
                'content': [{'value': 'A ☕ reply'}],
                'in-reply-to': ['http://orig/post'],
            },
        }
        self.atom = """\
<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
       xmlns:thr="http://purl.org/syndication/thread/1.0">

<uri>http://this/reply</uri>
<thr:in-reply-to href="http://orig/post" />
<content>A ☕ reply</content>
</entry>
"""
        self.html = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=abc"></head>
<body>
<article class="h-entry">
  <span class="p-uid">http://this/reply</span>
  <a class="u-url" href="http://this/reply">http://this/reply</a>
  <div class="e-content p-name">
  A ☕ reply
  </div>
  <a class="u-in-reply-to" href="http://orig/post"></a>
</article>
</body>
</html>
"""

    def test_render_errors(self):
        for source, target in ('', ''), ('abc', ''), ('', 'xyz'):
            resp = application.get_response('/render?source=%s&target=%s' % (source, target))
            self.assertEqual(400, resp.status_int, resp.body)

        # no Response
        resp = application.get_response('/render?source=abc&target=xyz')
        self.assertEqual(404, resp.status_int)

        # no source data
        Response(id='abc xyz').put()
        resp = application.get_response('/render?source=abc&target=xyz')
        self.assertEqual(404, resp.status_int)

    def test_render_as2(self):
        Response(id='abc xyz', source_as2=json_dumps(self.as2)).put()
        resp = application.get_response('/render?source=abc&target=xyz')
        self.assertEqual(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode(),
                                     ignore_blanks=True)

    def test_render_mf2(self):
        Response(id='abc xyz', source_mf2=json_dumps(self.mf2)).put()
        resp = application.get_response('/render?source=abc&target=xyz')
        self.assertEqual(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode(),
                                     ignore_blanks=True)

    def test_render_atom(self):
        Response(id='abc xyz', source_atom=self.atom).put()
        resp = application.get_response('/render?source=abc&target=xyz')
        self.assertEqual(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode(),
                                     ignore_blanks=True)
