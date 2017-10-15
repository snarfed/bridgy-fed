# coding=utf-8
"""Unit tests for render.py."""
from __future__ import unicode_literals
import json

from models import Response
import testutil
from render import app


class RenderTest(testutil.TestCase):

    def setUp(self):
        super(RenderTest, self).setUp()

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
<head><meta charset="utf-8"></head>
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
            resp = app.get_response('/render?source=%s&target=%s' % (source, target))
            self.assertEquals(400, resp.status_int, resp.body)

        # no Response
        resp = app.get_response('/render?source=abc&target=xyz')
        self.assertEquals(404, resp.status_int)

        # no source data
        Response(id='abc xyz').put()
        resp = app.get_response('/render?source=abc&target=xyz')
        self.assertEquals(404, resp.status_int)

    def test_render_as2(self):
        Response(id='abc xyz', source_as2=json.dumps(self.as2)).put()
        resp = app.get_response('/render?source=abc&target=xyz')
        self.assertEquals(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode('utf-8'),
                                     ignore_blanks=True)

    def test_render_mf2(self):
        Response(id='abc xyz', source_mf2=json.dumps(self.mf2)).put()
        resp = app.get_response('/render?source=abc&target=xyz')
        self.assertEquals(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode('utf-8'),
                                     ignore_blanks=True)

    def test_render_atom(self):
        Response(id='abc xyz', source_atom=self.atom).put()
        resp = app.get_response('/render?source=abc&target=xyz')
        self.assertEquals(200, resp.status_int)
        self.assert_multiline_equals(self.html, resp.body.decode('utf-8'),
                                     ignore_blanks=True)
