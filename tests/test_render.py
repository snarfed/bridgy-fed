# coding=utf-8
"""Unit tests for render.py."""
import copy
from unittest import skip

from granary import as2
from granary.tests.test_as1 import COMMENT, DELETE_OF_ID, UPDATE
from oauth_dropins.webutil.util import json_dumps

from app import app
import common
from models import Object
import render
from . import testutil

EXPECTED_HTML = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=https://fake.com/123456"></head>
<body class="">
<article class="h-entry">
  <span class="p-uid">tag:fake.com:123456</span>
  <time class="dt-published" datetime="2012-12-05T00:58:26+00:00">2012-12-05T00:58:26+00:00</time>
  <a class="u-url" href="https://fake.com/123456">https://fake.com/123456</a>
  <div class="e-content p-name">
  A ☕ reply
  </div>
  <a class="u-in-reply-to" href="https://fake.com/123"></a>
</article>
</body>
</html>
"""

class RenderTest(testutil.TestCase):

    def test_render_errors(self):
        resp = self.client.get(f'/render?id=')
        self.assertEqual(400, resp.status_code)

        resp = self.client.get(f'/render')
        self.assertEqual(400, resp.status_code)

        # no Object
        resp = self.client.get('/render?id=abc')
        self.assertEqual(404, resp.status_code)

    def test_render(self):
        with app.test_request_context('/'):
            Object(id='abc', as2=json_dumps(as2.from_as1(COMMENT))).put()
        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(EXPECTED_HTML, resp.get_data(as_text=True), ignore_blanks=True)

    def test_render_no_url(self):
        comment = copy.deepcopy(COMMENT)
        del comment['url']
        with app.test_request_context('/'):
            Object(id='abc', as2=json_dumps(as2.from_as1(comment))).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        expected = EXPECTED_HTML.replace(
            '\n<meta http-equiv="refresh" content="0;url=https://fake.com/123456">', ''
            ).replace('<a class="u-url" href="https://fake.com/123456">https://fake.com/123456</a>', '')
        self.assert_multiline_equals(expected, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    @skip
    def test_render_update_redirect(self):
        with app.test_request_context('/'):
            # UPDATE's object field is a full object
            Object(id='abc', as2=json_dumps(as2.from_as1(UPDATE))).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/render?id=tag%3Afake.com%3A123456',
                         resp.headers['Location'])

    @skip
    def test_render_delete_redirect(self):
        with app.test_request_context('/'):
            # DELETE_OF_ID's object field is a bare string id
            Object(id='abc', as1=json_dumps(as2.from_as1(DELETE_OF_ID))).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/render?id=tag%3Afake.com%3A123456',
                         resp.headers['Location'])
