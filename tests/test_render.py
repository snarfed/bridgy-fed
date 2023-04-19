"""Unit tests for render.py."""
import copy

from granary import as2
from granary.tests.test_as1 import ACTOR, COMMENT, DELETE_OF_ID, UPDATE

from flask_app import app
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
  <a class="u-url" href="https://fake.com/123456">fake.com/123456</a>
  <div class="e-content p-name">
  A ☕ reply
  </div>
  <a class="u-in-reply-to" href="https://fake.com/123"></a>
</article>
</body>
</html>
"""
EXPECTED_AUTHOR_HTML = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=https://fake.com/123456"></head>
<body class="">
<article class="h-entry">
  <span class="p-uid">tag:fake.com:123456</span>
  <time class="dt-published" datetime="2012-12-05T00:58:26+00:00">2012-12-05T00:58:26+00:00</time>
  <span class="p-author h-card">
    <data class="p-uid" value="tag:fake.com:444"></data>
    <a class="p-name u-url" href="https://plus.google.com/bob">Bob</a>
    <img class="u-photo" src="https://bob/picture" alt="" />
  </span>
  <a class="u-url" href="https://fake.com/123456">fake.com/123456</a>
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
            Object(id='abc', as2=as2.from_as1(COMMENT)).put()
        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(EXPECTED_HTML, resp.get_data(as_text=True), ignore_blanks=True)

    def test_render_with_author(self):
        with app.test_request_context('/'):
            Object(id='abc', as2=as2.from_as1({**COMMENT, 'author': 'def'})).put()
            Object(id='def', as2=as2.from_as1(ACTOR)).put()
        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(
            EXPECTED_AUTHOR_HTML, resp.get_data(as_text=True), ignore_blanks=True)

    def test_render_no_url(self):
        comment = copy.deepcopy(COMMENT)
        del comment['url']
        with app.test_request_context('/'):
            Object(id='abc', as2=as2.from_as1(comment)).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        expected = EXPECTED_HTML.replace(
            '\n<meta http-equiv="refresh" content="0;url=https://fake.com/123456">', ''
            ).replace('<a class="u-url" href="https://fake.com/123456">fake.com/123456</a>', '')
        self.assert_multiline_equals(expected, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_render_deleted_object(self):
        with app.test_request_context('/'):
            Object(id='abc', as2={'content': 'foo'}, deleted=True).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(410, resp.status_code)

    def test_render_delete_activity(self):
        with app.test_request_context('/'):
            Object(id='abc', as2=as2.from_as1(DELETE_OF_ID)).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(410, resp.status_code)

    def test_render_update_inner_obj_exists_redirect(self):
        with app.test_request_context('/'):
            # UPDATE's object field is a full object
            Object(id='abc', as2=as2.from_as1(UPDATE)).put()
            Object(id=UPDATE['object']['id'], as2={'content': 'foo'}).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/render?id=tag%3Afake.com%3A123456',
                         resp.headers['Location'])

    def test_render_delete_inner_obj_exists_redirect(self):
        with app.test_request_context('/'):
            # DELETE_OF_ID's object field is a bare string id
            Object(id='abc', as2=as2.from_as1(DELETE_OF_ID)).put()
            Object(id=DELETE_OF_ID['object'], as2={'content': 'foo'}).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/render?id=tag%3Afake.com%3A123456',
                         resp.headers['Location'])

    def test_render_update_no_inner_obj_serve_as_is(self):
        with app.test_request_context('/'):
            # UPDATE's object field is a full object
            Object(id='abc', as2=as2.from_as1(UPDATE)).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_in("""\
<div class="e-content p-name">
A ☕ reply
</div>
<a class="u-in-reply-to" href="https://fake.com/123"></a>
""", resp.get_data(as_text=True), ignore_blanks=True)

    def test_render_update_inner_obj_too_minimal_serve_as_is(self):
        with app.test_request_context('/'):
            # UPDATE's object field is a full object
            Object(id='abc', as2=as2.from_as1(UPDATE)).put()
            Object(id=UPDATE['object']['id'], as2={'id': 'foo'}).put()

        resp = self.client.get('/render?id=abc')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_in("""\
<div class="e-content p-name">
A ☕ reply
</div>
<a class="u-in-reply-to" href="https://fake.com/123"></a>
""", resp.get_data(as_text=True), ignore_blanks=True)

