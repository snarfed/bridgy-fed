"""Unit tests for convert.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from granary.tests.test_as1 import ACTOR, COMMENT, DELETE_OF_ID, UPDATE
from models import Object
from oauth_dropins.webutil.testutil import requests_response
import requests

import app
from common import CONTENT_TYPE_HTML

from .test_redirect import (
    REPOST_AS2,
    REPOST_HTML,
)
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


class ConvertTest(testutil.TestCase):

    def test_unknown_source(self):
        resp = self.client.get('/convert/nope/web/http://foo')
        self.assertEqual(404, resp.status_code)

    def test_unknown_dest(self):
        resp = self.client.get('/convert/activitypub/nope/http://foo')
        self.assertEqual(404, resp.status_code)

    def test_missing_url(self):
        resp = self.client.get('/convert/activitypub/web/')
        self.assertEqual(404, resp.status_code)

    def test_url_not_web(self):
        resp = self.client.get('/convert/activitypub/web/git+ssh://foo/bar')
        self.assertEqual(400, resp.status_code)

    def test_activitypub_to_web_object(self):
        url = 'https://user.com/bar?baz=baj&biff'
        with self.request_context:
            Object(id=url, our_as1=COMMENT).put()

        resp = self.client.get('/convert/activitypub/web/https://user.com/bar?baz=baj&biff')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(EXPECTED_HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_object_empty(self):
        with self.request_context:
            Object(id='http://foo').put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(404, resp.status_code)

    @patch('requests.get')
    def test_activitypub_to_web_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(as2.from_as1(COMMENT))
        url = 'https://user.com/bar?baz=baj&biff'

        resp = self.client.get(f'/convert/activitypub/web/{url}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual(CONTENT_TYPE_HTML, resp.content_type)
        self.assert_multiline_equals(EXPECTED_HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

        mock_get.assert_has_calls((self.as2_req(url),))

    @patch('requests.get')
    def test_activitypub_to_web_fetch_fails(self, mock_get):
        mock_get.side_effect = [requests_response('', status=405)]

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(502, resp.status_code)
        mock_get.assert_has_calls((self.as2_req('http://foo'),))

    def test_activitypub_to_web_with_author(self):
        with self.request_context:
            Object(id='http://foo', our_as1={**COMMENT, 'author': 'http://bar'},
                   source_protocol='activitypub').put()
            Object(id='http://bar', our_as1=ACTOR,
                   source_protocol='activitypub').put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(EXPECTED_AUTHOR_HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_no_url(self):
        comment = copy.deepcopy(COMMENT)
        del comment['url']
        with self.request_context:
            Object(id='http://foo', our_as1=comment).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(200, resp.status_code)
        expected = EXPECTED_HTML.replace(
            '\n<meta http-equiv="refresh" content="0;url=https://fake.com/123456">', ''
            ).replace('<a class="u-url" href="https://fake.com/123456">fake.com/123456</a>', '')
        self.assert_multiline_equals(expected, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_deleted_object(self):
        with self.request_context:
            Object(id='http://foo', as2={'content': 'foo'}, deleted=True).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(410, resp.status_code)

    def test_activitypub_to_web_delete_activity(self):
        with self.request_context:
            Object(id='http://foo', our_as1=DELETE_OF_ID).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(410, resp.status_code)

    def test_activitypub_to_web_update_inner_obj_exists_redirect(self):
        with self.request_context:
            # UPDATE's object field is a full object
            Object(id='http://foo', our_as1=UPDATE).put()
            Object(id=UPDATE['object']['id'], as2={'content': 'foo'}).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/convert/activitypub/web/tag:fake.com:123456',
                         resp.headers['Location'])

    def test_activitypub_to_web_delete_inner_obj_exists_redirect(self):
        with self.request_context:
            # DELETE_OF_ID's object field is a bare string id
            Object(id='http://foo', our_as1=DELETE_OF_ID).put()
            Object(id=DELETE_OF_ID['object'], as2={'content': 'foo'}).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/convert/activitypub/web/tag:fake.com:123456',
                         resp.headers['Location'])

    def test_activitypub_to_web_update_no_inner_obj_serve_as_is(self):
        with self.request_context:
            # UPDATE's object field is a full object
            Object(id='http://foo', our_as1=UPDATE).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_in("""\
<div class="e-content p-name">
A ☕ reply
</div>
<a class="u-in-reply-to" href="https://fake.com/123"></a>
""", resp.get_data(as_text=True), ignore_blanks=True)

    def test_activitypub_to_web_update_inner_obj_too_minimal_serve_as_is(self):
        with self.request_context:
            # UPDATE's object field is a full object
            Object(id='http://foo', our_as1=UPDATE).put()
            Object(id=UPDATE['object']['id'], as2={'id': 'foo'}).put()

        resp = self.client.get('/convert/activitypub/web/http://foo')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_in("""\
<div class="e-content p-name">
A ☕ reply
</div>
<a class="u-in-reply-to" href="https://fake.com/123"></a>
""", resp.get_data(as_text=True), ignore_blanks=True)

    def test_render_endpoint_redirect(self):
        resp = self.client.get('/render?id=http://foo%3Fbar')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/convert/activitypub/web/http://foo?bar',
                         resp.headers['Location'])
