"""Unit tests for convert.py.
"""
import copy
from unittest.mock import patch

from granary import as2
from granary.tests.test_as1 import ACTOR, COMMENT, DELETE_OF_ID, UPDATE
from models import Object
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import parse_mf2

# import first so that Fake is defined before URL routes are registered
from . import testutil

from common import CONTENT_TYPE_HTML

COMMENT_AS2 = {
    **as2.to_as1(COMMENT),
    'type': 'Note',
    'id': 'https://fed.brid.gy/r/tag:fake.com:123456',
    'url': 'https://fed.brid.gy/r/https://fake.com/123456',
    'name': 'A ☕ reply',
    'inReplyTo': 'https://fake.com/123',
}
HTML = """\
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
AUTHOR_HTML = """\
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
        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://nope.brid.gy/')
        self.assertEqual(404, resp.status_code)

    def test_unknown_dest(self):
        resp = self.client.get('/convert/nope/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(404, resp.status_code)

    def test_missing_url(self):
        resp = self.client.get('/convert/web/',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(404, resp.status_code)

    def test_url_not_web(self):
        resp = self.client.get('/convert/web/git+ssh://foo/bar',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(400, resp.status_code)

    def test_activitypub_to_web_object(self):
        url = 'https://user.com/bar?baz=baj&biff'
        Object(id=url, our_as1=COMMENT).put()

        resp = self.client.get('/convert/web/https://user.com/bar?baz=baj&biff',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_object_empty(self):
        Object(id='http://foo').put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(404, resp.status_code)

    @patch('requests.get')
    def test_activitypub_to_web_fetch(self, mock_get):
        mock_get.return_value = self.as2_resp(as2.from_as1(COMMENT))
        url = 'https://user.com/bar?baz=baj&biff'

        resp = self.client.get(f'/convert/web/{url}',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assertEqual(CONTENT_TYPE_HTML, resp.content_type)
        self.assert_multiline_equals(HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

        mock_get.assert_has_calls((self.as2_req(url),))

    @patch('requests.get')
    def test_activitypub_to_web_fetch_fails(self, mock_get):
        mock_get.side_effect = [requests_response('', status=405)]

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(502, resp.status_code)
        mock_get.assert_has_calls((self.as2_req('http://foo'),))

    def test_activitypub_to_web_with_author(self):
        Object(id='http://foo', our_as1={**COMMENT, 'author': 'http://bar'},
               source_protocol='activitypub').put()
        Object(id='http://bar', our_as1=ACTOR,
               source_protocol='activitypub').put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(AUTHOR_HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_no_url(self):
        comment = copy.deepcopy(COMMENT)
        del comment['url']
        Object(id='http://foo', our_as1=comment).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(200, resp.status_code)
        expected = HTML.replace(
            '\n<meta http-equiv="refresh" content="0;url=https://fake.com/123456">', ''
            ).replace('<a class="u-url" href="https://fake.com/123456">fake.com/123456</a>', '')
        self.assert_multiline_equals(expected, resp.get_data(as_text=True),
                                     ignore_blanks=True)

    def test_activitypub_to_web_deleted_object(self):
        Object(id='http://foo', as2={'content': 'foo'}, deleted=True).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(410, resp.status_code)

    def test_activitypub_to_web_delete_activity(self):
        Object(id='http://foo', our_as1=DELETE_OF_ID).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(410, resp.status_code)

    def test_activitypub_to_web_update_inner_obj_exists_redirect(self):
        # UPDATE's object field is a full object
        Object(id='http://foo', our_as1=UPDATE).put()
        Object(id=UPDATE['object']['id'], as2={'content': 'foo'}).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/convert/web/tag:fake.com:123456',
                         resp.headers['Location'])

    def test_activitypub_to_web_delete_inner_obj_exists_redirect(self):
        # DELETE_OF_ID's object field is a bare string id
        Object(id='http://foo', our_as1=DELETE_OF_ID).put()
        Object(id=DELETE_OF_ID['object'], as2={'content': 'foo'}).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'/convert/web/tag:fake.com:123456',
                         resp.headers['Location'])

    def test_activitypub_to_web_update_no_inner_obj_serve_as_is(self):
        # Update's object field is a full object
        Object(id='http://foo', our_as1=UPDATE).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_in("""\
<div class="e-content p-name">
A ☕ reply
</div>
<a class="u-in-reply-to" href="https://fake.com/123"></a>
""", resp.get_data(as_text=True), ignore_blanks=True)

    def test_activitypub_to_web_update_inner_obj_too_minimal_serve_as_is(self):
        # Update's object field is a full object
        Object(id='http://foo', our_as1=UPDATE).put()
        Object(id=UPDATE['object']['id'], as2={'id': 'foo'}).put()

        resp = self.client.get('/convert/web/http://foo',
                               base_url='https://ap.brid.gy/')
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
        self.assertEqual(f'https://ap.brid.gy/convert/web/http://foo?bar',
                         resp.headers['Location'])

    def test_convert_source_path_redirect(self):
        resp = self.client.get('/convert/activitypub/web/https:/foo%3Fbar%23baz')
        self.assertEqual(301, resp.status_code)
        self.assertEqual(f'https://ap.brid.gy/convert/web/https:/foo%3Fbar%23baz',
                         resp.headers['Location'])

        # the Flask/Werkeug test client strips the #baz here. but ideally we
        # should be testing it since somehow request.full_path URL-decodes in
        # prod but not here. ugh.

        # resp = self.client.get('/convert/activitypub/web/https:/foo?bar#baz')
        # self.assertEqual(301, resp.status_code)
        # self.assertEqual(f'https://ap.brid.gy/convert/web/https:/foo%3Fbar%23baz',
        #                  resp.headers['Location'])

    def test_web_to_activitypub_object(self):
        url = 'https://user.com/bar?baz=baj&biff'
        self.make_user('user.com')

        Object(id=url, mf2=parse_mf2(HTML)['items'][0]).put()

        resp = self.client.get(f'/convert/ap/{url}',
                               base_url='https://web.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_equals(COMMENT_AS2, resp.json, ignore=['to'])

    @patch('requests.get')
    def test_web_to_activitypub_fetch(self, mock_get):
        mock_get.return_value = requests_response(HTML)
        url = 'https://user.com/bar?baz=baj&biff'
        self.make_user('user.com')

        Object(id=url, mf2=parse_mf2(HTML)['items'][0]).put()

        resp = self.client.get(f'/convert/ap/{url}',
                               base_url='https://web.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_equals(COMMENT_AS2, resp.json, ignore=['to'])

    def test_web_to_activitypub_no_user(self):
        resp = self.client.get(f'/convert/ap/http://nope.com/post',
                               base_url='https://web.brid.gy/')
        self.assertEqual(400, resp.status_code)

    def test_web_to_activitypub_url_decode(self):
        """https://github.com/snarfed/bridgy-fed/issues/581"""
        self.make_user('user.com')
        self.store_object(id='http://user.com/a#b', mf2=parse_mf2(HTML)['items'][0])

        resp = self.client.get(f'/convert/ap/http://user.com/a%23b',
                               base_url='https://web.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_equals(COMMENT_AS2, resp.json, ignore=['to'])

    def test_fed_subdomain(self):
        url = 'https://user.com/post'
        Object(id=url, our_as1=COMMENT).put()

        resp = self.client.get('/convert/web/https://user.com/post',
                               base_url='https://fed.brid.gy/')
        self.assertEqual(200, resp.status_code)
        self.assert_multiline_equals(HTML, resp.get_data(as_text=True),
                                     ignore_blanks=True)

