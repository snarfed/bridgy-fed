# coding=utf-8
"""Unit tests for salmon.py.

TODO: test error handling
"""
import copy
import datetime
from unittest import mock

from django_salmon import magicsigs
from oauth_dropins.webutil.testutil import requests_response, UrlopenResult
import requests

from app import application
import common
from models import MagicKey, Response
from . import testutil


@mock.patch('requests.post')
@mock.patch('requests.get')
@mock.patch('requests.head')
@mock.patch('urllib.request.urlopen')
class SalmonTest(testutil.TestCase):

    def setUp(self):
        super(SalmonTest, self).setUp()
        self.key = MagicKey.get_or_create('alice')

    def send_slap(self, mock_urlopen, mock_head, mock_get, mock_post, atom_slap):
        # salmon magic key discovery. first host-meta, then webfinger
        mock_urlopen.side_effect = [
            UrlopenResult(200, """\
<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
  <Link rel='lrdd' type='application/xrd+xml' template='http://webfinger/{uri}' />
</XRD>"""),
            UrlopenResult(200, """\
<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
    <Subject>alice@fedsoc.net</Subject>
    <Link rel='magic-public-key' href='%s' />
</XRD>""" % self.key.href()),
        ]

        # webmention discovery
        mock_head.return_value = requests_response(url='http://orig/post')
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        # webmention post
        mock_post.return_value = requests_response()

        slap = magicsigs.magic_envelope(atom_slap, common.CONTENT_TYPE_ATOM, self.key)
        got = application.get_response('/foo.com@foo.com/salmon', method='POST',
                                       body=slap)
        self.assertEqual(200, got.status_int)

        # check salmon magic key discovery
        mock_urlopen.assert_has_calls((
            mock.call('http://fedsoc.net/.well-known/host-meta'),
            mock.call('http://webfinger/alice@fedsoc.net'),
        ))

        # check webmention discovery
        self.expected_headers = copy.deepcopy(common.HEADERS)
        self.expected_headers['Accept'] = '*/*'
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS)

    def test_reply(self, mock_urlopen, mock_head, mock_get, mock_post):
        atom_reply = """\
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'>
  <id>https://my/reply</id>
  <uri>https://my/reply</uri>
  <author>
    <name>Alice</name>
    <uri>alice@fedsoc.net</uri>
  </author>
  <thr:in-reply-to xmlns:thr="http://purl.org/syndication/thread/1.0">
    http://orig/post
  </thr:in-reply-to>
  <content>I hereby reply.</content>
  <title>My Reply</title>
  <updated>%s</updated>
</entry>""" % datetime.datetime.now().isoformat('T')
        self.send_slap(mock_urlopen, mock_head, mock_get, mock_post, atom_reply)

        # check webmention post
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={'source': 'https://my/reply', 'target': 'http://orig/post'},
            allow_redirects=False,
            headers=self.expected_headers)

        # check stored response
        resp = Response.get_by_id('https://my/reply http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(atom_reply, resp.source_atom)

    def test_like(self, mock_urlopen, mock_head, mock_get, mock_post):
        atom_like = """\
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'
       xmlns:activity='http://activitystrea.ms/spec/1.0/'>
  <uri>https://my/like</uri>
  <author>
    <name>Alice</name>
    <uri>alice@fedsoc.net</uri>
  </author>
  <activity:verb>http://activitystrea.ms/schema/1.0/like</activity:verb>
  <activity:object>http://orig/post</activity:object>
  <updated>%s</updated>
</entry>""" % datetime.datetime.now().isoformat('T')
        self.send_slap(mock_urlopen, mock_head, mock_get, mock_post, atom_like)

        # check webmention post
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'http://localhost/render?source=https%3A%2F%2Fmy%2Flike&target=http%3A%2F%2Forig%2Fpost',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers=self.expected_headers)

        # check stored response
        resp = Response.get_by_id('https://my/like http://orig/post')
        self.assertEqual('in', resp.direction)
        self.assertEqual('ostatus', resp.protocol)
        self.assertEqual('complete', resp.status)
        self.assertEqual(atom_like, resp.source_atom)

    def test_bad_envelope(self, *mocks):
        got = application.get_response('/foo.com/salmon', method='POST',
                                       body=b'not xml')
        self.assertEqual(400, got.status_int)

    def test_bad_inner_xml(self, *mocks):
        slap = magicsigs.magic_envelope('not xml', common.CONTENT_TYPE_ATOM, self.key)
        got = application.get_response('/foo.com/salmon', method='POST', body=slap)
        self.assertEqual(400, got.status_int)

    def test_rsvp_not_supported(self, *mocks):
        slap = magicsigs.magic_envelope("""\
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'
       xmlns:activity='http://activitystrea.ms/spec/1.0/'>
  <uri>https://my/rsvp</uri>
  <activity:verb>http://activitystrea.ms/schema/1.0/rsvp</activity:verb>
  <activity:object>http://orig/event</activity:object>
</entry>""", common.CONTENT_TYPE_ATOM, self.key)
        got = application.get_response('/foo.com/salmon', method='POST', body=slap)
        self.assertEqual(501, got.status_int)
