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

import common
from models import Domain, Activity
from . import testutil


@mock.patch('requests.post')
@mock.patch('requests.get')
@mock.patch('requests.head')
@mock.patch('urllib.request.urlopen')
class SalmonTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.key = Domain.get_or_create('alice')

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
        got = self.client.post('/foo.com@foo.com/salmon', data=slap)
        self.assertEqual(200, got.status_code)

        # check salmon magic key discovery
        mock_urlopen.assert_has_calls((
            mock.call('http://fedsoc.net/.well-known/host-meta'),
            mock.call('http://webfinger/alice@fedsoc.net'),
        ))

        # check webmention discovery
        self.assert_req(mock_get, 'http://orig/post')

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
        self.assert_req(
            mock_post,
            'http://orig/webmention',
            data={'source': 'https://my/reply', 'target': 'http://orig/post'},
            allow_redirects=False,
            headers={'Accept': '*/*'})

        # check stored post
        activity = Activity.get_by_id('https://my/reply http://orig/post')
        self.assertEqual('orig', activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('ostatus', activity.protocol)
        self.assertEqual('complete', activity.status)
        self.assertEqual(atom_reply, activity.source_atom)

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
        self.assert_req(
            mock_post,
            'http://orig/webmention',
            data={
                'source': 'http://localhost/render?source=https%3A%2F%2Fmy%2Flike&target=http%3A%2F%2Forig%2Fpost',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers={'Accept': '*/*'})

        # check stored post
        activity = Activity.get_by_id('https://my/like http://orig/post')
        self.assertEqual('orig', activity.domain)
        self.assertEqual('in', activity.direction)
        self.assertEqual('ostatus', activity.protocol)
        self.assertEqual('complete', activity.status)
        self.assertEqual(atom_like, activity.source_atom)

    def test_bad_envelope(self, *mocks):
        got = self.client.post('/foo.com/salmon', data='not xml')
        self.assertEqual(400, got.status_code)

    def test_bad_inner_xml(self, *mocks):
        slap = magicsigs.magic_envelope('not xml', common.CONTENT_TYPE_ATOM, self.key)
        got = self.client.post('/foo.com/salmon', data=slap)
        self.assertEqual(400, got.status_code)

    def test_rsvp_not_supported(self, *mocks):
        slap = magicsigs.magic_envelope("""\
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'
       xmlns:activity='http://activitystrea.ms/spec/1.0/'>
  <uri>https://my/rsvp</uri>
  <activity:verb>http://activitystrea.ms/schema/1.0/rsvp</activity:verb>
  <activity:object>http://orig/event</activity:object>
</entry>""", common.CONTENT_TYPE_ATOM, self.key)
        got = self.client.post('/foo.com/salmon', data=slap)
        self.assertEqual(501, got.status_code)
