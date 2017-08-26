# coding=utf-8
"""Unit tests for salmon.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import copy
import datetime
import urllib

from django_salmon import magicsigs
import mock
from oauth_dropins.webutil.testutil import requests_response, UrlopenResult
import requests

import common
import models
from salmon import app
import testutil


@mock.patch('requests.post')
@mock.patch('requests.get')
@mock.patch('urllib2.urlopen')
class SalmonTest(testutil.TestCase):

    def test_slap(self, mock_urlopen, mock_get, mock_post):
        # salmon magic key discovery. first host-meta, then webfinger
        key = models.MagicKey.get_or_create('alice')
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
</XRD>""" % key.href()),
        ]

        # webmention discovery
        mock_get.return_value = requests_response(
            '<html><head><link rel="webmention" href="/webmention"></html>')
        # webmention post
        mock_post.return_value = requests_response()

        # send slap!
        atom_reply = """\
<?xml version='1.0' encoding='UTF-8'?>
<entry xmlns='http://www.w3.org/2005/Atom'>
  <id>https://my/reply</id>
  <link href="https://my/reply" />
  <author>
    <name>Alice</name>
    <uri>alice@fedsoc.net</uri>
  </author>
  <thr:in-reply-to xmlns:thr="http://purl.org/syndication/thread/1.0" ref="http://orig/post">
    http://orig/post
  </thr:in-reply-to>
  <content>I hereby reply.</content>
  <title>My Reply</title>
  <updated>%s</updated>
</entry>""" % datetime.datetime.now().isoformat(b'T')
        slap = magicsigs.magic_envelope(atom_reply, 'application/atom+xml', key)
        got = app.get_response('/@foo.com/salmon', method='POST', body=slap)
        self.assertEquals(200, got.status_int)

        # check salmon magic key discovery
        mock_urlopen.assert_has_calls((
            mock.call('http://fedsoc.net/.well-known/host-meta'),
            mock.call('http://webfinger/alice@fedsoc.net'),
        ))

        # check webmention discovery and post
        expected_headers = copy.deepcopy(common.HEADERS)
        expected_headers['Accept'] = '*/*'
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS, verify=False)
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'https://my/reply',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers=expected_headers,
            verify=False)
