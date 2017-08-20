# coding=utf-8
"""Unit tests for salmon.py.

TODO: test error handling
"""
from __future__ import unicode_literals
import unittest
import urllib

from google.appengine.datastore import datastore_stub_util
from google.appengine.ext import testbed

from django_salmon import magicsigs
import mock
from oauth_dropins.webutil import testutil
import requests

import common
import models
from salmon import app


@mock.patch('requests.post')
@mock.patch('requests.get')
@mock.patch('urllib2.urlopen')
class SalmonTest(unittest.TestCase):

    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        hrd_policy = datastore_stub_util.PseudoRandomHRConsistencyPolicy(probability=.5)
        self.testbed.init_datastore_v3_stub(consistency_policy=hrd_policy)
        self.testbed.init_memcache_stub()

    def tearDown(self):
        self.testbed.deactivate()

    def test_slap(self, mock_urlopen, mock_get, mock_post):
        # salmon magic key discovery. first host-meta, then webfinger
        key = models.MagicKey.get_or_create('alice')
        mock_urlopen.side_effect = [
            testutil.UrlopenResult(200, """\
<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
  <Link rel='lrdd' type='application/xrd+xml' template='http://webfinger/{uri}' />
</XRD>"""),
            testutil.UrlopenResult(200, """\
<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
    <Subject>alice@fedsoc.net</Subject>
    <Link rel='magic-public-key' href='%s' />
</XRD>""" % key.href()),
        ]

        # webmention discovery
        html = '<html><head><link rel="webmention" href="/webmention"></html>'
        resp = requests.Response()
        resp.status_code = 200
        resp._text = html
        resp._content = html.encode('utf-8')
        mock_get.return_value = resp

        # webmention post
        resp = requests.Response()
        resp.status_code = 200
        mock_post.return_value = resp

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
  <updated>2017-08-25T00:00:00</updated>
</entry>"""
        slap = magicsigs.magic_envelope(atom_reply, 'application/atom+xml', key)
        got = app.get_response('/@foo.com/salmon', method='POST', body=slap)
        self.assertEquals(200, got.status_int)

        # check salmon magic key discovery
        mock_urlopen.assert_has_calls((
            mock.call('http://fedsoc.net/.well-known/host-meta'),
            mock.call('http://webfinger/alice@fedsoc.net'),
        ))

        # check webmention discovery and post
        mock_get.assert_called_once_with(
            'http://orig/post', headers=common.HEADERS, verify=False)
        mock_post.assert_called_once_with(
            'http://orig/webmention',
            data={
                'source': 'https://my/reply',
                'target': 'http://orig/post',
            },
            allow_redirects=False,
            headers=common.HEADERS,
            verify=False)
