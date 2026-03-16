"""Unit tests for filters.py."""
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob
from filters import (
    content_blocklisted,
    media_blocklisted,
)
from memcache import memcache
from models import Object, PROTOCOLS
from oauth_dropins.webutil.testutil import requests_response
from .testutil import Fake, OtherFake, TestCase


class ContentBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        memcache.set('content-blocklist', 'badword\nspam')

    def test_pass(self):
        self.assertFalse(content_blocklisted(Object(our_as1={'content': 'foo bar'})))

    def test_pass_no_stored_blocklist(self):
        memcache.delete('content-blocklist')
        self.assertFalse(content_blocklisted(Object(
            our_as1={'content': 'badword spam'})))

    def test_fail(self):
        for val in (
                'this has badword in it',
                'this has spam in it',
                ' bAdWoRd ',
                '<b>bad</b>word',
        ):
            for field in 'content', 'summary', 'displayName':
                with self.subTest(val=val, field=field):
                    self.assertTrue(content_blocklisted(Object(our_as1={field: val})))

    def test_fail_inner_object(self):
        self.assertTrue(content_blocklisted(Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {'content': 'this has badword'},
        })))


class MediaBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        AtpRemoteBlob(id='http://example.com/bad', cid='badblobcid').put()
        memcache.set('media-blocklist', 'badblobcid')

    def test_pass_no_stored_blocklist(self):
        memcache.delete('media-blocklist')
        self.assertFalse(media_blocklisted(Object(our_as1={
            'image': [{'url': 'http://example.com/bad'}],
        })))

    def test_pass(self):
        for obj_as1 in (
                {'image': [{'url': 'http://example.com/ok'}]},
                {'attachments': [{
                    'objectType': 'note',
                    'url': 'http://example.com/bad',
                }]},
                # shouldn't fetch
                {'attachments': [{
                    'objectType': 'note',
                    'url': 'http://example.com/unknown',
                }]},
        ):
            with self.subTest(obj_as1=obj_as1):
                self.assertFalse(media_blocklisted(Object(our_as1=obj_as1)))

    def test_fail(self):
        for obj_as1 in (
                {'image': [{'url': 'http://example.com/bad'}]},
                {'attachments': [{
                    'objectType': 'image',
                    'url': 'http://example.com/bad',
                }]},
                {'attachments': [{
                    'objectType': 'video',
                    'stream': {'url': 'http://example.com/bad'},
                }]},
                {'attachments': [{
                    'objectType': 'audio',
                    'stream': {'url': 'http://example.com/bad'},
                }]},
                {'objectType': 'activity', 'verb': 'post',
                 'object': {'image': [{'url': 'http://example.com/bad'}]}},
        ):
            with self.subTest(obj_as1=obj_as1):
                self.assertTrue(media_blocklisted(Object(our_as1=obj_as1)))

    @patch('requests.get', return_value=requests_response('blob contents'))
    def test_fetch_blob_fail(self, mock_get):
        memcache.set('media-blocklist',
                     'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        self.assertTrue(media_blocklisted(Object(our_as1={
            'image': [{'url': 'http://example.com/new'}],
        })))
        mock_get.assert_has_calls(mock_get, [self.req('http://example.com/new')])
