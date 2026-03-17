"""Unit tests for filters.py."""
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob
import filters
from filters import (
    content_blocklisted,
    domain_blocklisted,
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
        obj = Object(our_as1={'content': 'foo bar'})
        self.assertFalse(content_blocklisted(obj, None))

    def test_pass_no_stored_blocklist(self):
        memcache.delete('content-blocklist')
        self.assertFalse(content_blocklisted(Object(
            our_as1={'content': 'badword spam'}), None))

    def test_fail(self):
        for val in (
                'this has badword in it',
                'this has spam in it',
                ' bAdWoRd ',
                '<b>bad</b>word',
        ):
            for field in 'content', 'summary', 'displayName':
                with self.subTest(val=val, field=field):
                    obj = Object(our_as1={field: val})
                    self.assertTrue(content_blocklisted(obj, None))

    def test_fail_inner_object(self):
        self.assertTrue(content_blocklisted(Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {'content': 'this has badword'},
        }), None))


class MediaBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        AtpRemoteBlob(id='http://example.com/bad', cid='badblobcid').put()
        memcache.set('media-blocklist', 'badblobcid')

    def test_pass_no_stored_blocklist(self):
        memcache.delete('media-blocklist')
        self.assertFalse(media_blocklisted(Object(our_as1={
            'image': [{'url': 'http://example.com/bad'}],
        }), None))

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
                self.assertFalse(media_blocklisted(Object(our_as1=obj_as1), None))

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
                self.assertTrue(media_blocklisted(Object(our_as1=obj_as1), None))

    @patch('requests.get', return_value=requests_response('blob contents'))
    def test_fetch_blob_fail(self, mock_get):
        memcache.set('media-blocklist',
                     'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq')
        self.assertTrue(media_blocklisted(Object(our_as1={
            'image': [{'url': 'http://example.com/new'}],
        }), None))
        mock_get.assert_has_calls(mock_get, [self.req('http://example.com/new')])


class DomainBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        self.blocklist = Object(id='global-domain-blocklist', is_csv=True,
                                csv='domain\nbad.com\nevil.org').put()
        filters.GLOBAL_DOMAIN_BLOCKLIST.loaded_at = None

    def test_no_stored_blocklist(self):
        self.blocklist.delete()
        self.assertFalse(domain_blocklisted(
            Object(our_as1={'id': 'https://bad.com/post'}), None))

    def test_pass(self):
        self.assertFalse(domain_blocklisted(Object(our_as1={
            'id': 'https://good.com/post',
            'author': 'https://good.com/user',
        }), None))

    def test_fail_obj_id(self):
        self.assertTrue(domain_blocklisted(
            Object(our_as1={'id': 'https://bad.com/post'}), None))

    def test_fail_actor(self):
        self.assertTrue(domain_blocklisted(
            Object(our_as1={'actor': 'https://bad.com/user'}), None))

    def test_fail_inner_object(self):
        self.assertTrue(domain_blocklisted(Object(our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {'id': 'https://bad.com/post'},
        }), None))

    def test_fail_from_user(self):
        from_user = self.make_user('fake://bad.com/', cls=Fake)
        self.assertTrue(domain_blocklisted(
            Object(our_as1={'id': 'https://good.com/post'}), from_user))
