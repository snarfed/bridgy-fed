"""Unit tests for filters.py."""
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob
import filters
from filters import (
    content_blocklisted,
    domain_blocklisted,
    duplicate_content,
    media_blocklisted,
)
from models import Object, PROTOCOLS
from oauth_dropins.webutil.testutil import requests_response
from .testutil import Fake, OtherFake, TestCase


class ContentBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        self.blocklist = Object(id='internal:content-blocklist',
                                raw=['badword', 'spam']).put()
        filters.CONTENT_BLOCKLIST.loaded_at = None

    def test_pass(self):
        obj = Object(our_as1={'content': 'foo bar'})
        self.assertFalse(content_blocklisted(obj, None))

    def test_pass_no_stored_blocklist(self):
        self.blocklist.delete()
        filters.CONTENT_BLOCKLIST.loaded_at = None
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
        AtpRemoteBlob(id='http://example.com/bad', cid='badcid').put()
        self.blocklist = Object(id='internal:media-blocklist', raw=['badcid']).put()
        filters.MEDIA_BLOCKLIST.loaded_at = None

    def test_pass_no_stored_blocklist(self):
        self.blocklist.delete()
        filters.MEDIA_BLOCKLIST.loaded_at = None
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
        Object(id='internal:media-blocklist', raw=[
            'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq',
        ]).put()
        filters.MEDIA_BLOCKLIST.loaded_at = None
        self.assertTrue(media_blocklisted(Object(our_as1={
            'image': [{'url': 'http://example.com/new'}],
        }), None))
        mock_get.assert_has_calls(mock_get, [self.req('http://example.com/new')])


class DomainBlocklistedTest(TestCase):
    def setUp(self):
        super().setUp()
        self.blocklist = Object(id='internal:domain-blocklist',
                                raw=['bad.com', 'evil.org']).put()
        filters.DOMAIN_BLOCKLIST.loaded_at = None

    def test_no_stored_blocklist(self):
        self.blocklist.delete()
        self.assertFalse(domain_blocklisted(
            Object(our_as1={'id': 'https://bad.com/post'}), None))

    def test_pass(self):
        for obj_as1 in (
            {'id': 'https://good.com/post', 'author': 'https://good.com/user'},
            {'objectType': 'note'},  # no id or actor
        ):
            with self.subTest(obj_as1=obj_as1):
                self.assertFalse(domain_blocklisted(Object(our_as1=obj_as1), None))

    def test_fail(self):
        for obj_as1 in (
                {'id': 'https://bad.com/post'},
                {'actor': 'https://bad.com/user'},
                {
                    'objectType': 'activity',
                    'verb': 'post',
                    'object': {'id': 'https://bad.com/post'},
                },
        ):
            self.assertTrue(domain_blocklisted(Object(our_as1=obj_as1), None))

    def test_fail_from_user(self):
        from_user = self.make_user('fake://bad.com/', cls=Fake)
        self.assertTrue(domain_blocklisted(
            Object(our_as1={'id': 'https://good.com/post'}), from_user))


class DuplicateContentTest(TestCase):
    def test_pass(self):
        for obj_as1 in (
            {'id': 'fake:post', 'author': 'fake:user'},  # no text content
            {'content': 'hello', 'author': 'fake:user1'},  # first time
            {'content': 'hello', 'author': 'fake:user2'},  # same text, different user
            {'content': 'world', 'author': 'fake:user1'},  # same user, different text
        ):
            with self.subTest(obj_as1=obj_as1):
                self.assertFalse(duplicate_content(Object(our_as1=obj_as1), None))

    def test_pass_different_image(self):
        duplicate_content(Object(our_as1={'content': 'hello'}))
        self.assertFalse(duplicate_content(Object(our_as1={
            'content': 'hello', 'author': 'fake:user',
            'image': [{'url': 'http://example.com/1.jpg'}],
        }), None))
        self.assertFalse(duplicate_content(Object(our_as1={
            'content': 'hello', 'author': 'fake:user',
            'image': [{'url': 'http://example.com/2.jpg'}],
        }), None))

    def test_fail(self):
        for obj_as1, user in (
            ({'content': 'dup1', 'author': 'fake:user'}, None),
            ({'content': 'dup2'}, self.make_user('fake:user', cls=Fake)),
        ):
            with self.subTest(obj_as1=obj_as1):
                obj = Object(our_as1=obj_as1)
                duplicate_content(obj, user)  # store in memcache
                self.assertTrue(duplicate_content(obj, user))
