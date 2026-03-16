"""Unit tests for filters.py."""
from filters import (
    content_blocklisted,
)
from memcache import memcache
from models import Object, PROTOCOLS
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
