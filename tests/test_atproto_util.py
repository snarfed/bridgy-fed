"""Unit tests for atproto_util.py."""

from multiformats import CID
from oauth_dropins.webutil.testutil import NOW

import atproto_util
from atproto_util import (
    dag_cbor_cid,
    datetime_to_tid,
    tid_to_datetime,
)
from . import testutil


class AtProtoUtilTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        atproto_util._clockid = 17

    def test_dag_cbor_cid(self):
        self.assertEqual(
            CID.decode('bafyreiblaotetvwobe7cu2uqvnddr6ew2q3cu75qsoweulzku2egca4dxq'),
            dag_cbor_cid({'foo': 'bar'}))

    def test_datetime_to_tid(self):
        self.assertEqual('3iom4o4g6u2l2', datetime_to_tid(NOW))

    def test_tid_to_datetime(self):
        self.assertEqual(NOW, tid_to_datetime('3iom4o4g6u2l2'))

