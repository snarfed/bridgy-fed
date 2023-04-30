"""Unit tests for atproto_util.py."""

from Crypto.PublicKey import ECC
from multiformats import CID
from oauth_dropins.webutil.testutil import NOW

import atproto_util
from atproto_util import (
    dag_cbor_cid,
    datetime_to_tid,
    sign_commit,
    tid_to_datetime,
    verify_commit_sig,
)
from . import testutil


class AtProtoUtilTest(testutil.TestCase):

    def test_dag_cbor_cid(self):
        self.assertEqual(
            CID.decode('bafyreiblaotetvwobe7cu2uqvnddr6ew2q3cu75qsoweulzku2egca4dxq'),
            dag_cbor_cid({'foo': 'bar'}))

    def test_datetime_to_tid(self):
        self.assertEqual('3iom4o4g6u2l2', datetime_to_tid(NOW))

    def test_tid_to_datetime(self):
        self.assertEqual(NOW, tid_to_datetime('3iom4o4g6u2l2'))

    def test_sign_commit_and_verify(self):
        user = self.make_user('user.com')

        commit = {'foo': 'bar'}
        key = ECC.import_key(user.p256_key)
        sign_commit(commit, key)
        assert verify_commit_sig(commit, key)

    def test_verify_commit_error(self):
        key = ECC.import_key(self.make_user('user.com').p256_key)
        with self.assertRaises(KeyError):
            self.assertFalse(verify_commit_sig({'foo': 'bar'}, key))

    def test_verify_commit_fail(self):
        key = ECC.import_key(self.make_user('user.com').p256_key)
        self.assertFalse(verify_commit_sig({'foo': 'bar', 'sig': 'nope'}, key))
