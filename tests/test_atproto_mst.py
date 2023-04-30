"""Unit tests for atproto_mst.py.

Heavily based on:
https://github.com/bluesky/atproto/blob/main/packages/repo/tests/mst.test.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!
"""
from base64 import b32encode
from datetime import datetime
import time
import random
import string
from unittest import skip

import dag_cbor.random
from multiformats import CID

from atproto_mst import common_prefix_len, ensure_valid_key, MST
import atproto_util
from . import testutil

CID1 = CID.decode('bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454')


class MstTest(testutil.TestCase):

    def test_add(self):
        mst = MST()
        data = self.random_keys_and_cids(1000)
        for key, cid in data:
            mst = mst.add(key, cid)

        for key, cid in data:
            got = mst.get(key)
            self.assertEqual(cid, got)

        self.assertEqual(1000, mst.leaf_count())

    def test_edits_records(self):
        mst = MST()
        data = self.random_keys_and_cids(100)

        for key, cid in data:
            mst = mst.add(key, cid)

        edited = []
        for (key, _), cid in zip(data, dag_cbor.random.rand_cid()):
            mst = mst.update(key, cid)
            edited.append([key, cid])

        for key, cid in edited:
            self.assertEqual(cid, mst.get(key))

        self.assertEqual(100, mst.leaf_count())

    def test_deletes_records(self):
        mst = MST()
        data = self.random_keys_and_cids(1000)
        for key, cid in data:
            mst = mst.add(key, cid)

        to_delete = data[:100]
        the_rest = data[100:]
        for key, _ in to_delete:
            mst = mst.delete(key)

        self.assertEqual(900, mst.leaf_count())

        for key, _ in to_delete:
            self.assertIsNone(mst.get(key))

        for key, cid in the_rest:
            self.assertEqual(cid, mst.get(key))

    def test_is_order_independent(self):
        mst = MST()
        data = self.random_keys_and_cids(1000)
        for key, cid in data:
            mst = mst.add(key, cid)

        all_nodes = mst.all_nodes()

        recreated = MST()
        random.shuffle(data)
        for key, cid in data:
            recreated = recreated.add(key, cid)

        self.assertEqual(all_nodes, recreated.all_nodes())

    def test_common_prefix_length(self):
        self.assertEqual(3, common_prefix_len('abc', 'abc'))
        self.assertEqual(0, common_prefix_len('', 'abc'))
        self.assertEqual(0, common_prefix_len('abc', ''))
        self.assertEqual(2, common_prefix_len('ab', 'abc'))
        self.assertEqual(2, common_prefix_len('abc', 'ab'))
        self.assertEqual(3, common_prefix_len('abcde', 'abc'))
        self.assertEqual(3, common_prefix_len('abc', 'abcde'))
        self.assertEqual(3, common_prefix_len('abcde', 'abc1'))
        self.assertEqual(2, common_prefix_len('abcde', 'abb'))
        self.assertEqual(0, common_prefix_len('abcde', 'qbb'))
        self.assertEqual(0, common_prefix_len('', 'asdf'))
        self.assertEqual(3, common_prefix_len('abc', 'abc\x00'))
        self.assertEqual(3, common_prefix_len('abc\x00', 'abc'))

    def test_rejects_the_empty_key(self):
        with self.assertRaises(ValueError):
            MST().add('')

    def test_rejects_a_key_with_no_collection(self):
        with self.assertRaises(ValueError):
            MST().add('asdf')

    def test_rejects_a_key_with_a_nested_collection(self):
        with self.assertRaises(ValueError):
            MST().add('nested/collection/asdf')

    def test_rejects_on_empty_coll_or_rkey(self):
        for key in 'coll/', '/rkey':
            with self.assertRaises(ValueError):
                MST().add(key)

    def test_rejects_non_ascii_chars(self):
        for key in 'coll/jalapeñoA', 'coll/coöperative', 'coll/abc💩':
            with self.assertRaises(ValueError):
                MST().add(key)

    def test_rejects_ascii_that_we_dont_support(self):
        for key in ('coll/key$', 'coll/key%', 'coll/key(', 'coll/key)',
                    'coll/key+', 'coll/key='):
            with self.assertRaises(ValueError):
                MST().add(key)

    def test_rejects_keys_over_256_chars(self):
        with self.assertRaises(ValueError):
            MST().add(
            'coll/asdofiupoiwqeurfpaosidfuapsodirupasoirupasoeiruaspeoriuaspeoriu2p3o4iu1pqw3oiuaspdfoiuaspdfoiuasdfpoiasdufpwoieruapsdofiuaspdfoiuasdpfoiausdfpoasidfupasodifuaspdofiuasdpfoiasudfpoasidfuapsodfiuasdpfoiausdfpoasidufpasodifuapsdofiuasdpofiuasdfpoaisdufpao',
        )

    def test_computes_empty_tree_root_CID(self):
        self.assertEqual(0, MST().leaf_count())
        self.assertEqual(
            'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm',
            MST().get_pointer().encode('base32'))

    def test_computes_trivial_tree_root_CID(self):
        mst = MST().add('com.example.record/3jqfcqzm3fo2j', CID1)
        self.assertEqual(1, mst.leaf_count())
        self.assertEqual(
            'bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu',
            mst.get_pointer().encode('base32'))

    def test_computes_single_layer_2_tree_root_CID(self):
        mst = MST().add('com.example.record/3jqfcqzm3fx2j', CID1)
        self.assertEqual(1, mst.leaf_count())
        self.assertEqual(2, mst.layer)
        self.assertEqual(
            'bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai',
            mst.get_pointer().encode('base32'))

    def test_computes_simple_tree_root_CID(self):
        mst = MST()
        mst = mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fr2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
        mst = mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm4fc2j', CID1) # level 0
        self.assertEqual(5, mst.leaf_count())
        self.assertEqual(
            'bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m',
            mst.get_pointer().encode('base32'))

    def test_trims_top_of_tree_on_delete(self):
        l1root = 'bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4'
        l0root = 'bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi'

        mst = MST()
        mst = mst.add('com.example.record/3jqfcqzm3fn2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fo2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
        mst = mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
        mst = mst.add('com.example.record/3jqfcqzm3fu2j', CID1) # level 0

        self.assertEqual(6, mst.leaf_count())
        self.assertEqual(1, mst.layer)
        self.assertEqual(l1root, mst.get_pointer().encode('base32'))

        mst = mst.delete('com.example.record/3jqfcqzm3fs2j') # level 1
        self.assertEqual(5, mst.leaf_count())
        self.assertEqual(0, mst.layer)
        self.assertEqual(l0root, mst.get_pointer().encode('base32'))

    def test_handles_insertion_that_splits_two_layers_down(self):
        """
                    *                                *
           _________|________                    ____|_____
           |   |    |    |   |                  |    |     |
           *   d    *    i   *       ->         *    f     *
         __|__    __|__    __|__              __|__      __|___
        |  |  |  |  |  |  |  |  |            |  |  |    |  |   |
        a  b  c  e  g  h  j  k  l            *  d  *    *  i   *
                                           __|__   |   _|_   __|__
                                          |  |  |  |  |   | |  |  |
                                          a  b  c  e  g   h j  k  l
        """
        l1root = 'bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem'
        l2root = 'bafyreid2x5eqs4w4qxvc5jiwda4cien3gw2q6cshofxwnvv7iucrmfohpm'

        mst = MST()
        mst = mst.add('com.example.record/3jqfcqzm3fo2j', CID1) # A; level 0
        mst = mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # B; level 0
        mst = mst.add('com.example.record/3jqfcqzm3fr2j', CID1) # C; level 0
        mst = mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # D; level 1
        mst = mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # E; level 0
        # GAP for F
        mst = mst.add('com.example.record/3jqfcqzm3fz2j', CID1) # G; level 0
        mst = mst.add('com.example.record/3jqfcqzm4fc2j', CID1) # H; level 0
        mst = mst.add('com.example.record/3jqfcqzm4fd2j', CID1) # I; level 1
        mst = mst.add('com.example.record/3jqfcqzm4ff2j', CID1) # J; level 0
        mst = mst.add('com.example.record/3jqfcqzm4fg2j', CID1) # K; level 0
        mst = mst.add('com.example.record/3jqfcqzm4fh2j', CID1) # L; level 0

        self.assertEqual(11, mst.leaf_count())
        self.assertEqual(1, mst.layer)
        self.assertEqual(l1root, mst.get_pointer().encode('base32'))

        # insert F, which will push E out in the node with G+H to a new node under D
        mst = mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # F; level 2
        self.assertEqual(12, mst.leaf_count())
        self.assertEqual(2, mst.layer)
        self.assertEqual(l2root, mst.get_pointer().encode('base32'))

        # remove F, which should push E back over with G+H
        mst = mst.delete('com.example.record/3jqfcqzm3fx2j') # F; level 2
        self.assertEqual(11, mst.leaf_count())
        self.assertEqual(1, mst.layer)
        self.assertEqual(l1root, mst.get_pointer().encode('base32'))

    def test_handles_new_layers_that_are_two_higher_than_existing(self):
        """
             *        ->            *
           __|__                  __|__
          |     |                |  |  |
          a     c                *  b  *
                                 |     |
                                 *     *
                                 |     |
                                 a     c
        """

        l0root = 'bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky'
        l2root = 'bafyreiavxaxdz7o7rbvr3zg2liox2yww46t7g6hkehx4i4h3lwudly7dhy'
        l2root2 = 'bafyreig4jv3vuajbsybhyvb7gggvpwh2zszwfyttjrj6qwvcsp24h6popu'

        mst = MST()
        mst = mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # A; level 0
        mst = mst.add('com.example.record/3jqfcqzm3fz2j', CID1) # C; level 0
        self.assertEqual(2, mst.leaf_count())
        self.assertEqual(0, mst.layer)
        self.assertEqual(l0root, mst.get_pointer().encode('base32'))

        # insert B, which is two levels above
        mst = mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
        self.assertEqual(3, mst.leaf_count())
        self.assertEqual(2, mst.layer)
        self.assertEqual(l2root, mst.get_pointer().encode('base32'))

        # remove B
        mst = mst.delete('com.example.record/3jqfcqzm3fx2j') # B; level 2
        self.assertEqual(2, mst.leaf_count())
        self.assertEqual(0, mst.layer)
        self.assertEqual(l0root, mst.get_pointer().encode('base32'))

        # insert B (level=2) and D (level=1)
        mst = mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
        mst = mst.add('com.example.record/3jqfcqzm4fd2j', CID1) # D; level 1
        self.assertEqual(4, mst.leaf_count())
        self.assertEqual(2, mst.layer)
        self.assertEqual(l2root2, mst.get_pointer().encode('base32'))

        # remove D
        mst = mst.delete('com.example.record/3jqfcqzm4fd2j') # D; level 1
        self.assertEqual(3, mst.leaf_count())
        self.assertEqual(2, mst.layer)
        self.assertEqual(l2root, mst.get_pointer().encode('base32'))
