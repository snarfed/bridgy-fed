"""Unit tests for atproto_mst.py.

Heavily based on:
https://github.com/snarfed/atproto/blob/main/packages/repo/tests/mst.test.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!
"""
from base64 import b32encode
import time
import random
import string
from unittest import skip

import dag_cbor.random
from multiformats import CID

from atproto_mst import common_prefix_len, ensure_valid_key, MST
from . import testutil

# make random test data deterministic
random.seed(1234567890)

CID1 = CID.decode('bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454')


_tid_last = time.time_ns() // 1000  # microseconds
_tid_clockid = random.randint(0, 31)

def next_tid():
    global _tid_last

    # enforce that we're at least 1us after the last TID to prevent TIDs moving
    # backwards if system clock drifts backwards
    now = time.time_ns() // 1000
    if now > _tid_last:
        _tid_last = now
    else:
        _tid_last += 1
        now = _tid_last

    # the bottom 32 clock ids can be randomized & are not guaranteed to be
    # collision resistant. we use the same clockid for all TIDs coming from this
    # machine
    encoded = (
        b32encode(now.to_bytes((now.bit_length() + 7) // 8, byteorder='big')).decode() +
        b32encode(_tid_clockid.to_bytes((_tid_clockid.bit_length() + 7) // 8, byteorder='big')).ljust(2, b'2').decode()
    )
    return f'{encoded[:4]}-{encoded[4:7]}-{encoded[7:11]}-{encoded[11:]}'


def generate_bulk_data_keys(num):
    return {
        f'com.example.record/{i}': cid
        for i, cid in enumerate(dag_cbor.random.rand_cid(num))
    }


class MstTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.mst = MST()

        self.shuffled = list(generate_bulk_data_keys(10).items())
        random.shuffle(self.shuffled)

    def test_add(self):
        for entry in self.shuffled:
            self.mst = self.mst.add(entry[0], entry[1])

        for entry in self.shuffled:
            got = self.mst.get(entry[0])
            self.assertEqual(entry[1], got)

        self.assertEqual(10, self.mst.leaf_count())

    # def test_edits_records(self):
    #     edited_mst = self.mst
    #     to_edit = self.shuffled.slice(0, 100)

    #     edited = []
    #     for entry in to_edit:
    #         new_cid = util.random_cid()
    #         edited_mst = edited_mst.update(entry[0], new_cid)
    #         edited.append([entry[0], new_cid])

    #     for entry in edited:
    #         got = edited_mst.get(entry[0])
    #         self.assertEqual(entry[1], got)

    #     self.assertEqual(1000, edited_mst.leaf_count())

    # def test_deletes_records(self):
    #     deleted_mst = self.mst
    #     to_delete = self.shuffled[0:100]
    #     the_rest = self.shuffled[100:]
    #     for entry in to_delete:
    #         deleted_mst.delete(entry[0])

    #     self.assertEqual(900, deleted_mst.leaf_count())

    #     for entry in to_delete:
    #         self.assert_is_none(deleted_mst.get(entry[0]))

    #     for entry in the_rest:
    #         self.assertEqual(entry[1], deleted_mst.get(entry[0]))

    @skip
    def test_is_order_independent(self):
        all_nodes = self.mst.all_nodes()

        recreated = MST()
        reshuffled = random.shuffle(Object.entries(mapping))
        for entry in reshuffled:
            recreated.add(entry[0], entry[1])

        self.assertEqual(all_nodes, recreated.all_nodes())

    # def test_diffs(self):
    #     to_diff = self.mst

    #     to_add = Object.entries(util.generate_bulk_data_keys(100))
    #     to_edit = self.shuffled[500:600]
    #     to_del = self.shuffled[400:500]

    #     expected_updates = {}
    #     expected_dels = {}
    #     expected_adds = {entry[0]: {'key': entry[0], 'cid': entry[1]}
    #                     for entry in to_add.items()}

    #     for entry in to_add:
    #         to_diff.add(entry[0], entry[1])
    #         expected_adds[entry[0]] = x

    #     for entry in to_edit:
    #         updated = util.random_cid()
    #         to_diff.update(entry[0], updated)
    #         expected_updates[entry[0]] = {
    #             'key': entry[0],
    #             'prev': entry[1],
    #             'cid': updated,
    #         }

    #     for entry in to_del:
    #         to_diff.delete(entry[0])
    #         expected_dels[entry[0]] = {'key': entry[0], 'cid': entry[1]}

    #     diff = DataDiff.of(to_diff, self.mst)

    #     self.assertEqual(100, len(diff.add_list()))
    #     self.assertEqual(100, len(diff.update_list()))
    #     self.assertEqual(100, len(diff.delete_list()))

    #     self.assertEqual(expected_adds, diff.adds)
    #     self.assertEqual(expected_updates, diff.updates)
    #     self.assertEqual(expected_dels, diff.deletes)

    #     # ensure we correctly report all added CIDs
    #     for entry in to_diff.walk():
    #         cid = entry.get_pointer() if entry.is_tree() else entry.value
    #         self.assert_true(blockstore.has(cid) or diff.new_cids.has(cid))

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
            self.mst.add('')

    def test_rejects_a_key_with_no_collection(self):
        with self.assertRaises(ValueError):
            self.mst.add('asdf')

    def test_rejects_a_key_with_a_nested_collection(self):
        with self.assertRaises(ValueError):
            self.mst.add('nested/collection/asdf')

    def test_rejects_on_empty_coll_or_rkey(self):
        for key in 'coll/', '/rkey':
            with self.assertRaises(ValueError):
                self.mst.add(key)

    def test_rejects_non_ascii_chars(self):
        for key in 'coll/jalapeñoA', 'coll/coöperative', 'coll/abc💩':
            with self.assertRaises(ValueError):
                self.mst.add(key)

    def test_rejects_ascii_that_we_dont_support(self):
        for key in ('coll/key$', 'coll/key%', 'coll/key(', 'coll/key)',
                    'coll/key+', 'coll/key='):
            with self.assertRaises(ValueError):
                self.mst.add(key)

    def test_rejects_keys_over_256_chars(self):
        with self.assertRaises(ValueError):
            self.mst.add(
            'coll/asdofiupoiwqeurfpaosidfuapsodirupasoirupasoeiruaspeoriuaspeoriu2p3o4iu1pqw3oiuaspdfoiuaspdfoiuasdfpoiasdufpwoieruapsdofiuaspdfoiuasdpfoiausdfpoasidfupasodifuaspdofiuasdpfoiasudfpoasidfuapsodfiuasdpfoiausdfpoasidufpasodifuapsdofiuasdpofiuasdfpoaisdufpao',
        )

    @skip
    def test_computes_empty_tree_root_CID(self):
        self.assertEqual(0, self.mst.leaf_count())
        self.assertEqual(
            'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm',
            str(self.mst.get_pointer()))

    # def test_computes_trivial_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fo2j', CID1)
    #     self.assertEqual(1, self.mst.leaf_count())
    #     self.assertEqual(
    #         'bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu',
    #         str(self.mst.get_pointer()))

    # def test_computes_singlelayer2_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1)
    #     self.assertEqual(1, self.mst.leaf_count())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(
    #         'bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai',
    #         str(self.mst.get_pointer()))

    # def test_computes_simple_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fr2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fc2j', CID1) # level 0
    #     self.assertEqual(5, self.mst.leaf_count())
    #     self.assertEqual(
    #         'bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m',
    #         str(self.mst.get_pointer()))

    # def test_trims_top_of_tree_on_delete(self):
    #     l1root = 'bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4'
    #     l0root = 'bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi'

    #     self.mst.add('com.example.record/3jqfcqzm3fn2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fo2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fu2j', CID1) # level 0

    #     self.assertEqual(6, self.mst.leaf_count())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(self.mst.get_pointer()))

    #     self.mst.delete('com.example.record/3jqfcqzm3fs2j') # level 1
    #     self.assertEqual(5, self.mst.leaf_count())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(self.mst.get_pointer()))

    # def test_handles_insertion_that_splits_two_layers_down(self):
    #     """
    #                 *                                *
    #        _________|________                    ____|_____
    #        |   |    |    |   |                  |    |     |
    #        *   d    *    i   *       ->         *    f     *
    #      __|__    __|__    __|__              __|__      __|___
    #     |  |  |  |  |  |  |  |  |            |  |  |    |  |   |
    #     a  b  c  e  g  h  j  k  l            *  d  *    *  i   *
    #                                        __|__   |   _|_   __|__
    #                                       |  |  |  |  |   | |  |  |
    #                                       a  b  c  e  g   h j  k  l
    #     """
    #     l1root = 'bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem'
    #     l2root = 'bafyreid2x5eqs4w4qxvc5jiwda4cien3gw2q6cshofxwnvv7iucrmfohpm'

    #     self.mst.add('com.example.record/3jqfcqzm3fo2j', CID1) # A; level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # B; level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fr2j', CID1) # C; level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # D; level 1
    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # E; level 0
    #     # GAP for F
    #     self.mst.add('com.example.record/3jqfcqzm3fz2j', CID1) # G; level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fc2j', CID1) # H; level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fd2j', CID1) # I; level 1
    #     self.mst.add('com.example.record/3jqfcqzm4ff2j', CID1) # J; level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fg2j', CID1) # K; level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fh2j', CID1) # L; level 0

    #     self.assertEqual(11, self.mst.leaf_count())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(self.mst.get_pointer()))

    #     # insert F, which will push E out in the node with G+H to a new node under D
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # F; level 2
    #     self.assertEqual(12, self.mst.leaf_count())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(self.mst.get_pointer()))

    #     # remove F, which should push E back over with G+H
    #     self.mst.delete('com.example.record/3jqfcqzm3fx2j') # F; level 2
    #     self.assertEqual(11, self.mst.leaf_count())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(self.mst.get_pointer()))

    # def test_handles_new_layers_that_are_two_higher_than_existing(self):
    #     """
    #          *        ->            *
    #        __|__                  __|__
    #       |     |                |  |  |
    #       a     c                *  b  *
    #                              |     |
    #                              *     *
    #                              |     |
    #                              a     c
    #     """

    #     l0root = 'bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky'
    #     l2root = 'bafyreiavxaxdz7o7rbvr3zg2liox2yww46t7g6hkehx4i4h3lwudly7dhy'
    #     l2root2 = 'bafyreig4jv3vuajbsybhyvb7gggvpwh2zszwfyttjrj6qwvcsp24h6popu'

    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # A; level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fz2j', CID1) # C; level 0
    #     self.assertEqual(2, self.mst.leaf_count())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(self.mst.get_pointer()))

    #     # insert B, which is two levels above
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
    #     self.assertEqual(3, self.mst.leaf_count())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(self.mst.get_pointer()))

    #     # remove B
    #     self.mst.delete('com.example.record/3jqfcqzm3fx2j') # B; level 2
    #     self.assertEqual(2, self.mst.leaf_count())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(self.mst.get_pointer()))

    #     # insert B (level=2) and D (level=1)
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
    #     self.mst.add('com.example.record/3jqfcqzm4fd2j', CID1) # D; level 1
    #     self.assertEqual(4, self.mst.leaf_count())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root2, str(self.mst.get_pointer()))

    #     # remove D
    #     self.mst.delete('com.example.record/3jqfcqzm4fd2j') # D; level 1
    #     self.assertEqual(3, self.mst.leaf_count())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(self.mst.get_pointer()))
