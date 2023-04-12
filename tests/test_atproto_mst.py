"""Unit tests for atproto_mst.py.

Heavily based on:
https://github.com/snarfed/atproto/blob/main/packages/repo/tests/mst.test.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!
"""
from unittest import mock, skip

from multiformats import CID

from atproto_mst import common_prefix_len, ensure_valid_key, MST
from . import testutil

CID1 = CID.decode('bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454')


class MstTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.mst = MST()

    # def test_add(self):
    #     for entry in shuffled:
    #         self.mst.add(entry[0], entry[1])

    #     for entry in shuffled:
    #         got = self.mst.get(entry[0])
    #         self.assertEqual(entry[1], got)

    #     self.assertEqual(1000, self.mst.leafCount())

    # def test_edits_records(self):
    #     editedMst = self.mst
    #     toEdit = shuffled.slice(0, 100)

    #     edited = []
    #     for entry in toEdit:
    #         newCid = util.randomCid()
    #         editedMst = editedMst.update(entry[0], newCid)
    #         edited.append([entry[0], newCid])

    #     for entry in edited:
    #         got = editedMst.get(entry[0])
    #         self.assertEqual(entry[1], got)

    #     self.assertEqual(1000, editedMst.leafCount())

    # def test_deletes_records(self):
    #     deletedMst = self.mst
    #     toDelete = shuffled[0:100]
    #     theRest = shuffled[100:]
    #     for entry in toDelete:
    #         deletedMst.delete(entry[0])

    #     self.assertEqual(900, deletedMst.leafCount())

    #     for entry in toDelete:
    #         self.assertIsNone(deletedMst.get(entry[0]))

    #     for entry in theRest:
    #         self.assertEqual(entry[1], deletedMst.get(entry[0]))

    # def test_is_order_independent(self):
    #     allNodes = self.mst.allNodes()

    #     recreated = MST.create(blockstore)
    #     reshuffled = util.shuffle(Object.entries(mapping))
    #     for entry in reshuffled:
    #         recreated.add(entry[0], entry[1])

    #     self.assertEqual(allNodes, recreated.allNodes())

    # @skip
    # def test_saves_and_loads_from_blockstore(self):
    #     root = util.saveMst(blockstore, self.mst)
    #     loaded = MST.load(blockstore, root)
    #     self.assertEqual(self.mst.allNodes(), loaded.allNodes())

    # def test_diffs(self):
    #     toDiff = self.mst

    #     toAdd = Object.entries(
    #         util.generateBulkDataKeys(100, blockstore),
    #     )
    #     toEdit = shuffled[500:600]
    #     toDel = shuffled[400:500]

    #     expectedUpdates = {}
    #     expectedDels = {}
    #     expectedAdds = {entry[0]: {'key': entry[0], 'cid': entry[1]}
    #                     for entry in toAdd.items()}

    #     for entry in toAdd:
    #         toDiff.add(entry[0], entry[1])
    #         expectedAdds[entry[0]] = x

    #     for entry in toEdit:
    #         updated = util.randomCid()
    #         toDiff.update(entry[0], updated)
    #         expectedUpdates[entry[0]] = {
    #             'key': entry[0],
    #             'prev': entry[1],
    #             'cid': updated,
    #         }

    #     for entry in toDel:
    #         toDiff.delete(entry[0])
    #         expectedDels[entry[0]] = {'key': entry[0], 'cid': entry[1]}

    #     diff = DataDiff.of(toDiff, self.mst)

    #     self.assertEqual(100, len(diff.addList()))
    #     self.assertEqual(100, len(diff.updateList()))
    #     self.assertEqual(100, len(diff.deleteList()))

    #     self.assertEqual(expectedAdds, diff.adds)
    #     self.assertEqual(expectedUpdates, diff.updates)
    #     self.assertEqual(expectedDels, diff.deletes)

    #     # ensure we correctly report all added CIDs
    #     for entry in toDiff.walk():
    #         cid = entry.getPointer() if entry.isTree() else entry.value
    #         self.assertTrue(blockstore.has(cid) or diff.newCids.has(cid))

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

    # def test_computes_empty_tree_root_CID(self):
    #     self.assertEqual(0, self.mst.leafCount())
    #     self.assertEqual(
    #         'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm',
    #         str(mst.getPointer()))

    # def test_computes_trivial_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fo2j', CID1)
    #     self.assertEqual(1, self.mst.leafCount())
    #     self.assertEqual(
    #         'bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu',
    #         str(mst.getPointer()))

    # def test_computes_singlelayer2_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1)
    #     self.assertEqual(1, self.mst.leafCount())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(
    #         'bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai',
    #         str(mst.getPointer()))

    # def test_computes_simple_tree_root_CID(self):
    #     self.mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fr2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm4fc2j', CID1) # level 0
    #     self.assertEqual(5, self.mst.leafCount())
    #     self.assertEqual(
    #         'bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m',
    #         str(mst.getPointer()))

    # def test_trims_top_of_tree_on_delete(self):
    #     l1root = 'bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4'
    #     l0root = 'bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi'

    #     self.mst.add('com.example.record/3jqfcqzm3fn2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fo2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fp2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fs2j', CID1) # level 1
    #     self.mst.add('com.example.record/3jqfcqzm3ft2j', CID1) # level 0
    #     self.mst.add('com.example.record/3jqfcqzm3fu2j', CID1) # level 0

    #     self.assertEqual(6, self.mst.leafCount())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(mst.getPointer()))

    #     self.mst.delete('com.example.record/3jqfcqzm3fs2j') # level 1
    #     self.assertEqual(5, self.mst.leafCount())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(mst.getPointer()))

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

    #     self.assertEqual(11, self.mst.leafCount())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(mst.getPointer()))

    #     # insert F, which will push E out in the node with G+H to a new node under D
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # F; level 2
    #     self.assertEqual(12, self.mst.leafCount())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(mst.getPointer()))

    #     # remove F, which should push E back over with G+H
    #     self.mst.delete('com.example.record/3jqfcqzm3fx2j') # F; level 2
    #     self.assertEqual(11, self.mst.leafCount())
    #     self.assertEqual(1, self.mst.layer)
    #     self.assertEqual(l1root, str(mst.getPointer()))

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
    #     self.assertEqual(2, self.mst.leafCount())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(mst.getPointer()))

    #     # insert B, which is two levels above
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
    #     self.assertEqual(3, self.mst.leafCount())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(mst.getPointer()))

    #     # remove B
    #     self.mst.delete('com.example.record/3jqfcqzm3fx2j') # B; level 2
    #     self.assertEqual(2, self.mst.leafCount())
    #     self.assertEqual(0, self.mst.layer)
    #     self.assertEqual(l0root, str(mst.getPointer()))

    #     # insert B (level=2) and D (level=1)
    #     self.mst.add('com.example.record/3jqfcqzm3fx2j', CID1) # B; level 2
    #     self.mst.add('com.example.record/3jqfcqzm4fd2j', CID1) # D; level 1
    #     self.assertEqual(4, self.mst.leafCount())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root2, str(mst.getPointer()))

    #     # remove D
    #     self.mst.delete('com.example.record/3jqfcqzm4fd2j') # D; level 1
    #     self.assertEqual(3, self.mst.leafCount())
    #     self.assertEqual(2, self.mst.layer)
    #     self.assertEqual(l2root, str(mst.getPointer()))
