"""Unit tests for atproto_diff.py.

Heavily based on:
https://github.com/bluesky/atproto/blob/main/packages/repo/tests/sync/diff.test.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!
"""
import dag_cbor.random

from atproto_diff import Change, Diff
from atproto_mst import MST
from . import testutil


class AtProtoDiffTest(testutil.TestCase):

    def test_diffs(self):
        mst = MST()
        data = self.random_keys_and_cids(3)#1000)
        for key, cid in data:
            mst = mst.add(key, cid)

        before = after = mst

        to_add = self.random_keys_and_cids(1)#100)
        to_edit = data[1:2]
        to_del = data[0:1]

        # these are all {str key: Change}
        expected_adds = {}
        expected_updates = {}
        expected_deletes = {}

        for key, cid in to_add:
            after = after.add(key, cid)
            expected_adds[key] = Change(key=key, cid=cid)

        for (key, prev), new in zip(to_edit, dag_cbor.random.rand_cid()):
            after = after.update(key, new)
            expected_updates[key] = Change(key=key, prev=prev, cid=new)

        for key, cid in to_del:
            after = after.delete(key)
            expected_deletes[key] = Change(key=key, cid=cid)

        diff = Diff.of(after, before)

        self.assertEqual(1, len(diff.adds))
        self.assertEqual(1, len(diff.updates))
        self.assertEqual(1, len(diff.deletes))

        self.assertEqual(expected_adds, diff.adds)
        self.assertEqual(expected_updates, diff.updates)
        self.assertEqual(expected_deletes, diff.deletes)

        # ensure we correctly report all added CIDs
        for entry in after.walk():
            cid = entry.get_pointer() if isinstance(entry, MST) else entry.value
            # TODO
            # assert cid in blockstore or cid in diff.new_cids

