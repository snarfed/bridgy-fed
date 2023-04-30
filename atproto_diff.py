"""AT Protocol utility for diffing two MSTs.

Heavily based on:
https://github.com/bluesky/atproto/blob/main/packages/repo/src/mst/diff.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!
"""
from collections import namedtuple
import logging

from atproto_mst import Leaf, MST, Walker

logger = logging.getLogger(__name__)


def mst_diff(cur, prev=None):
    """Generates a diff between two MSTs.

    Args:
        cur: :class:`MST`
        prev: :class:`MST`, optional

    Returns:
        :class:`Diff`
    """
    cur.get_pointer()
    if not prev:
        return null_diff(cur)

    prev.get_pointer()
    diff = Diff()

    left_walker = Walker(prev)
    right_walker = Walker(cur)
    while not left_walker.status.done or not right_walker.status.done:
        # print(left_walker.status, right_walker.status)
        # if one walker is finished, continue walking the other & logging all nodes
        if left_walker.status.done and not right_walker.status.done:
            node = right_walker.status.cur
            if isinstance(node, Leaf):
                diff.record_add(node.key, node.value)
            else:
                diff.record_new_cid(node.pointer)
            right_walker.advance()
            continue

        elif not left_walker.status.done and right_walker.status.done:
            node = left_walker.status.cur
            if isinstance(node, Leaf):
                diff.record_delete(node.key, node.value)
            else:
                diff.record_removed_cid(node.pointer)
            left_walker.advance()
            continue

        if left_walker.status.done or right_walker.status.done:
            break

        left = left_walker.status.cur
        right = right_walker.status.cur
        if not left or not right:
            break

        # if both pointers are leaves, record an update & advance both or record
        # the lowest key and advance that pointer
        if isinstance(left, Leaf) and isinstance(right, Leaf):
            if left.key == right.key:
                if left.value != right.value:
                    diff.record_update(left.key, left.value, right.value)
                left_walker.advance()
                right_walker.advance()
            elif left.key < right.key:
                diff.record_delete(left.key, left.value)
                left_walker.advance()
            else:
                diff.record_add(right.key, right.value)
                right_walker.advance()

            continue

        # next, ensure that we're on the same layer
        #
        # if one walker is at a higher layer than the other, we need to do one
        # of two things if the higher walker is pointed at a tree, step into
        # that tree to try to catch up with the lower if the higher walker is
        # pointed at a leaf, then advance the lower walker to try to catch up
        # the higher
        if left_walker.layer() > right_walker.layer():
            if isinstance(left, Leaf):
                if isinstance(right, Leaf):
                    diff.record_add(right.key, right.value)
                else:
                    diff.record_new_cid(right.pointer)

                right_walker.advance()
            else:
                diff.record_removed_cid(left.pointer)
                left_walker.step_into()

            continue

        elif left_walker.layer() < right_walker.layer():
            if isinstance(right, Leaf):
                if isinstance(left, Leaf):
                    diff.record_delete(left.key, left.value)
                else:
                    diff.record_removed_cid(left.pointer)

                left_walker.advance()

            else:
                diff.record_new_cid(right.pointer)
                right_walker.step_into()

            continue

        # if we're on the same level, and both pointers are trees, do a
        # comparison. if they're the same, step over. if they're different, step
        # in to find the subdiff
        if isinstance(left, MST) and isinstance(right, MST):
            if left.pointer == right.pointer:
                left_walker.step_over()
                right_walker.step_over()
            else:
                diff.record_new_cid(right.pointer)
                diff.record_removed_cid(left.pointer)
                left_walker.step_into()
                right_walker.step_into()

            continue

        # finally, if one pointer is a tree and the other is a leaf, simply step
        # into the tree
        if isinstance(left, Leaf) and isinstance(right, MST):
            diff.record_new_cid(right.pointer)
            right_walker.step_into()
            continue

        elif isinstance(left, MST) and isinstance(right, Leaf):
            diff.record_removed_cid(left.pointer)
            left_walker.step_into()
            continue

        raise RuntimeError('Unidentifiable case in diff walk')

    return diff


def null_diff(tree):
    """Generates a "null" diff for a single MST with all adds and new CIDs.

    Args:
        tree: :class:`MST`

    Returns:
        :class:`Diff`
    """
    diff = Diff()

    for entry in tree.walk():
        if isinstance(entry, Leaf):
            diff.record_add(entry.key, entry.value)
        else:
            diff.record_new_cid(entry.pointer)

    return diff


Change = namedtuple('Change', [
    'key',   # str
    'cid',   # :class:`CID`
    'prev',  # :class:`CID`
], defaults=[None])


class Diff:
    """A diff between two MSTs.

    Attributes:
      adds: {str key: :class:`Change`}
      updates: {str key: :class:`Change`}
      deletes: {str key: :class:`Change`}
      new_cids: set of :class:`CID`
      removed_cids: set of :class:`CID`
    """

    def __init__(self):
        self.adds = {}
        self.updates = {}
        self.deletes = {}
        self.new_cids = set()
        self.removed_cids = set()

    @staticmethod
    def of(cur, prev=None):
        """
        Args:
          cur: :class:`MST`
          prev: :class:`MST`, optional

        Returns:
          :class:`Diff`
        """
        return mst_diff(cur, prev)

    def record_add(self, key, cid):
        """
        Args:
          key: str
          cid: :class:`CID`
        """
        self.adds[key] = Change(key=key, cid=cid)
        self.new_cids.add(cid)

    def record_update(self, key, prev, cid):
        """
        Args:
          key: str
          prev: :class:`CID`
          cid: :class:`CID`
        """
        self.updates[key] = Change(key=key, cid=cid, prev=prev)
        self.new_cids.add(cid)

    def record_delete(self, key, cid):
        """
        Args:
          key: str
          cid: :class:`CID`
        """
        self.deletes[key] = Change(key=key, cid=cid)

    def record_new_cid(self, cid):
        """
        Args:
          cid: :class:`CID`
        """
        if cid in self.removed_cids:
            self.removed_cids.remove(cid)
        else:
            self.new_cids.add(cid)

    def record_removed_cid(self, cid):
        """
        Args:
          cid: :class:`CID`
        """
        if cid in self.new_cids:
            self.new_cids.remove(cid)
        else:
            self.removed_cids.add(cid)

    def add_diff(self, diff):
        """
        Args:
          diff: :class:`Diff`
        """
        for add in diff.adds.values():
            if self.deletes[add.key]:
                deleted = self.deletes[add.key]
                if deleted.cid != add.cid:
                    self.record_update(add.key, deleted.cid, add.cid)
                del self.deletes[add.key]
            else:
                self.record_add(add.key, add.cid)

        for update in diff.updates.values():
            self.record_update(update.key, update.prev, update.cid)
            del self.adds[update.key]
            del self.deletes[update.key]

        for deleted in diff.deletes.values():
            if self.adds[deleted.key]:
                del self.adds[deleted.key]
            else:
                del self.updates[deleted.key]
                self.record_delete(deleted.key, deleted.cid)

        self.new_cids |= diff.new_cids

    def updated_keys(self):
        return self.adds | self.updates | self.deletes
