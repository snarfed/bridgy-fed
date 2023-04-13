"""Bluesky / AT Protocol Merkle search tree implementation.

* https://atproto.com/guides/data-repos
* https://atproto.com/lexicons/com-atproto-sync
* https://hal.inria.fr/hal-02303490/document

Heavily based on:
https://github.com/snarfed/atproto/blob/main/packages/repo/src/mst/mst.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically!

Notable differences:
* All in memory, no block storage (yet)
X * MST class is mutable, not immutable

From that file:

This is an implementation of a Merkle Search Tree (MST)
The data structure is described here: https://hal.inria.fr/hal-02303490/document
The MST is an ordered, insert-order-independent, deterministic tree.
Keys are laid out in alphabetic order.
The key insight of an MST is that each key is hashed and starting 0s are counted
to determine which layer it falls on (5 zeros for ~32 fanout).
This is a merkle tree, so each subtree is referred to by it's hash (CID).
When a leaf is changed, ever tree on the path to that leaf is changed as well,
thereby updating the root hash.

For atproto, we use SHA-256 as the key hashing algorithm, and ~4 fanout
(2-bits of zero per layer).

A couple notes on CBOR encoding:

There are never two neighboring subtrees.
Therefore, we can represent a node as an array of
leaves & pointers to their right neighbor (possibly null),
along with a pointer to the left-most subtree (also possibly null).

Most keys in a subtree will have overlap.
We do compression on prefixes by describing keys as:
* the length of the prefix that it shares in common with the preceding key
* the rest of the string

For example:

If the first leaf in a tree is `bsky/posts/abcdefg` and the second is
`bsky/posts/abcdehi` Then the first will be described as `prefix: 0, key:
'bsky/posts/abcdefg'`, and the second will be described as `prefix: 16, key:
'hi'.`
"""
from collections import namedtuple
from hashlib import sha256
from os.path import commonprefix
import re


Entry = namedtuple('Entry', [
    'p',  # int, length of prefix that this key shares with the prev key
    'k',  # bytes, the rest of the key outside the shared prefix
    'v',  # str CID, value
    't',  # str CID, next subtree (to the right of leaf), or None
])

Data = namedtuple('Data', [
    'l',  # str CID, left-most subtree, or None
    'e',  # list of Entry
])

Leaf = namedtuple('Leaf', [
    'key',    # str, record key ???
    'value',  # CID ???
])


class MST:
    """Merkle search tree class.

    Attributes:
      entries: sequence of :class:`MST` and :class:`Leaf`
      layer: int, this MST's layer in the root MST
      pointer: :class:`CID`
      outdated_pointer: boolean, ???
    """
    entries = None
    layer = None
    pointer = None
    outdated_pointer = False

#     def __init__(
#         pointer: CID,
#         entries: NodeEntry[],
#         layer: number,
#     ):
#         assert pointer
#         self.entries = entries
#         self.layer = layer
#         self.pointer = pointer

    def __init__(self):
        """Constructor."""
        # self.pointer = cid_for_entries(entries)
        # { layer = None } = opts or {}
        # return MST(pointer, entries, layer)

#     def from_data(
#         data: NodeData,
#         opts?: Partial<MstOpts>,
#     ):
#     """
#     Returns:
#       MST
#     """
#         { layer = None } = opts or {}
#         entries = deserialize_node_data(data, opts)
#         pointer = cid_for_cbor(data)
#         return new MST(pointer, entries, layer)

    def __eq__(self, other):
        if isinstance(other, MST):
            return self.get_pointer() == other.get_pointer()

#     # Getters (lazy load)
#     # -------------------

    # We don't want to load entries of every subtree, just the ones we need
    def get_entries(self):
        """
        Returns:
          sequence of :class:`MST` and :class:`Leaf`
        """
#         if self.entries:
#             return [...self.entries]

#         if self.pointer:
#             data = self.storage.read_obj(self.pointer, node_data_def)
#             first_leaf = data.e[0]
#             layer =
#                 first_leaf != undefined
#                     ? leading_zeros_on_hash(first_leaf.k)
#                     : undefined
#             self.entries = deserialize_node_data(self.storage, data, {
#                 layer,
#             })

#             return self.entries
#         throw new Error('No entries or CID provided')

    def get_pointer(self):
       """Returns this MST's root CID ??? pointer. Calculates it if needed.

       We don't hash the node on every mutation for performance reasons. Instead
       we keep track of whether the pointer is outdated and only (recursively)
       calculate when needed.

       Returns:
         :class:`CID`
       """
#         if not self.outdated_pointer:
#             return self.pointer
#         entries = self.get_entries()
#         outdated = entries.filter(
#             (e) => e.is_tree() and e.outdated_pointer,
#         ) as MST[]
#         if outdated.length > 0:
#             Promise.all(outdated.map((e) => e.get_pointer()))
#             entries = self.get_entries()
#         self.pointer = cid_for_entries(entries)
#         self.outdated_pointer = false
#         return self.pointer

    def get_layer(self):
        """Returns this MST's layer, and sets self.layer.

        In most cases, we get the layer of a node from a hint on creation. In the
        case of the topmost node in the tree, we look for a key in the node &
        determine the layer. In the case where we don't find one, we recurse down
        until we do. If we still can't find one, then we have an empty tree and the
        node is layer 0.

        Returns:
          int
        """
        # self.layer = self.attempt_get_layer()
        # if self.layer == None:
        #     self.layer = 0
        # return self.layer

    def attempt_get_layer(self):
        """Returns this MST's layer, and sets self.layer.

        Returns:
          int or None
        """
#         if self.layer != None:
#             return self.layer
#         entries = self.get_entries()
#         layer = layer_for_entries(entries)
#         if layer == None:
#             for entry in entries:
#                 if entry.is_tree():
#                     child_layer = entry.attempt_get_layer()
#                     if child_layer != None:
#                         layer = child_layer + 1
#                         break
#         if layer != None:
#             self.layer = layer
#         return layer

    # Core functionality
    # -------------------

    def add(self, key, value=None, known_zeros=None):
        """Adds a new leaf for the given key/value pair.

        Args:
          key: str
          value: :class:`CID`
          known_zeros: int

        Raises:
          ValueError if a leaf with that key already exists
        """
        ensure_valid_key(key)
#         key_zeros = known_zeros ?? (leading_zeros_on_hash(key))
#         layer = self.get_layer()
#         new_leaf = new Leaf(key, value)
#         if key_zeros == layer:
#             # it belongs in self layer
#             index = self.find_gt_or_equal_leaf_index(key)
#             found = self.at_index(index)
#             if found.is_leaf() and found.key == key:
#                 throw new Error(`There is already a value at key: ${key}`)
#             prev_node = self.at_index(index - 1)
#             if not prev_node or prev_node.is_leaf():
#                 # if entry before is a leaf, (or we're on far left) we can just splice in
#                 return self.splice_in(new_leaf, index)
#             else:
#                 # else we try to split the subtree around the key
#                 split_sub_tree = prev_node.split_around(key)
#                 return self.replace_with_split(
#                     index - 1,
#                     split_sub_tree[0],
#                     new_leaf,
#                     split_sub_tree[1],
#                 )
#         else if key_zeros < layer:
#             # it belongs on a lower layer
#             index = self.find_gt_or_equal_leaf_index(key)
#             prev_node = self.at_index(index - 1)
#             if prev_node and prev_node.is_tree():
#                 # if entry before is a tree, we add it to that tree
#                 new_subtree = prev_node.add(key, value, key_zeros)
#                 return self.update_entry(index - 1, new_subtree)
#             else:
#                 sub_tree = self.create_child()
#                 new_sub_tree = sub_tree.add(key, value, key_zeros)
#                 return self.splice_in(new_sub_tree, index)
#         else:
#             # it belongs on a higher layer & we must push the rest of the tree down
#             split = self.split_around(key)
#             # if the newly added key has >=2 more leading zeros than the current highest layer
#             # then we need to add in structural nodes in between as well
#             left: MST | None = split[0]
#             right: MST | None = split[1]
#             layer = self.get_layer()
#             extra_layers_to_add = key_zeros - layer
#             # intentionally starting at 1, since first layer is taken care of by split
#             for i in range(1, extra_layers_to_add):
#                 if left != None:
#                     left = left.create_parent()
#                 if right != None:
#                     right = right.create_parent()
#             updated: NodeEntry[] = []
#             if left:
#                 updated.push(left)
#             updated.push(new Leaf(key, value))
#             if right:
#                 updated.push(right)
#             new_root = MST.create(updated, {
#                 layer: key_zeros,
#             })
#             new_root.outdated_pointer = true
#             return new_root

    def get(self, key):
        """Gets the value at the given key.

        Args:
          key: str

        Returns:
          :class:`CID` or None
        """
#         index = self.find_gt_or_equal_leaf_index(key)
#         found = self.at_index(index)
#         if found and found.is_leaf() and found.key == key:
#             return found.value
#         prev = self.at_index(index - 1)
#         if prev and prev.is_tree():
#             return prev.get(key)
#         return None

    def update(self, key, value):
        """Edits the value at the given key

        Args:
          key: str
          value: :class:`CID`

        Returns:
          MST

        Raises:
          KeyError if key doesn't exist
        """
#         ensure_valid_key(key)
#         index = self.find_gt_or_equal_leaf_index(key)
#         found = self.at_index(index)
#         if found and found.is_leaf() and found.key == key:
#             return self.update_entry(index, new Leaf(key, value))
#         prev = self.at_index(index - 1)
#         if prev and prev.is_tree():
#             updated_tree = prev.update(key, value)
#             return self.update_entry(index - 1, updated_tree)
#         throw new Error(`Could not find a record with key: ${key}`)

    def delete(self, key):
        """Deletes the value at the given key.

        Args:
          key: str

        Returns:
          :class:`MST`

        Raises:
          KeyError if key doesn't exist
        """
#         altered = self.delete_recurse(key)
#         return altered.trim_top()

    def delete_recurse(self, key):
        """Deletes the value and subtree, if any, at the given key.

        Args:
          key: str

        Returns:
          :class:`MST`
        """
#         index = self.find_gt_or_equal_leaf_index(key)
#         found = self.at_index(index)
#         # if found, remove it on self level
#         if found.is_leaf() and found.key == key:
#             prev = self.at_index(index - 1)
#             next = self.at_index(index + 1)
#             if prev.is_tree() and next.is_tree():
#                 merged = prev.append_merge(next)
#                 return self.new_tree([
#                     ...(self.slice(0, index - 1)),
#                     merged,
#                     ...(self.slice(index + 2)),
#                 ])
#             else:
#                 return self.remove_entry(index)
#         # else recurse down to find it
#         prev = self.at_index(index - 1)
#         if prev.is_tree():
#             subtree = prev.delete_recurse(key)
#             sub_tree_entries = subtree.get_entries()
#             if sub_tree_entries.length == 0:
#                 return self.remove_entry(index - 1)
#             else:
#                 return self.update_entry(index - 1, subtree)
#         else:
#             throw new Error(`Could not find a record with key: ${key}`)

#     # Simple Operations
#     # -------------------

    def update_entry(self, index, entry):
        """Updates an entry in place.

        Args:
          index: int
          entry: :class:`MST` or :class:`Leaf`

        Returns:
          MST
        """
#         update = [
#             ...(self.slice(0, index)),
#             entry,
#             ...(self.slice(index + 1)),
#         ]
#         return self.new_tree(update)

    def remove_entry(self, index):
        """Removes the entry at a given index.

        Args:
          index: int

        Returns:
          MST
        """
#         updated = [
#             ...(self.slice(0, index)),
#             ...(self.slice(index + 1)),
#         ]
#         return self.new_tree(updated)

    def append(self, entry):
        """Appends an entry to the end of the node.

        Args:
          entry: :class:`MST` or :class:`Leaf`

        Returns:
          MST
        """
#         entries = self.get_entries()
#         return self.new_tree([...entries, entry])

    def prepend(self, entry):
        """Prepends an entry to the start of the node.

        Args:
          entry: :class:`MST` or :class:`Leaf`

        Returns:
          MST
        """
#         entries = self.get_entries()
#         return self.new_tree([entry, ...entries])

    def at_index(self, index):
        """Returns the entry at a given index.

        Args:
          index: int

        Returns:
          :class:`MST` or :class:`Leaf` or None
        """
#         entries = self.get_entries()
#         return entries[index] ?? None

    def slice(self, start=None, end=None):
        """Returns a slice of this node.

        Args:
          start: int, optional
          end: int, optional

        Returns:
          sequence of :class:`MST` and :class:`Leaf`
        """
#         entries = self.get_entries()
#         return entries.slice(start, end)

    def splice_in(self, entry, index):
        """Inserts an entry at a given index.

        Args:
          entry: :class:`MST` or :class:`Leaf`
          index: int

        Returns:
          MST
        """
#         update = [
#             ...(self.slice(0, index)),
#             entry,
#             ...(self.slice(index)),
#         ]
#         return self.new_tree(update)

    def replace_with_split(self, index, left=None, leaf=None, right=None):
        """Replaces an entry with [ Maybe(tree), Leaf, Maybe(tree) ].

        Args:
          index: int
          left: :class:`MST` or :class:`Leaf`
          leaf: :class:`Leaf`
          right: :class:`MST` or :class:`Leaf`

        Returns:
          MST
        """
#         update = self.slice(0, index)
#         if left:
#             update.push(left)
#         update.push(leaf)
#         if right:
#             update.push(right)
#         update.push(...(self.slice(index + 1)))
#         return self.new_tree(update)

    def trim_top(self):
        """Trims the top and return its subtree, if necessary.

        Only if the topmost node in the tree only points to another tree.
        Otherwise, does nothing.

        Returns:
          MST
        """
#         entries = self.get_entries()
#         if entries.length == 1 and entries[0].is_tree():
#             return entries[0].trim_top()
#         else:
#             return self

#     # Subtree & Splits
#     # -------------------

    def split_around(self, key):
        """Recursively splits a subtree around a given key.

        Args:
          key: str

        Returns:
          tuple, (:class:`MST` or None, :class:`MST or None)
        """
#         index = self.find_gt_or_equal_leaf_index(key)
#         # split tree around key
#         left_data = self.slice(0, index)
#         right_data = self.slice(index)
#         left = self.new_tree(left_data)
#         right = self.new_tree(right_data)

#         # if the far right of the left side is a subtree,
#         # we need to split it on the key as well
#         last_in_left = left_data[left_data.length - 1]
#         if last_in_left.is_tree():
#             left = left.remove_entry(left_data.length - 1)
#             split = last_in_left.split_around(key)
#             if split[0]:
#                 left = left.append(split[0])
#             if split[1]:
#                 right = right.prepend(split[1])

#         return [
#             (left.get_entries()).length > 0 ? left : None,
#             (right.get_entries()).length > 0 ? right : None,
#         ]

    def append_merge(self, to_merge):
        """Merges another tree with this one.
#     # The simple merge case where every key in the right tree is greater than every key in the left tree
#     # (used primarily for deletes)

        Args:
          to_merge: :class:`MST`

        Returns:
          MST
        """
#         assert self.get_layer() == to_merge.get_layer(), \
#             'Trying to merge two nodes from different layers of the MST'
#         self_entries = self.get_entries()
#         to_merge_entries = to_merge.get_entries()
#         last_in_left = self_entries[self_entries.length - 1]
#         first_in_right = to_merge_entries[0]
#         if last_in_left.is_tree() and first_in_right.is_tree():
#             merged = last_in_left.append_merge(first_in_right)
#             return self.new_tree([
#                 ...self_entries.slice(0, self_entries.length - 1),
#                 merged,
#                 ...to_merge_entries.slice(1),
#             ])
#         else:
#             return self.new_tree([...self_entries, ...to_merge_entries])

#     # Create relatives
#     # -------------------

    def create_child(self):
        """
        Returns:
          MST
        """
#         layer = self.get_layer()
#         return MST.create([], {
#             layer: layer - 1,
#         })

    def create_parent(self):
        """
        Returns:
          MST
        """
#         layer = self.get_layer()
#         parent = MST.create([self], {
#             layer: layer + 1,
#         })
#         parent.outdated_pointer = true
#         return parent

#     # Finding insertion points
#     # -------------------

    def find_gt_or_equal_leaf_index(self, key):
        """Finds the index of the first leaf node greater than or equal to the value.

        Args:
          key: str

        Returns:
          int
        """
#         entries = self.get_entries()
#         maybe_index = entries.find_index(
#             (entry) => entry.is_leaf() and entry.key >= key,
#         )
#         # if we can't find, we're on the end
#         return maybe_index >= 0 ? maybe_index : entries.length

#     # List operations (partial tree traversal)
#     # -------------------

#     # @TODO write tests for these

#     # Walk tree starting at key
#     def walk_leaves_from(key: string): AsyncIterable<Leaf>:
#         index = self.find_gt_or_equal_leaf_index(key)
#         entries = self.get_entries()
#         prev = entries[index - 1]
#         if prev and prev.is_tree():
#             for e in prev.walk_leaves_from(key):
#                 yield e
#         for entry in entries[index:]:
#             if entry.is_leaf():
#                 yield entry
#             else:
#                 for e in entry.walk_leaves_from(key):
#                     yield e

#     def list(
#         count = Number.MAX_SAFE_INTEGER,
#         after?: string,
#         before?: string,
#     ):
#     """
#     Returns:
#       Leaf[]
#     """
#         vals: Leaf[] = []
#         for leaf in self.walk_leaves_from(after or ''):
#             if leaf.key == after:
#                 continue
#             if vals.length >= count:
#                 break
#             if before and leaf.key >= before:
#                 break
#             vals.push(leaf)
#         return vals

#     def list_with_prefix(
#         prefix: string,
#         count = Number.MAX_SAFE_INTEGER,
#     ):
#     """
#     Returns:
#       Leaf[]
#     """
#         vals: Leaf[] = []
#         for leaf in self.walk_leaves_from(prefix):
#             if vals.length >= count or !leaf.key.starts_with(prefix):
#                 break
#             vals.push(leaf)
#         return vals

#     # Full tree traversal
#     # -------------------

#     # Walk full tree & emit nodes, consumer can bail at any point by returning false
#     def walk(): AsyncIterable<NodeEntry>:
#         yield self
#         entries = self.get_entries()
#         for entry in entries:
#             if entry.is_tree():
#                 for e in entry.walk():
#                     yield e
#             else:
#                 yield entry

#     # Walk full tree & emit nodes, consumer can bail at any point by returning false
#     def paths():
#     """
#     Returns:
#       sequence of :class:`MST` and :class:`Leaf`
#     """
#         entries = self.get_entries()
#         paths: NodeEntry[][] = []
#         for entry in entries:
#             if entry.is_leaf():
#                 paths.push([entry])
#             if entry.is_tree():
#                 sub_paths = entry.paths()
#                 paths = [...paths, ...sub_paths.map((p) => [entry, ...p])]
#         return paths

    def all_nodes(self):
        """Walks the tree and returns all nodes.

        Returns:
          sequence of :class:`MST` and :class:`Leaf`
        """
#         nodes: NodeEntry[] = []
#         for entry in self.walk():
#             nodes.push(entry)
#         return nodes

#     # Walks tree & returns all cids
#     def all_cids():
#     """
#     Returns:
#       CidSet
#     """
#         cids = new CidSet()
#         entries = self.get_entries()
#         for entry in entries:
#             if entry.is_leaf():
#                 cids.add(entry.value)
#             else:
#                 subtree_cids = entry.all_cids()
#                 cids.add_set(subtree_cids)
#         cids.add(self.get_pointer())
#         return cids

#     # Walks tree & returns all leaves
#     def leaves():
#         leaves: Leaf[] = []
#         for entry in self.walk():
#             if entry.is_leaf():
#                 leaves.push(entry)
#         return leaves

    def leaf_count(self):
        """Returns the total number of leaves in this MST.

        Returns:
          int
        """
        return self.leaves().length

#     # Reachable tree traversal
#     # -------------------

#     # Walk reachable branches of tree & emit nodes, consumer can bail at any point by returning false
#     def walk_reachable(): AsyncIterable<NodeEntry>:
#         yield self
#         entries = self.get_entries()
#         for entry in entries:
#             if entry.is_tree():
#                 try:
#                     for e in entry.walk_reachable():
#                         yield e
#                 catch (err):
#                     if err instanceof MissingBlockError:
#                         continue
#                     else:
#                         throw err
#             else:
#                 yield entry

#     def reachable_leaves():
#     """
#     Returns:
#       Leaf[]
#     """
#         leaves: Leaf[] = []
#         for entry in self.walk_reachable():
#             if entry.is_leaf():
#                 leaves.push(entry)
#         return leaves

#     # Sync Protocol

#     def write_to_car_stream(car: BlockWriter):
#     """
#     Returns:
#       void
#     """
#         entries = self.get_entries()
#         leaves = new CidSet()
#         to_fetch = new CidSet()
#         to_fetch.add(self.get_pointer())
#         for entry in entries:
#             if entry.is_leaf():
#                 leaves.add(entry.value)
#             else:
#                 to_fetch.add(entry.get_pointer())
#         while (to_fetch.size() > 0):
#             next_layer = new CidSet()
#             fetched = self.storage.get_blocks(to_fetch.to_list())
#             if fetched.missing.length > 0:
#                 throw new MissingBlocksError('mst node', fetched.missing)
#             for cid in to_fetch.to_list():
#                 found = parse.get_and_parse_by_def(
#                     fetched.blocks,
#                     cid,
#                     node_data_def,
#                 )
#                 car.put({ cid, bytes: found.bytes })
#                 entries = deserialize_node_data(self.storage, found.obj)

#                 for entry in entries:
#                     if entry.is_leaf():
#                         leaves.add(entry.value)
#                     else:
#                         next_layer.add(entry.get_pointer())
#             to_fetch = next_layer
#         leaf_data = self.storage.get_blocks(leaves.to_list())
#         if leaf_data.missing.length > 0:
#             throw new MissingBlocksError('mst leaf', leaf_data.missing)

#         for leaf in leaf_data.blocks.entries():
#             car.put(leaf)

    def cids_for_path(self, key):
        """Returns the CIDs in a given key path. ???

        Args:
          key: str

        Returns:
          sequence of :class:`CID`
        """
#         cids: CID[] = [self.get_pointer()]
#         index = self.find_gt_or_equal_leaf_index(key)
#         found = self.at_index(index)
#         if found and found.is_leaf() and found.key == key:
#             return [...cids, found.value]
#         prev = self.at_index(index - 1)
#         if prev and prev.is_tree():
#             return [...cids, ...(prev.cids_for_path(key))]
#         return cids


def leading_zeros_on_hash(self, key):
    """Returns the number of leading zeros in a key's hash.

    Args:
      key: str or bytes

    Returns:
      int
    """
    hash = sha256(key).hexdigest()
    leading_zeros = 0
    for byte in hash:
        if byte < 64:
             leading_zeros += 1
        if byte < 16:
             leading_zeros += 1
        if byte < 4:
             leading_zeros += 1
        if byte == 0:
            leading_zeros += 1
        else:
            break

    return leading_zeros


def layer_for_entries(entries):
    """
    sequence of :class:`MST` and :class:`Leaf`
    Returns:
      number | None
    """
    # first_leaf = entries.find((entry) => entry.is_leaf())
    # if not first_leaf or first_leaf.is_tree():
    #      return None
    # return leading_zeros_on_hash(first_leaf.key)


# def deserialize_node_data = (
#     storage: ReadableBlockstore,
#     data: NodeData,
#     opts?: Partial<MstOpts>,
# ):
#     """
#     Returns:
#       sequence of :class:`MST` and :class:`Leaf`
#     """
#     { layer } = opts or {}
#     entries: NodeEntry[] = []
#     if (data.l != None):
#         entries.push(
#             MST.load(storage, data.l,:
#                 layer: layer ? layer - 1 : undefined,
#             )

#     last_key = ''
#     for entry in data.e:
#         key_str = uint8arrays.to_string(entry.k, 'ascii')
#         key = last_key.slice(0, entry.p) + key_str
#         ensure_valid_key(key)
#         entries.push(new Leaf(key, entry.v))
#         last_key = key
#         if entry.t != None:
#             entries.push(
#                 MST.load(storage, entry.t,:
#                     layer: layer ? layer - 1 : undefined,
#                 )

#     return entries


def serialize_node_data(entries):
    """
    Args:
      entries: sequence of :class:`MST` and :class:`Leaf`

    Returns:
      :class:`Data`
    """
#     data: NodeData =:
#         l: None,
#         e: [],

#     i = 0
#     if entries[0].is_tree():
#         i += 1
#         data.l = entries[0].pointer

#     last_key = ''
#     while i < entries.length:
#         leaf = entries[i]
#         next = entries[i + 1]
#         if not leaf.is_leaf():
#             throw new Error('Not a valid node: two subtrees next to each other')
#         i += 1

#         subtree: CID | None = None
#         if next.is_tree():
#             subtree = next.pointer
#             i += 1

#         ensure_valid_key(leaf.key)
#         prefix_len = count_prefix_len(last_key, leaf.key)
#         data.e.push({
#             'p': prefix_len,
#             'k': uint8arrays.from_string(leaf.key.slice(prefix_len), 'ascii'),
#             'v': leaf.value,
#             't': subtree,
#         })

#         last_key = leaf.key

#     return data


def common_prefix_len(a, b):
    """
    Args:
      a, b: str

    Returns:
      int
    """
    return len(commonprefix((a, b)))


def cid_for_entries(entries):
    """
    Args:
      entries: sequence of :class:`MST` and :class:`Leaf`

    Returns:
      CID
    """
    data = serialize_node_data(entries)
    return cid_for_cbor(data)
    NodeData = {
        l: null,
        e: [],
    }

def ensure_valid_key(key):
    """
    Args:
      key: str

    Raises:
      ValueError if key is not a valid MST key.
    """
    valid = re.compile('[a-zA-Z0-9_\-:.]*$')
    split = key.split('/')
    if not (len(key) <= 256 and
            len(split) == 2 and
            split[0] and
            split[1] and
            valid.match(split[0]) and
            valid.match(split[1])
            ):
        raise ValueError(f'Invalid MST key: {key}')
