"""Bluesky / AT Protocol Merkle search tree implementation.

* https://atproto.com/guides/data-repos
* https://atproto.com/lexicons/com-atproto-sync
* https://hal.inria.fr/hal-02303490/document

Heavily based on:
https://github.com/snarfed/atproto/blob/main/packages/repo/src/mst/mst.ts

Huge thanks to the Bluesky team for working in the public, in open source, and to
Daniel Holmgren and Devin Ivy for this code specifically! From that file:

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
from os.path import commonprefix
import re

# subTreePointer = z.nullable(common.cid)
# treeEntry = z.object({
#     'p': z.number(), // prefix count of ascii chars that this key shares with the prev key
#     'k': common.bytes, // the rest of the key outside the shared prefix
#     'v': common.cid, // value
#     't': subTreePointer, // next subtree (to the right of leaf)
# })
# nodeData = z.object({
#     l: subTreePointer, // left-most subtree
#     e: z.array(treeEntry), //entries
# })
# type NodeData = z.infer<typeof nodeData>

# nodeDataDef = {
#     name: 'mst node',
#     schema: nodeData,

# type NodeEntry = MST | Leaf

# type MstOpts = {
#     layer: number

class MST:
#     entries: NodeEntry[] | None
#     layer: number | None
#     pointer: CID
#     outdatedPointer = false

#     def __init__(
#         pointer: CID,
#         entries: NodeEntry[],
#         layer: number,
#     ):
#         assert pointer
#         this.entries = entries
#         this.layer = layer
#         this.pointer = pointer

#     def create(
#         entries: NodeEntry[] = [],
#         opts?: Partial<MstOpts>,
#     ):
#     """
#     Returns:
#       MST
#     """
#         pointer = util.cid_for_entries(entries)
#         { layer = None } = opts or {}
#         return new MST(pointer, entries, layer)

#     def fromData(
#         data: NodeData,
#         opts?: Partial<MstOpts>,
#     ):
#     """
#     Returns:
#       MST
#     """
#         { layer = None } = opts or {}
#         entries = util.deserializeNodeData(data, opts)
#         pointer = cidForCbor(data)
#         return new MST(pointer, entries, layer)

#     # Getters (lazy load)
#     # -------------------

#     # We don't want to load entries of every subtree, just the ones we need
#     def getEntries():
#     """
#     Returns:
#       NodeEntry[]
#     """
#         if this.entries:
#             return [...this.entries]

#         if this.pointer:
#             data = this.storage.readObj(this.pointer, nodeDataDef)
#             firstLeaf = data.e[0]
#             layer =
#                 firstLeaf != undefined
#                     ? util.leadingZerosOnHash(firstLeaf.k)
#                     : undefined
#             this.entries = util.deserializeNodeData(this.storage, data, {
#                 layer,
#             })

#             return this.entries
#         throw new Error('No entries or CID provided')

#     # We don't hash the node on every mutation for performance reasons
#     # Instead we keep track of whether the pointer is outdated and only (recursively) calculate when needed
#     def getPointer():
#     """
#     Returns:
#       CID
#     """
#         if not this.outdatedPointer:
#             return this.pointer
#         entries = this.getEntries()
#         outdated = entries.filter(
#             (e) => e.isTree() and e.outdatedPointer,
#         ) as MST[]
#         if outdated.length > 0:
#             Promise.all(outdated.map((e) => e.getPointer()))
#             entries = this.getEntries()
#         this.pointer = cid_for_entries(entries)
#         this.outdatedPointer = false
#         return this.pointer

#     # In most cases, we get the layer of a node from a hint on creation
#     # In the case of the topmost node in the tree, we look for a key in the node & determine the layer
#     # In the case where we don't find one, we recurse down until we do.
#     # If we still can't find one, then we have an empty tree and the node is layer 0
#     def getLayer():
#     """
#     Returns:
#       number
#     """
#         this.layer = this.attemptGetLayer()
#         if this.layer == None:
#             this.layer = 0
#         return this.layer

#     def attemptGetLayer():
#     """
#     Returns:
#       number | None
#     """
#         if this.layer != None:
#             return this.layer
#         entries = this.getEntries()
#         layer = util.layerForEntries(entries)
#         if layer == None:
#             for entry in entries:
#                 if entry.isTree():
#                     childLayer = entry.attemptGetLayer()
#                     if childLayer != None:
#                         layer = childLayer + 1
#                         break
#         if layer != None:
#             this.layer = layer
#         return layer

    # Core functionality
    # -------------------

    # Adds a new leaf for the given key/value pair
    # Throws if a leaf with that key already exists
    def add(self, key, value=None, known_zeros=None):
        """
        Args:
          key: str
          value: :class:`CID`
          known_zeros: int
        """
        ensure_valid_key(key)
#         keyZeros = knownZeros ?? (util.leadingZerosOnHash(key))
#         layer = this.getLayer()
#         newLeaf = new Leaf(key, value)
#         if keyZeros == layer:
#             # it belongs in this layer
#             index = this.findGtOrEqualLeafIndex(key)
#             found = this.atIndex(index)
#             if found.isLeaf() and found.key == key:
#                 throw new Error(`There is already a value at key: ${key}`)
#             prevNode = this.atIndex(index - 1)
#             if not prevNode or prevNode.isLeaf():
#                 # if entry before is a leaf, (or we're on far left) we can just splice in
#                 return this.spliceIn(newLeaf, index)
#             else:
#                 # else we try to split the subtree around the key
#                 splitSubTree = prevNode.splitAround(key)
#                 return this.replaceWithSplit(
#                     index - 1,
#                     splitSubTree[0],
#                     newLeaf,
#                     splitSubTree[1],
#                 )
#         else if keyZeros < layer:
#             # it belongs on a lower layer
#             index = this.findGtOrEqualLeafIndex(key)
#             prevNode = this.atIndex(index - 1)
#             if prevNode and prevNode.isTree():
#                 # if entry before is a tree, we add it to that tree
#                 newSubtree = prevNode.add(key, value, keyZeros)
#                 return this.updateEntry(index - 1, newSubtree)
#             else:
#                 subTree = this.createChild()
#                 newSubTree = subTree.add(key, value, keyZeros)
#                 return this.spliceIn(newSubTree, index)
#         else:
#             # it belongs on a higher layer & we must push the rest of the tree down
#             split = this.splitAround(key)
#             # if the newly added key has >=2 more leading zeros than the current highest layer
#             # then we need to add in structural nodes in between as well
#             left: MST | None = split[0]
#             right: MST | None = split[1]
#             layer = this.getLayer()
#             extraLayersToAdd = keyZeros - layer
#             # intentionally starting at 1, since first layer is taken care of by split
#             for i in range(1, extraLayersToAdd):
#                 if left != None:
#                     left = left.createParent()
#                 if right != None:
#                     right = right.createParent()
#             updated: NodeEntry[] = []
#             if left:
#                 updated.push(left)
#             updated.push(new Leaf(key, value))
#             if right:
#                 updated.push(right)
#             newRoot = MST.create(updated, {
#                 layer: keyZeros,
#             })
#             newRoot.outdatedPointer = true
#             return newRoot

#     # Gets the value at the given key
#     def get(key: string):
#     """
#     Returns:
#       CID | None
#     """
#         index = this.findGtOrEqualLeafIndex(key)
#         found = this.atIndex(index)
#         if found and found.isLeaf() and found.key == key:
#             return found.value
#         prev = this.atIndex(index - 1)
#         if prev and prev.isTree():
#             return prev.get(key)
#         return None

#     # Edits the value at the given key
#     # Throws if the given key does not exist
#     def update(key: string, value: CID):
#     """
#     Returns:
#       MST
#     """
#         util.ensure_valid_key(key)
#         index = this.findGtOrEqualLeafIndex(key)
#         found = this.atIndex(index)
#         if found and found.isLeaf() and found.key == key:
#             return this.updateEntry(index, new Leaf(key, value))
#         prev = this.atIndex(index - 1)
#         if prev and prev.isTree():
#             updatedTree = prev.update(key, value)
#             return this.updateEntry(index - 1, updatedTree)
#         throw new Error(`Could not find a record with key: ${key}`)

#     # Deletes the value at the given key
#     def delete(key: string):
#     """
#     Returns:
#       MST
#     """
#         altered = this.deleteRecurse(key)
#         return altered.trimTop()

#     def deleteRecurse(key: string):
#     """
#     Returns:
#       MST
#     """
#         index = this.findGtOrEqualLeafIndex(key)
#         found = this.atIndex(index)
#         # if found, remove it on this level
#         if found.isLeaf() and found.key == key:
#             prev = this.atIndex(index - 1)
#             next = this.atIndex(index + 1)
#             if prev.isTree() and next.isTree():
#                 merged = prev.appendMerge(next)
#                 return this.newTree([
#                     ...(this.slice(0, index - 1)),
#                     merged,
#                     ...(this.slice(index + 2)),
#                 ])
#             else:
#                 return this.removeEntry(index)
#         # else recurse down to find it
#         prev = this.atIndex(index - 1)
#         if prev.isTree():
#             subtree = prev.deleteRecurse(key)
#             subTreeEntries = subtree.getEntries()
#             if subTreeEntries.length == 0:
#                 return this.removeEntry(index - 1)
#             else:
#                 return this.updateEntry(index - 1, subtree)
#         else:
#             throw new Error(`Could not find a record with key: ${key}`)

#     # Simple Operations
#     # -------------------

#     # update entry in place
#     def updateEntry(index: number, entry: NodeEntry):
#     """
#     Returns:
#       MST
#     """
#         update = [
#             ...(this.slice(0, index)),
#             entry,
#             ...(this.slice(index + 1)),
#         ]
#         return this.newTree(update)

#     # remove entry at index
#     def removeEntry(index: number):
#     """
#     Returns:
#       MST
#     """
#         updated = [
#             ...(this.slice(0, index)),
#             ...(this.slice(index + 1)),
#         ]
#         return this.newTree(updated)

#     # append entry to end of the node
#     def append(entry: NodeEntry):
#     """
#     Returns:
#       MST
#     """
#         entries = this.getEntries()
#         return this.newTree([...entries, entry])

#     # prepend entry to start of the node
#     def prepend(entry: NodeEntry):
#     """
#     Returns:
#       MST
#     """
#         entries = this.getEntries()
#         return this.newTree([entry, ...entries])

#     # returns entry at index
#     def atIndex(index: number):
#     """
#     Returns:
#       NodeEntry | None
#     """
#         entries = this.getEntries()
#         return entries[index] ?? None

#     # returns a slice of the node (like array.slice)
#     def slice(
#         start?: number | undefined,
#         end?: number | undefined,
#     ):
#     """
#     Returns:
#       NodeEntry[]>
#     """
#         entries = this.getEntries()
#         return entries.slice(start, end)

#     # inserts entry at index
#     def spliceIn(entry: NodeEntry, index: number):
#     """
#     Returns:
#       MST
#     """
#         update = [
#             ...(this.slice(0, index)),
#             entry,
#             ...(this.slice(index)),
#         ]
#         return this.newTree(update)

#     # replaces an entry with [ Maybe(tree), Leaf, Maybe(tree) ]
#     def replaceWithSplit(
#         index: number,
#         left: MST | None,
#         leaf: Leaf,
#         right: MST | None,
#     ):
#     """
#     Returns:
#       MST
#     """
#         update = this.slice(0, index)
#         if left:
#             update.push(left)
#         update.push(leaf)
#         if right:
#             update.push(right)
#         update.push(...(this.slice(index + 1)))
#         return this.newTree(update)

#     # if the topmost node in the tree only points to another tree, trim the top and return the subtree
#     def trimTop():
#     """
#     Returns:
#       MST
#     """
#         entries = this.getEntries()
#         if entries.length == 1 and entries[0].isTree():
#             return entries[0].trimTop()
#         else:
#             return this

#     # Subtree & Splits
#     # -------------------

#     # Recursively splits a sub tree around a given key
#     def splitAround(key: string):
#     """
#     Returns:
#       [MST | None, MST | None]
#     """
#         index = this.findGtOrEqualLeafIndex(key)
#         # split tree around key
#         leftData = this.slice(0, index)
#         rightData = this.slice(index)
#         left = this.newTree(leftData)
#         right = this.newTree(rightData)

#         # if the far right of the left side is a subtree,
#         # we need to split it on the key as well
#         lastInLeft = leftData[leftData.length - 1]
#         if lastInLeft.isTree():
#             left = left.removeEntry(leftData.length - 1)
#             split = lastInLeft.splitAround(key)
#             if split[0]:
#                 left = left.append(split[0])
#             if split[1]:
#                 right = right.prepend(split[1])

#         return [
#             (left.getEntries()).length > 0 ? left : None,
#             (right.getEntries()).length > 0 ? right : None,
#         ]

#     # The simple merge case where every key in the right tree is greater than every key in the left tree
#     # (used primarily for deletes)
#     def appendMerge(toMerge: MST):
#     """
#     Returns:
#       MST
#     """
#         assert this.getLayer() == toMerge.getLayer(), \
#             'Trying to merge two nodes from different layers of the MST'
#         thisEntries = this.getEntries()
#         toMergeEntries = toMerge.getEntries()
#         lastInLeft = thisEntries[thisEntries.length - 1]
#         firstInRight = toMergeEntries[0]
#         if lastInLeft.isTree() and firstInRight.isTree():
#             merged = lastInLeft.appendMerge(firstInRight)
#             return this.newTree([
#                 ...thisEntries.slice(0, thisEntries.length - 1),
#                 merged,
#                 ...toMergeEntries.slice(1),
#             ])
#         else:
#             return this.newTree([...thisEntries, ...toMergeEntries])

#     # Create relatives
#     # -------------------

#     def createChild():
#     """
#     Returns:
#       MST
#     """
#         layer = this.getLayer()
#         return MST.create([], {
#             layer: layer - 1,
#         })

#     def createParent():
#     """
#     Returns:
#       MST
#     """
#         layer = this.getLayer()
#         parent = MST.create([this], {
#             layer: layer + 1,
#         })
#         parent.outdatedPointer = true
#         return parent

#     # Finding insertion points
#     # -------------------

#     # finds index of first leaf node that is greater than or equal to the value
#     def findGtOrEqualLeafIndex(key: string):
#     """
#     Returns:
#       number
#     """
#         entries = this.getEntries()
#         maybeIndex = entries.findIndex(
#             (entry) => entry.isLeaf() and entry.key >= key,
#         )
#         # if we can't find, we're on the end
#         return maybeIndex >= 0 ? maybeIndex : entries.length

#     # List operations (partial tree traversal)
#     # -------------------

#     # @TODO write tests for these

#     # Walk tree starting at key
#     def walkLeavesFrom(key: string): AsyncIterable<Leaf>:
#         index = this.findGtOrEqualLeafIndex(key)
#         entries = this.getEntries()
#         prev = entries[index - 1]
#         if prev and prev.isTree():
#             for e in prev.walkLeavesFrom(key):
#                 yield e
#         for entry in entries[index:]:
#             if entry.isLeaf():
#                 yield entry
#             else:
#                 for e in entry.walkLeavesFrom(key):
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
#         for leaf in this.walkLeavesFrom(after or ''):
#             if leaf.key == after:
#                 continue
#             if vals.length >= count:
#                 break
#             if before and leaf.key >= before:
#                 break
#             vals.push(leaf)
#         return vals

#     def listWithPrefix(
#         prefix: string,
#         count = Number.MAX_SAFE_INTEGER,
#     ):
#     """
#     Returns:
#       Leaf[]
#     """
#         vals: Leaf[] = []
#         for leaf in this.walkLeavesFrom(prefix):
#             if vals.length >= count or !leaf.key.startsWith(prefix):
#                 break
#             vals.push(leaf)
#         return vals

#     # Full tree traversal
#     # -------------------

#     # Walk full tree & emit nodes, consumer can bail at any point by returning false
#     def walk(): AsyncIterable<NodeEntry>:
#         yield this
#         entries = this.getEntries()
#         for entry in entries:
#             if entry.isTree():
#                 for e in entry.walk():
#                     yield e
#             else:
#                 yield entry

#     # Walk full tree & emit nodes, consumer can bail at any point by returning false
#     def paths():
#     """
#     Returns:
#       NodeEntry[][]
#     """
#         entries = this.getEntries()
#         paths: NodeEntry[][] = []
#         for entry in entries:
#             if entry.isLeaf():
#                 paths.push([entry])
#             if entry.isTree():
#                 subPaths = entry.paths()
#                 paths = [...paths, ...subPaths.map((p) => [entry, ...p])]
#         return paths

#     # Walks tree & returns all nodes
#     def allNodes():
#     """
#     Returns:
#       NodeEntry[]
#     """
#         nodes: NodeEntry[] = []
#         for entry in this.walk():
#             nodes.push(entry)
#         return nodes

#     # Walks tree & returns all cids
#     def allCids():
#     """
#     Returns:
#       CidSet
#     """
#         cids = new CidSet()
#         entries = this.getEntries()
#         for entry in entries:
#             if entry.isLeaf():
#                 cids.add(entry.value)
#             else:
#                 subtreeCids = entry.allCids()
#                 cids.addSet(subtreeCids)
#         cids.add(this.getPointer())
#         return cids

#     # Walks tree & returns all leaves
#     def leaves():
#         leaves: Leaf[] = []
#         for entry in this.walk():
#             if entry.isLeaf():
#                 leaves.push(entry)
#         return leaves

#     # Returns total leaf count
#     def leafCount():
#     """
#     Returns:
#       number
#     """
#         leaves = this.leaves()
#         return leaves.length

#     # Reachable tree traversal
#     # -------------------

#     # Walk reachable branches of tree & emit nodes, consumer can bail at any point by returning false
#     def walkReachable(): AsyncIterable<NodeEntry>:
#         yield this
#         entries = this.getEntries()
#         for entry in entries:
#             if entry.isTree():
#                 try:
#                     for e in entry.walkReachable():
#                         yield e
#                 catch (err):
#                     if err instanceof MissingBlockError:
#                         continue
#                     else:
#                         throw err
#             else:
#                 yield entry

#     def reachableLeaves():
#     """
#     Returns:
#       Leaf[]
#     """
#         leaves: Leaf[] = []
#         for entry in this.walkReachable():
#             if entry.isLeaf():
#                 leaves.push(entry)
#         return leaves

#     # Sync Protocol

#     def writeToCarStream(car: BlockWriter):
#     """
#     Returns:
#       void
#     """
#         entries = this.getEntries()
#         leaves = new CidSet()
#         toFetch = new CidSet()
#         toFetch.add(this.getPointer())
#         for entry in entries:
#             if entry.isLeaf():
#                 leaves.add(entry.value)
#             else:
#                 toFetch.add(entry.getPointer())
#         while (toFetch.size() > 0):
#             nextLayer = new CidSet()
#             fetched = this.storage.getBlocks(toFetch.toList())
#             if fetched.missing.length > 0:
#                 throw new MissingBlocksError('mst node', fetched.missing)
#             for cid in toFetch.toList():
#                 found = parse.getAndParseByDef(
#                     fetched.blocks,
#                     cid,
#                     nodeDataDef,
#                 )
#                 car.put({ cid, bytes: found.bytes })
#                 entries = util.deserializeNodeData(this.storage, found.obj)

#                 for entry in entries:
#                     if entry.isLeaf():
#                         leaves.add(entry.value)
#                     else:
#                         nextLayer.add(entry.getPointer())
#             toFetch = nextLayer
#         leafData = this.storage.getBlocks(leaves.toList())
#         if leafData.missing.length > 0:
#             throw new MissingBlocksError('mst leaf', leafData.missing)

#         for leaf in leafData.blocks.entries():
#             car.put(leaf)

#     def cidsForPath(key: string):
#     """
#     Returns:
#       CID[]
#     """
#         cids: CID[] = [this.getPointer()]
#         index = this.findGtOrEqualLeafIndex(key)
#         found = this.atIndex(index)
#         if found and found.isLeaf() and found.key == key:
#             return [...cids, found.value]
#         prev = this.atIndex(index - 1)
#         if prev and prev.isTree():
#             return [...cids, ...(prev.cidsForPath(key))]
#         return cids

#     # Matching Leaf interface
#     # -------------------
#     def isTree():
#         return true

#     def isLeaf():
#         return false

#     def equals(other: NodeEntry):
#         if other.isLeaf():
#             return false
#         thisPointer = this.getPointer()
#         otherPointer = other.getPointer()
#         return thisPointer.equals(otherPointer)


# class Leaf:
#     def __init__(public key: string, public value: CID) {}

#     def isTree(): this is MST:
#         return false

#     def isLeaf(): this is Leaf:
#         return true

#     def equals(entry: NodeEntry): boolean:
#         if entry.isLeaf():
#             return this.key == entry.key and this.value.equals(entry.value)
#         else:
#             return false


# def leadingZerosOnHash(key: string | Uint8Array):
#     hash = sha256(key)
#     leadingZeros = 0
#     for byte in hash:
#         if byte < 64:
#              leadingZeros += 1
#         if byte < 16:
#              leadingZeros += 1
#         if byte < 4:
#              leadingZeros += 1
#         if byte == 0:
#             leadingZeros += 1
#         else:
#             break

#     return leadingZeros


# def layerForEntries = (
#     entries: NodeEntry[],
# ):
#     """
#     Returns:
#       number | None
#     """
#     firstLeaf = entries.find((entry) => entry.isLeaf())
#     if not firstLeaf or firstLeaf.isTree():
#          return None
#     return leadingZerosOnHash(firstLeaf.key)


# def deserializeNodeData = (
#     storage: ReadableBlockstore,
#     data: NodeData,
#     opts?: Partial<MstOpts>,
# ):
#     """
#     Returns:
#       NodeEntry[]> =
#     """
#     { layer } = opts or {}
#     entries: NodeEntry[] = []
#     if (data.l != None):
#         entries.push(
#             MST.load(storage, data.l,:
#                 layer: layer ? layer - 1 : undefined,
#             )

#     lastKey = ''
#     for entry in data.e:
#         keyStr = uint8arrays.toString(entry.k, 'ascii')
#         key = lastKey.slice(0, entry.p) + keyStr
#         ensure_valid_key(key)
#         entries.push(new Leaf(key, entry.v))
#         lastKey = key
#         if entry.t != None:
#             entries.push(
#                 MST.load(storage, entry.t,:
#                     layer: layer ? layer - 1 : undefined,
#                 )

#     return entries


# def serializeNodeData = (entries: NodeEntry[]): NodeData:
#     data: NodeData =:
#         l: None,
#         e: [],

#     i = 0
#     if entries[0].isTree():
#         i += 1
#         data.l = entries[0].pointer

#     lastKey = ''
#     while i < entries.length:
#         leaf = entries[i]
#         next = entries[i + 1]
#         if not leaf.isLeaf():
#             throw new Error('Not a valid node: two subtrees next to each other')
#         i += 1

#         subtree: CID | None = None
#         if next.isTree():
#             subtree = next.pointer
#             i += 1

#         ensure_valid_key(leaf.key)
#         prefixLen = countPrefixLen(lastKey, leaf.key)
#         data.e.push({
#             'p': prefixLen,
#             'k': uint8arrays.fromString(leaf.key.slice(prefixLen), 'ascii'),
#             'v': leaf.value,
#             't': subtree,
#         })

#         lastKey = leaf.key

#     return data


def common_prefix_len(a, b):
    """
    Args:
      a, b: str

    Returns:
      int
    """
    return len(commonprefix((a, b)))


def cid_for_entries (entries):
    """
    Args:
      entries: sequence of NodeEntry

    Returns:
      CID
    """
    data = serializeNodeData(entries)
    return cidForCbor(data)


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
