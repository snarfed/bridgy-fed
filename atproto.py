"""com.atproto.sync XRPC methods."""
from collections import namedtuple
import json
import logging
import random
import re

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import dag_cbor.encoding
from flask import g
from google.cloud.ndb.query import OR
from granary import bluesky
from multiformats import CID, multibase, multicodec, multihash
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_info import DEBUG

from atproto_mst import (
    MST,
    serialize_node_data,
)
from atproto_util import dag_cbor_cid
from flask_app import xrpc_server
from models import Follower, Object, PAGE_SIZE, User

logger = logging.getLogger(__name__)

# https://atproto.com/specs/atp#repo-data-layout
# TODO: remove? unused?
Commit = namedtuple('Commit', [
  'did',      # CID
  'version',  # int, always 2?
  'prev',     # CID, previous (root?) commit
  'data',     # CID, MST's root node
  'sig',      # bytes
])


def build_repo(did=None, user=None, earliest=None, latest=None):
    """Builds a single user's repo, including commits, records, and MST.

    Either did or user must be provided.

    Args:
      did: str did:web DID
      earliest: str, base32-encoded CID
      latest: str, base32-encoded CID

    Returns:
      ([dict node, ...], :class:`MST`) tuple. First element is the
      chain of repo nodes, latest to earliest.

    Raises ValueError if did is not did:web or no user exists with that domain.
    """
    assert (did is None) ^ (user is None)

    if did:
        domain = util.domain_from_link(bluesky.did_web_to_url(did), minimize=False)
        if not domain:
            raise ValueError(f'No domain found in {did}')

        user = User.get_by_id(domain)
        if not user:
            raise ValueError(f'No user found for domain {domain}')

    if earliest:
        earliest = CID.decode(earliest)
    if latest:
        latest = CID.decode(latest)

    inside = (earliest is None)

    # collect Bluesky records
    # maps repo path '[collection]/[rkey]' to app.bsky record dict
    records = {}

    records['app.bsky.actor.profile/self'] = bluesky.as1_to_profile(user.to_as1())

    for obj in Object.query(Object.domains == user.key.id(),
                                Object.labels == 'user'):
        if not obj.bsky:
            logging.debug(f'Skipping {obj.key}')
        path = f'{obj.bsky["$type"]}/{datetime_to_tid(obj.created)}'
        records[path] = obj.bsky

    for follower in Follower.query(Follower.status == 'active',
                                   OR(Follower.src == domain,
                                      Follower.dest == domain)):
        bsky = bluesky.from_as1(follower.to_as1())
        if not bsky:
            logging.debug(f'Skipping {follower.key}')
        path = f'{bsky["$type"]}/{datetime_to_tid(follower.created)}'
        records[path] = bsky

    # build MST and commit chain
    nodes = []
    mst = MST()
    commit = None
    for path, record in records.items():
        # construct the record
        logger.debug(f'Generating node for {path} {record}')
        nodes.append(record)
        cid = dag_cbor_cid(record)

        # add to MST if we're inside the query range
        if inside:
            logger.debug(f'Adding to MST: {path} {cid}')
            mst = mst.add(path, cid)
            if cid == latest:
                # latest is inclusive
                inside = False
        elif cid == earliest:
            # earliest is exclusive
            inside = True

        # serialize and add all MST nodes
        serialized_mst = serialize_node_data(mst.all_nodes())._asdict()
        # TODO: subtree and leaf nodes?
        nodes.append(serialized_mst)

        # create and sign a commit
        # NOTE: prev is the CID of the last *signed* commit, including sig field
        prev_cid = dag_cbor_cid(commit) if commit else None
        commit = {
            'version': 2,
            # TODO: real DID handling, including did:plc
            'did': f'did:web:{domain}',
            'prev': prev_cid,
            'data': dag_cbor_cid(serialized_mst),
        }

        # signing isn't yet in atproto.com docs, this is from the TS code and
        # conversations with @why on Matrix:
        # * https://matrix.to/#/!vpdMrhHjzaPbBUSgOs:matrix.org/$Xaf4ugYks-iYg7Pguh3dN8hlsvVMUOuCQo3fMiYPXTY?via=matrix.org&via=minds.com&via=envs.net
        # * https://github.com/bluesky-social/atproto/blob/384e739a3b7d34f7a95d6ba6f08e7223a7398995/packages/repo/src/util.ts#L238-L248
        # * https://github.com/bluesky-social/atproto/blob/384e739a3b7d34f7a95d6ba6f08e7223a7398995/packages/crypto/src/p256/keypair.ts#L66-L73
        # * https://github.com/bluesky-social/indigo/blob/f1f2480888ab5d0ac1e03bd9b7de090a3d26cd13/repo/repo.go#L64-L70
        # * https://github.com/whyrusleeping/go-did/blob/2146016fc220aa1e08ccf26aaa762f5a11a81404/key.go#L67-L91
        #
        # which cipher? we currently use P-256, signature is ECDSA around SHA-256.
        # * Go supports P-256, ED25519, SECP256K1 keys
        # * TS supports P-256, SECP256K1 keys
        # * this recommends ED25519, then P-256:
        #   https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/
        key = ECC.import_key(user.p256_key)
        signer = DSS.new(key, 'fips-186-3',
                         randfunc=random.randbytes if DEBUG else None)
        commit['sig'] = signer.sign(SHA256.new(dag_cbor.encoding.encode(commit)))

        nodes.append(commit)

    return nodes, mst


@xrpc_server.method('com.atproto.sync.getBlob')
def get_blob(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.getBlocks')
def get_blocks(input, did=None, cids=None):
    """Gets blocks from a given repo by their CIDs.

    Ignores any unknown CIDs.

    Args:
      did: str
      cids: list of str base32-encoded :class:`CID`s

    Returns:
      bytes, binary DAG-CBOR, application/vnd.ipld.car
    """
    if cids is None:
        cids = []

    cids = [CID.decode(cid) for cid in cids]
    blocks, _ = build_repo(did=did)

    return dag_cbor.encoding.encode([blocks[cid] for cid in cids
                                     if cid in blocks])


@xrpc_server.method('com.atproto.sync.getCheckout')
def get_checkout(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.getCommitPath')
def get_commit_path(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.getHead')
def get_head(input, did=None):
    """

    Args:
      did: str

    Returns:
      str, :class:`CID`
    """
    _, mst = build_repo(did=did)
    return {'root': mst.get_pointer().encode('base32')}


@xrpc_server.method('com.atproto.sync.getRecord')
def get_record(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.getRepo')
def get_repo(input, did, earliest=None, latest=None):
    """Gets a repo's current MST.

    Args:
      did: str
      earliest: optional str, :class:`CID`, exclusive
      latest: optional str, :class:`CID`, inclusive

    Returns:
      bytes, binary DAG-CBOR, application/vnd.ipld.car
    """
    nodes, mst = build_repo(did=did, earliest=earliest, latest=latest)
    return dag_cbor.encoding.encode(nodes)


@xrpc_server.method('com.atproto.sync.listBlobs')
def list_blobs(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.listRepos')
def list_repos(input, ):
    """List dids and root cids of hosted repos.

    Args:
      limit: int
      cursor: str, not yet supported. TODO

    Returns:
      list of repos (DID + head CID)
    """
    return {
        # TODO: cursor
        'repos': [{
            'did': f'did:web:{user.key.id()}',
            'head': build_repo(user=user)[1].get_pointer().encode('base32')
        } for user in User.query() if not user.use_instead]
    }


@xrpc_server.method('com.atproto.sync.notifyOfUpdate')
def notify_of_update(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.requestCrawl')
def request_crawl(input, ):
    """

    Args:
      

    Returns:
      
    """


@xrpc_server.method('com.atproto.sync.subscribeRepos')
def subscribe_repos(input, ):
    """

    Args:
      

    Returns:
      
    """
