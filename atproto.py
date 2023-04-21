"""com.atproto.sync XRPC methods."""
import json
import logging
import random
import re

import dag_cbor.encoding
from flask import g
from granary import bluesky
from multiformats import CID, multibase, multicodec, multihash
from oauth_dropins.webutil import util

from atproto_mst import MST, serialize_node_data
from flask_app import xrpc_server
from models import Object, PAGE_SIZE, User

logger = logging.getLogger(__name__)


# the bottom 32 clock ids can be randomized & are not guaranteed to be collision
# resistant. we use the same clockid for all TIDs coming from this runtime.
_clockid = random.randint(0, 31)
# _tid_last = time.time_ns() // 1000  # microseconds

# def next_tid():
#     global _tid_last

#     # enforce that we're at least 1us after the last TID to prevent TIDs moving
#     # backwards if system clock drifts backwards
#     now = time.time_ns() // 1000
#     if now > _tid_last:
#         _tid_last = now
#     else:
#         _tid_last += 1
#         now = _tid_last


def datetime_to_tid(dt):
    """Converts a datetime to an ATProto TID.

    https://atproto.com/guides/data-repos#identifier-types

    Args:
      dt: :class:`datetime.datetime`

    Returns:
      str, base32-encoded TID
    """
    base32 = multibase.get('base32')

    def base32_int_bytes(val):
        return base32.encode(val.to_bytes((val.bit_length() + 7) // 8, byteorder='big'))

    # util.d(base32_int_bytes(int(dt.timestamp() * 1000)),
    #        base32_int_bytes(_clockid).ljust(2, '2'))
    tid = (base32_int_bytes(int(dt.timestamp() * 1000 * 1000)) +
           base32_int_bytes(_clockid).ljust(2, '2'))
    # TODO
    # assert len(tid) == 13, tid
    return tid

    # return f'{encoded[:4]}-{encoded[4:7]}-{encoded[7:11]}-{encoded[11:]}'


def build_pds(did=None, user=None, earliest=None, latest=None):
    """Builds a single user's PDS, including DAG-CBOR blocks and MST.

    Either did or user must be provided.

    Args:
      did: str did:web DID
      earliest: str, base32-encoded CID
      latest: str, base32-encoded CID

    Returns:
      ({:class:`CID`: Bluesky object}, :class:`MST`) tuple

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

    blocks = {}   # maps CID to Bluesky object
    mst = MST()

    if earliest:
        earliest = CID.decode(multibase.decode(earliest))
    if latest:
        latest = CID.decode(multibase.decode(latest))

    inside = (earliest is None)
    for obj in Object.query(Object.domains == user.key.id(), Object.labels == 'user'):
        if not obj.as1:
            continue

        logger.debug(f'Generating block for {obj.as1}')
        bs = bluesky.from_as1(obj.as1)
        digest = multihash.digest(dag_cbor.encoding.encode(bs), 'sha2-256')
        cid = CID('base58btc', 1, multicodec.get('dag-cbor'), digest)
        blocks[cid] = bs

        tid = datetime_to_tid(obj.created)
        rkey = f'{bs["$type"]}/{tid}'

        if inside:
            logger.debug(f'Adding to MST: {rkey} {cid}')
            mst = mst.add(rkey, cid)
            if cid == latest:
                inside = False
        elif cid == earliest:
            inside = True

    return blocks, mst


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

    cids = [CID.decode(multibase.decode(cid)) for cid in cids]
    blocks, _ = build_pds(did=did)

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
    _, mst = build_pds(did=did)
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
    _, mst = build_pds(did=did, earliest=earliest, latest=latest)
    return dag_cbor.encoding.encode(serialize_node_data(mst.all_nodes())._asdict())


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
            'head': build_pds(user=user)[1].get_pointer().encode('base32')
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
