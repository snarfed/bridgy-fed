"""Misc AT Protocol utils. TIDs, CIDs, etc."""
import copy
from datetime import datetime, timezone
import logging
from numbers import Integral
import random

from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import dag_cbor.encoding
from multiformats import CID, multicodec, multihash
from oauth_dropins.webutil.appengine_info import DEBUG

logger = logging.getLogger(__name__)

# the bottom 32 clock ids can be randomized & are not guaranteed to be collision
# resistant. we use the same clockid for all TIDs coming from this runtime.
_clockid = random.randint(0, 31)
# _tid_last = time.time_ns() // 1000  # microseconds

S32_CHARS = '234567abcdefghijklmnopqrstuvwxyz'


def dag_cbor_cid(obj):
    """Returns the DAG-CBOR CID for a given object.

    Args:
      obj: CBOR-compatible native object or value

    Returns:
      :class:`CID`
    """
    encoded = dag_cbor.encoding.encode(obj)
    digest = multihash.digest(encoded, 'sha2-256')
    return CID('base58btc', 1, multicodec.get('dag-cbor'), digest)


def s32encode(num):
    """Base32 encode with encoding variant sort.

    Based on https://github.com/bluesky-social/atproto/blob/main/packages/common-web/src/tid.ts

    Args:
      num: int or Integral

    Returns:
      str
    """
    assert isinstance(num, Integral)

    encoded = []
    while num > 0:
        c = num % 32
        num = num // 32
        encoded.insert(0, S32_CHARS[c])

    return ''.join(encoded)


def s32decode(val):
    """Base32 decode with encoding variant sort.

    Based on https://github.com/bluesky-social/atproto/blob/main/packages/common-web/src/tid.ts

    Args:
      val: str

    Returns:
      int or Integral
    """
    i = 0
    for c in val:
        i = i * 32 + S32_CHARS.index(c)

    return i


def datetime_to_tid(dt):
    """Converts a datetime to an ATProto TID.

    https://atproto.com/guides/data-repos#identifier-types

    Args:
      dt: :class:`datetime.datetime`

    Returns:
      str, base32-encoded TID
    """
    tid = (s32encode(int(dt.timestamp() * 1000 * 1000)) +
           s32encode(_clockid).ljust(2, '2'))
    assert len(tid) == 13
    return tid


def tid_to_datetime(tid):
    """Converts an ATProto TID to a datetime.

    https://atproto.com/guides/data-repos#identifier-types

    Args:
      tid: bytes, base32-encoded TID

    Returns:
      :class:`datetime.datetime`

    Raises:
      ValueError if tid is not bytes or not 13 characters long
    """
    if not isinstance(tid, (str, bytes)) or len(tid) != 13:
        raise ValueError(f'Expected 13-character str or bytes; got {tid}')

    encoded = tid.replace('-', '')[:-2]  # strip clock id
    return datetime.fromtimestamp(s32decode(encoded) / 1000 / 1000, timezone.utc)


# TODO
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


def sign_commit(commit, key):
    """Signs a repo commit.

    Adds the signature in the `sig` field.

    Signing isn't yet in the atproto.com docs, this setup is taken from the TS
    code and conversations with @why on #bluesky-dev:matrix.org.

    * https://matrix.to/#/!vpdMrhHjzaPbBUSgOs:matrix.org/$Xaf4ugYks-iYg7Pguh3dN8hlsvVMUOuCQo3fMiYPXTY?via=matrix.org&via=minds.com&via=envs.net
    * https://github.com/bluesky-social/atproto/blob/384e739a3b7d34f7a95d6ba6f08e7223a7398995/packages/repo/src/util.ts#L238-L248
    * https://github.com/bluesky-social/atproto/blob/384e739a3b7d34f7a95d6ba6f08e7223a7398995/packages/crypto/src/p256/keypair.ts#L66-L73
    * https://github.com/bluesky-social/indigo/blob/f1f2480888ab5d0ac1e03bd9b7de090a3d26cd13/repo/repo.go#L64-L70
    * https://github.com/whyrusleeping/go-did/blob/2146016fc220aa1e08ccf26aaa762f5a11a81404/key.go#L67-L91

    The signature is ECDSA around SHA-256 of the input. We currently use P-256
    keypairs. Context:
    * Go supports P-256, ED25519, SECP256K1 keys
    * TS supports P-256, SECP256K1 keys
    * this recommends ED25519, then P-256:
      https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/

    Args:
      commit: dict repo commit
      key: :class:`Crypto.PublicKey.ECC.EccKey`
    """
    signer = DSS.new(key, 'fips-186-3', randfunc=random.randbytes if DEBUG else None)
    commit['sig'] = signer.sign(SHA256.new(dag_cbor.encoding.encode(commit)))


def verify_commit_sig(commit, key):
    """Returns true if the commit's signature is valid, False otherwise.

    See :func:`sign_commit` for more background.

    Args:
      commit: dict repo commit
      key: :class:`Crypto.PublicKey.ECC.EccKey`

    Raises:
      KeyError if the commit isn't signed, ie doesn't have a `sig` field
    """
    commit = copy.copy(commit)
    sig = commit.pop('sig')

    verifier = DSS.new(key.public_key(), 'fips-186-3',
                       randfunc=random.randbytes if DEBUG else None)
    try:
        verifier.verify(SHA256.new(dag_cbor.encoding.encode(commit)), sig)
        return True
    except ValueError:
        logger.debug("Couldn't verify signature", exc_info=True)
        return False

