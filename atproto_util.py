"""Misc AT Protocol utils. TIDs, CIDs, etc."""
from datetime import datetime, timezone
from numbers import Integral
import random

import dag_cbor.encoding
from multiformats import CID, multicodec, multihash

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
