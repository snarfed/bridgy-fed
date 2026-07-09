"""Farcaster hub client. Enqueues receive tasks for events for bridged users.

https://snapchain.farcaster.xyz/reference/grpcapi/
https://snapchain.farcaster.xyz/reference/grpcapi/events
"""
import base64
from datetime import datetime, timedelta
import logging
from threading import Event, Lock, Thread, Timer
import time

import cachetools
from google.cloud.ndb import context
from google.cloud.ndb.exceptions import ContextError
import granary.farcaster
from granary.generated.farcaster.hub_event_pb2 import HUB_EVENT_TYPE_MERGE_MESSAGE
from granary.generated.farcaster.message_pb2 import (
    MESSAGE_TYPE_CAST_ADD,
    MESSAGE_TYPE_CAST_REMOVE,
    MESSAGE_TYPE_LINK_ADD,
    MESSAGE_TYPE_LINK_REMOVE,
    MESSAGE_TYPE_REACTION_ADD,
    MESSAGE_TYPE_REACTION_REMOVE,
    MESSAGE_TYPE_USER_DATA_ADD,
)
from granary.generated.farcaster.request_response_pb2 import FidRequest, SubscribeRequest
import grpc
from webutil import util
from webutil.appengine_config import ndb_client
from webutil.appengine_info import DEBUG
from webutil.util import json_dumps

from common import create_task, NDB_CONTEXT_KWARGS, report_error, report_exception
from farcaster import client, Farcaster, SNAPCHAIN_HOST, SNAPCHAIN_PORT
from models import Cursor, PROTOCOLS
from protocol import DELETE_TASK_DELAY
from ui import UIProtocol

logger = logging.getLogger(__name__)

RECONNECT_DELAY = timedelta(seconds=10)
LOAD_FIDS_FREQ = timedelta(seconds=10)
STORE_CURSOR_FREQ = timedelta(seconds=10)

# message types whose events represent removing/undoing something we may have
# already bridged, so they should be delayed like other deletes
DELETE_MESSAGE_TYPES = (
    MESSAGE_TYPE_CAST_REMOVE,
    MESSAGE_TYPE_REACTION_REMOVE,
    MESSAGE_TYPE_LINK_REMOVE,
)

# global: _load_fids populates them, handle uses them
fids = set()          # FIDs (int) of bridged out, native Farcaster users
bridged_fids = set()  # FIDs (int) of non-Farcaster users bridged into Farcaster
fids_loaded_at = datetime(1900, 1, 1)
fids_initialized = Event()

# dedupe events we've already handled, across reconnects
seen_hashes = cachetools.TTLCache(maxsize=1_000_000,
                                  ttl=timedelta(weeks=1).total_seconds())
seen_hashes_lock = Lock()

# global so that subscribe can reuse it across calls
cursor = None


def encode_messages(msgs):
    """Base64-encodes serialized Farcaster messages for a task's ``farcaster`` param.

    :meth:`models.Object.from_request` decodes this back into ``obj.farcaster``.

    Args:
      msgs (sequence of bytes): serialized ``message_pb2.Message``s

    Returns:
      str: JSON list of base64-encoded strings
    """
    return json_dumps([base64.b64encode(msg).decode() for msg in msgs])


def ndb_context():
    if ctx := context.get_context(raise_context_error=False):
        return ctx.use()

    return ndb_client.context(**NDB_CONTEXT_KWARGS)


def init():
    logger.info('Starting _load_fids timer')
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_fids, daemon=True, name='farcaster_hub._load_fids').start()
    fids_initialized.wait()
    fids_initialized.clear()

    Thread(target=subscriber, daemon=True, name='farcaster_hub.subscriber').start()


def _load_fids():
    global fids_loaded_at

    if not DEBUG:
        Timer(LOAD_FIDS_FREQ.total_seconds(), _load_fids).start()

    with ndb_context():
        try:
            loaded_at = util.now().replace(tzinfo=None)

            new_fc = Farcaster.query(Farcaster.status == None,
                                     Farcaster.enabled_protocols != None,
                                     Farcaster.updated > fids_loaded_at,
                                     ).fetch()
            fids.update(user.fid for user in new_fc)

            new_bridged = []
            for proto in PROTOCOLS.values():
                if proto and proto not in (Farcaster, UIProtocol):
                    users = proto.query(proto.status == None,
                                        proto.enabled_protocols == 'farcaster',
                                        proto.updated > fids_loaded_at,
                                        ).fetch()
                    new_bridged.extend(users)

            new_bridged_fids = []
            for user in new_bridged:
                if copy := user.get_copy(Farcaster):
                    if match := granary.farcaster.FARCASTER_URI_RE.fullmatch(copy):
                        if match['fid']:
                            new_bridged_fids.append(int(match['fid']))

            bridged_fids.update(new_bridged_fids)

            # set *after* we populate fids and bridged_fids so that if we crash
            # earlier, we re-query from the earlier timestamp
            fids_loaded_at = loaded_at
            fids_initialized.set()
            total = len(fids) + len(bridged_fids)
            logger.info(f'Farcaster FIDs: {total}, native {len(fids)} (+{len(new_fc)}), bridged {len(bridged_fids)} (+{len(new_bridged_fids)})')

        except BaseException:
            # eg google.cloud.ndb.exceptions.ContextError when we lose the ndb context
            report_exception()


def subscriber():
    """Wrapper around :func:`subscribe` that catches exceptions and reconnects."""
    logger.info(f'started thread to subscribe to Farcaster hub {SNAPCHAIN_HOST}:{SNAPCHAIN_PORT}')

    while True:
        try:
            with ndb_context():
                subscribe()
        except grpc.RpcError as err:
            logger.warning(err)
            logger.info(f'disconnected! waiting {RECONNECT_DELAY}, then reconnecting')
        except BaseException:
            report_exception()

        if DEBUG:
            return

        time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe():
    """Subscribes to the snapchain hub's event stream, handles events inline.

    Unlike Nostr relays, which only send us events matching filters we ask for,
    Farcaster hubs send us their *entire* event stream; we filter for events we
    care about ourselves, in :func:`handle`. That means we don't need to
    reconnect when we load new bridged users, unlike ``nostr_hub``.
    """
    global cursor
    if not cursor:
        cursor = Cursor.get_or_insert(f'{SNAPCHAIN_HOST}:{SNAPCHAIN_PORT}')
        if cursor.cursor:
            cursor.cursor += 1

    kwargs = {'event_types': [HUB_EVENT_TYPE_MERGE_MESSAGE]}
    if cursor.cursor:
        kwargs['from_id'] = cursor.cursor

    for event in client().hub.Subscribe(SubscribeRequest(**kwargs)):
        handle(event)

        cursor.cursor = event.id
        elapsed = util.now().replace(tzinfo=None) - cursor.updated
        if elapsed > STORE_CURSOR_FREQ:
            logger.info(f'updating stored Farcaster cursor to {cursor.cursor}')
            cursor.put()

    # hub closed the stream; persist our final cursor position before we
    # reconnect
    if cursor.cursor:
        cursor.put()


def handle(event):
    """Handles a Farcaster hub event. Enqueues a receive task for it if necessary.

    Args:
      event (hub_event_pb2.HubEvent)
    """
    if event.type != HUB_EVENT_TYPE_MERGE_MESSAGE:
        return

    msg = event.merge_message_body.message
    try:
        data = granary.farcaster.deserialize(msg)
    except ValueError:
        logger.info(f'ignoring event with no message data: {event}')
        return

    fid = data.fid
    msg_type = data.type

    if msg_type == MESSAGE_TYPE_USER_DATA_ADD:
        if fid in fids:
            _handle_profile_update(fid)
        return

    targets = set()  # int fids
    if msg_type == MESSAGE_TYPE_CAST_ADD:
        cast = data.cast_add_body
        targets.update(cast.mentions)
        if cast.HasField('parent_cast_id'):
            targets.add(cast.parent_cast_id.fid)
    elif msg_type in (MESSAGE_TYPE_REACTION_ADD, MESSAGE_TYPE_REACTION_REMOVE):
        if data.reaction_body.HasField('target_cast_id'):
            targets.add(data.reaction_body.target_cast_id.fid)
    elif msg_type in (MESSAGE_TYPE_LINK_ADD, MESSAGE_TYPE_LINK_REMOVE):
        targets.add(data.link_body.target_fid)
    elif msg_type != MESSAGE_TYPE_CAST_REMOVE:
        # unsupported/unknown message type
        return

    if not (fid in fids or targets & bridged_fids):
        return

    if not msg.hash:
        logger.info(f'ignoring message with no hash: {msg}')
        return

    with seen_hashes_lock:
        hash = msg.hash
        if not (seen := hash in seen_hashes):
            seen_hashes[hash] = True

    if seen:
        return

    obj_id = granary.farcaster.uri(fid, msg.hash)
    authed_as = granary.farcaster.uri(fid)
    logger.debug(f'Got Farcaster message {obj_id}')

    delay = DELETE_TASK_DELAY if msg_type in DELETE_MESSAGE_TYPES else None
    try:
        create_task(queue='receive', id=obj_id, source_protocol=Farcaster.LABEL,
                    authed_as=authed_as, delay=delay,
                    farcaster=encode_messages([msg.SerializeToString()]))
    except ContextError:
        raise  # handled in subscriber()
    except BaseException:
        report_error(obj_id, exception=True)


def _handle_profile_update(fid):
    """Refetches a bridged Farcaster user's full profile, enqueues a receive task.

    Individual ``USER_DATA_ADD`` messages only carry a single field, but
    profile :class:`models.Object` instances are expected to hold the user's
    whole profile, so we refetch it from the hub instead of bridging the
    single field update. Similar to how ``atproto_firehose`` reloads the whole
    DID doc on ``#identity`` events instead of applying a partial diff.

    Args:
      fid (int)
    """
    try:
        resp = client().hub.GetUserDataByFid(FidRequest(fid=fid))
    except grpc.RpcError as e:
        logger.warning(f'GetUserDataByFid({fid}) failed: {e}')
        return

    if not resp.messages:
        return

    obj_id = granary.farcaster.uri(fid)
    try:
        create_task(queue='receive', id=obj_id, source_protocol=Farcaster.LABEL,
                    authed_as=obj_id,
                    farcaster=encode_messages(
                        m.SerializeToString() for m in resp.messages))
    except ContextError:
        raise  # handled in subscriber()
    except BaseException:
        report_error(obj_id, exception=True)
