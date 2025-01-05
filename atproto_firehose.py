"""ATProto firehose client. Enqueues receive tasks for events for bridged users."""
from collections import namedtuple
from datetime import datetime, timedelta
from io import BytesIO
import itertools
import logging
import os
from queue import Queue
from threading import Event, Lock, Thread, Timer
import threading
import time

from arroba.datastore_storage import AtpRepo
from arroba.util import parse_at_uri
import dag_cbor
import dag_json
from google.cloud import ndb
from google.cloud.ndb.exceptions import ContextError
from granary.bluesky import AT_URI_PATTERN
from lexrpc.client import Client
import libipld
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.util import json_dumps, json_loads

from atproto import ATProto, Cursor
from common import (
    cache_policy,
    create_task,
    global_cache,
    global_cache_policy,
    global_cache_timeout_policy,
    NDB_CONTEXT_KWARGS,
    PROTOCOL_DOMAINS,
    report_error,
    report_exception,
    USER_AGENT,
)
from protocol import DELETE_TASK_DELAY
from web import Web

logger = logging.getLogger(__name__)

RECONNECT_DELAY = timedelta(seconds=30)
STORE_CURSOR_FREQ = timedelta(seconds=10)

# a commit operation. similar to arroba.repo.Write. record is None for deletes.
Op = namedtuple('Op', ['action', 'repo', 'path', 'seq', 'record', 'time'],
                # last four fields are optional
                defaults=[None, None, None, None])

# contains Ops
#
# maxsize is important here! if we hit this limit, subscribe will block when it
# tries to add more commits until handle consumes some. this keeps subscribe
# from getting too far ahead of handle and using too much memory in this queue.
commits = Queue(maxsize=1000)

# global so that subscribe can reuse it across calls
cursor = None

# global: _load_dids populates them, subscribe and handle use them
atproto_dids = set()
atproto_loaded_at = datetime(1900, 1, 1)
bridged_dids = set()
bridged_loaded_at = datetime(1900, 1, 1)
protocol_bot_dids = set()
dids_initialized = Event()


def load_dids():
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_dids).start()
    dids_initialized.wait()
    dids_initialized.clear()


def _load_dids():
    global atproto_dids, atproto_loaded_at, bridged_dids, bridged_loaded_at

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
        if not DEBUG:
            Timer(STORE_CURSOR_FREQ.total_seconds(), _load_dids).start()

        atproto_query = ATProto.query(ATProto.enabled_protocols != None,
                                      ATProto.updated > atproto_loaded_at)
        loaded_at = ATProto.query().order(-ATProto.updated).get().updated
        new_atproto = [key.id() for key in atproto_query.iter(keys_only=True)]
        atproto_dids.update(new_atproto)
        # set *after* we populate atproto_dids so that if we crash earlier, we
        # re-query from the earlier timestamp
        atproto_loaded_at = loaded_at

        bridged_query = AtpRepo.query(AtpRepo.status == None,
                                      AtpRepo.created > bridged_loaded_at)
        loaded_at = AtpRepo.query().order(-AtpRepo.created).get().created
        new_bridged = [key.id() for key in bridged_query.iter(keys_only=True)]
        bridged_dids.update(new_bridged)
        # set *after* we populate bridged_dids so that if we crash earlier, we
        # re-query from the earlier timestamp
        bridged_loaded_at = loaded_at

        if not protocol_bot_dids:
            bot_keys = [Web(id=domain).key for domain in PROTOCOL_DOMAINS]
            for bot in ndb.get_multi(bot_keys):
                if bot:
                    if did := bot.get_copy(ATProto):
                        logger.info(f'Loaded protocol bot user {bot.key.id()} {did}')
                        protocol_bot_dids.add(did)

        dids_initialized.set()
        total = len(atproto_dids) + len(bridged_dids)
        logger.info(f'DIDs: {total} ATProto {len(atproto_dids)} (+{len(new_atproto)}), AtpRepo {len(bridged_dids)} (+{len(new_bridged)}); commits {commits.qsize()}')


def subscriber():
    """Wrapper around :func:`_subscribe` that catches exceptions and reconnects."""
    logger.info(f'started thread to subscribe to {os.environ["BGS_HOST"]} firehose')
    load_dids()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
         while True:
            try:
                subscribe()
            except BaseException:
                report_exception()
            logger.info(f'disconnected! waiting {RECONNECT_DELAY} and then reconnecting')
            time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe():
    """Subscribes to the relay's firehose.

    Relay hostname comes from the ``BGS_HOST`` environment variable.

    Args:
      reconnect (bool): whether to always reconnect after we get disconnected
    """
    global cursor
    if not cursor:
        cursor = Cursor.get_or_insert(
            f'{os.environ["BGS_HOST"]} com.atproto.sync.subscribeRepos')
        # TODO: remove? does this make us skip events? if we remove it, will we
        # infinite loop when we fail on an event?
        if cursor.cursor:
            cursor.cursor += 1

    last_stored_cursor = cur_timestamp = None

    client = Client(f'https://{os.environ["BGS_HOST"]}',
                    headers={'User-Agent': USER_AGENT})

    for frame in client.com.atproto.sync.subscribeRepos(decode=False,
                                                        cursor=cursor.cursor):
        # parse header
        header = libipld.decode_dag_cbor(frame)
        if header.get('op') == -1:
            _, payload = libipld.decode_dag_cbor_multi(frame)
            logger.warning(f'Got error from relay! {payload}')
            continue

        t = header.get('t')

        if t not in ('#commit', '#account', '#identity'):
            logger.info(f'Got {t} from relay')
            continue

        # parse payload
        _, payload = libipld.decode_dag_cbor_multi(frame)
        repo = payload.get('repo') or payload.get('did')
        if not repo:
            logger.warning(f'Payload missing repo! {payload}')
            continue

        seq = payload.get('seq')
        if not seq:
            logger.warning(f'Payload missing seq! {payload}')
            continue

        cur_timestamp = payload['time']

        # if we fail processing this commit and raise an exception up to subscriber,
        # skip it and start with the next commit when we're restarted
        cursor.cursor = seq + 1

        elapsed = util.now().replace(tzinfo=None) - cursor.updated
        if elapsed > STORE_CURSOR_FREQ:
            events_s = 0
            if last_stored_cursor:
                events_s = int((cursor.cursor - last_stored_cursor) /
                               elapsed.total_seconds())
            last_stored_cursor = cursor.cursor

            behind = util.now() - util.parse_iso8601(cur_timestamp)

            # it's been long enough, update our stored cursor and metrics
            logger.info(f'updating stored cursor to {cursor.cursor}, {events_s} events/s, {behind} ({int(behind.total_seconds())} s) behind')
            cursor.put()
            # when running locally, comment out put above and uncomment this
            # cursor.updated = util.now().replace(tzinfo=None)

        if t in ('#account', '#identity'):
            if repo in atproto_dids or repo in bridged_dids:
                logger.debug(f'Got {t[1:]} {repo}')
                commits.put(Op(action='account', repo=repo, seq=seq,
                               time=cur_timestamp))
                continue

        assert t == '#commit'
        blocks = {}  # maps base32 str CID to dict block
        if block_bytes := payload.get('blocks'):
            _, blocks = libipld.decode_car(block_bytes)

        # detect records from bridged ATProto users that we should handle
        for p_op in payload.get('ops', []):
            op = Op(repo=payload['repo'], action=p_op.get('action'),
                    path=p_op.get('path'), seq=payload['seq'], time=payload['time'])
            if not op.action or not op.path:
                logger.info(
                    f'bad payload! seq {op.seq} action {op.action} path {op.path}!')
                continue

            if op.repo in atproto_dids and op.action == 'delete':
                logger.debug(f'Got delete from our ATProto user: {op}')
                # TODO: also detect deletes of records that *reference* our bridged
                # users, eg a delete of a follow or like or repost of them.
                # not easy because we need to getRecord the record to check
                commits.put(op)
                continue

            cid = p_op.get('cid')
            block = blocks.get(cid)
            # our own commits are sometimes missing the record
            # https://github.com/snarfed/bridgy-fed/issues/1016
            if not cid or not block:
                continue

            op = op._replace(record=block)
            type = op.record.get('$type')
            if not type:
                logger.warning('commit record missing $type! {op.action} {op.repo} {op.path} {cid}')
                logger.warning(dag_json.encode(op.record).decode())
                continue
            elif type not in ATProto.SUPPORTED_RECORD_TYPES:
                continue

            # generally we only want records from bridged Bluesky users. the one
            # exception is follows of protocol bot users.
            if (op.repo not in atproto_dids
                and not (type == 'app.bsky.graph.follow'
                         and op.record['subject'] in protocol_bot_dids)):
                continue

            def is_ours(ref, also_atproto_users=False):
                """Returns True if the arg is a bridge user."""
                if match := AT_URI_PATTERN.match(ref['uri']):
                    did = match.group('repo')
                    return did and (did in bridged_dids
                                    or also_atproto_users and did in atproto_dids)

            if type == 'app.bsky.feed.repost':
                if not is_ours(op.record['subject'], also_atproto_users=True):
                    continue

            elif type == 'app.bsky.feed.like':
                if not is_ours(op.record['subject'], also_atproto_users=False):
                    continue

            elif type in ('app.bsky.graph.block', 'app.bsky.graph.follow'):
                if op.record['subject'] not in bridged_dids:
                    continue

            elif type == 'app.bsky.feed.post':
                if reply := op.record.get('reply'):
                    if not is_ours(reply['parent'], also_atproto_users=True):
                        continue

            logger.debug(f'Got {op.action} {op.repo} {op.path}')
            commits.put(op)


def handler():
    """Wrapper around :func:`handle` that catches exceptions and restarts."""
    logger.info(f'started handle thread to store objects and enqueue receive tasks')

    while True:
        with ndb_client.context(**NDB_CONTEXT_KWARGS):
            try:
                handle()
                # if we return cleanly, that means we hit the limit
                break
            except BaseException:
                report_exception()
                # fall through to loop to create new ndb context in case this is
                # a ContextError
                # https://console.cloud.google.com/errors/detail/CIvwj_7MmsfOWw;time=P1D;locations=global?project=bridgy-federated


def handle(limit=None):
    def _handle_account(op):
        # reload DID doc to fetch new changes
        ATProto.load(op.repo, did_doc=True, remote=True)

    def _handle(op):
        at_uri = f'at://{op.repo}/{op.path}'

        type, _ = op.path.strip('/').split('/', maxsplit=1)
        if type not in ATProto.SUPPORTED_RECORD_TYPES:
            logger.info(f'Skipping unsupported type {type}: {at_uri}')
            return

        # store object, enqueue receive task
        if op.action in ('create', 'update'):
            record_kwarg = {
                'bsky': op.record,
            }
            obj_id = at_uri
        elif op.action == 'delete':
            verb = ('delete'
                    if type in ('app.bsky.actor.profile', 'app.bsky.feed.post')
                    else 'undo')
            obj_id = f'{at_uri}#{verb}'
            record_kwarg = {
                'our_as1': {
                    'objectType': 'activity',
                    'verb': verb,
                    'id': obj_id,
                    'actor': op.repo,
                    'object': at_uri,
                },
            }
        else:
            logger.error(f'Unknown action {action} for {op.repo} {op.path}')
            return

        delay = DELETE_TASK_DELAY if op.action == 'delete' else None
        try:
            create_task(queue='receive', id=obj_id, source_protocol=ATProto.LABEL,
                        authed_as=op.repo, received_at=op.time, delay=delay,
                        **record_kwarg)
            # when running locally, comment out above and uncomment this
            # logger.info(f'enqueuing receive task for {at_uri}')
        except ContextError:
            raise  # handled in handle()
        except BaseException:
            report_error(obj_id, exception=True)

    seen = 0
    while op := commits.get():
        match op.action:
            case 'account':
                _handle_account(op)
            case _:
                _handle(op)

        seen += 1
        if limit is not None and seen >= limit:
            return

    assert False, "handle thread shouldn't reach here!"
