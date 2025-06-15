"""Nostr backfeed, via long-lived websocket connection(s) to relay(s)."""
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

from google.cloud import ndb
from google.cloud.ndb.exceptions import ContextError
from granary.nostr import Nostr
from lexrpc.client import Client
import libipld
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.util import json_dumps, json_loads

from common import (
    create_task,
    NDB_CONTEXT_KWARGS,
    PROTOCOL_DOMAINS,
    report_error,
    report_exception,
    USER_AGENT,
)
from models import PROTOCOLS
from nostr import Nostr
from protocol import DELETE_TASK_DELAY
from web import Web

logger = logging.getLogger(__name__)

RECONNECT_DELAY = timedelta(seconds=30)
STORE_CURSOR_FREQ = timedelta(seconds=10)

# global: _load_pubkeys populates them, subscribe and handle use them
nostr_pubkeys = set()
nostr_loaded_at = datetime(1900, 1, 1)
bridged_pubkeys = set()
bridged_loaded_at = datetime(1900, 1, 1)
protocol_bot_pubkeys = set()
pubkeys_initialized = Event()


def load_pubkeys():
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_pubkeys, daemon=True).start()
    pubkeys_initialized.wait()
    pubkeys_initialized.clear()


def _load_pubkeys():
    global nostr_pubkeys, nostr_loaded_at, bridged_pubkeys, bridged_loaded_at

    if not DEBUG:
        Timer(STORE_CURSOR_FREQ.total_seconds(), _load_pubkeys).start()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
        try:
            # nostr_query = Nostr.query(Nostr.status == None,
            #                               Nostr.enabled_protocols != None,
            #                               Nostr.updated > nostr_loaded_at)
            # loaded_at = Nostr.query().order(-Nostr.updated).get().updated
            # new_nostr = [key.id() for key in nostr_query.iter(keys_only=True)]
            # nostr_pubkeys.update(new_nostr)

            # set *after* we populate nostr_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            nostr_loaded_at = loaded_at

            loaded_at = util.now()
            new_bridged = []
            for proto in PROTOCOLS.values():
                if proto and proto != Nostr:
                    new_bridged.extend(proto.query(proto.status == None,
                                                   proto.enabled_protocols = 'nostr',
                                                   proto.updated > bridged_loaded_at,
                                                   ).fetch())
            bridged_pubkeys.update(user.hex_pubkey() for user in new_bridged)

            # set *after* we populate bridged_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            bridged_loaded_at = loaded_at

            if not protocol_bot_pubkeys:
                bot_keys = [Web(id=domain).key for domain in PROTOCOL_DOMAINS]
                for bot in ndb.get_multi(bot_keys):
                    if bot and (pubkey := bot.get_copy(Nostr)):
                        logger.info(f'Loaded protocol bot user {bot.key.id()} {pubkey}')
                        protocol_bot_pubkeys.add(pubkey)

            pubkeys_initialized.set()
            total = len(nostr_pubkeys) + len(bridged_pubkeys)
            logger.info(f'Nostr pubkeys: {total} Nostr {len(nostr_pubkeys)} (+{len(new_nostr)}), AtpRepo {len(bridged_pubkeys)} (+{len(new_bridged)}); commits {commits.qsize()}')

        except BaseException:
            # eg google.cloud.ndb.exceptions.ContextError when we lose the ndb context
            # https://console.cloud.google.com/errors/detail/CLO6nJnRtKXRyQE?project=bridgy-federated
            report_exception()


def subscriber():
    """Wrapper around :func:`_subscribe` that catches exceptions and reconnects."""
    logger.info(f'started thread to subscribe to relay {Nostr.DEFAULT_TARGET}')
    load_pubkeys()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
         while True:
            try:
                subscribe()
            except BaseException:
                report_exception()
            logger.info(f'disconnected! waiting {RECONNECT_DELAY} and then reconnecting')
            time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe():
    """Subscribes to relay(s), backfeeds responses to our users' activities.

    Relay URL comes from :attr:`Nostr.DEFAULT_TARGET`.
    """
    with connect(Nostr.DEFAULT_TARGET, user_agent_header=util.user_agent,
                 open_timeout=util.HTTP_TIMEOUT,
                 close_timeout=util.HTTP_TIMEOUT) as ws:
        for event in Nostr().query(ws, {'#p': bridged_pubkeys}):
            if t not in ('#commit', '#account', '#identity'):
                if t not in ('#handle', '#tombstone'):
                    logger.info(f'Got {t} from relay')
                continue

            # parse payload
            _, payload = libipld.decode_dag_cbor_multi(frame)
            repo = payload.get('repo') or payload.get('pubkey')
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
            # ...
            if t in ('#account', '#identity'):
                if repo in nostr_pubkeys or repo in bridged_pubkeys:
                    t = t.removeprefix('#')
                    logger.debug(f'Got {t} {repo}')
                    commits.put(Op(action=t, repo=repo, seq=seq, time=cur_timestamp))
                continue

            blocks = {}  # maps base32 str CID to dict block
            if block_bytes := payload.get('blocks'):
                _, blocks = libipld.decode_car(block_bytes)

            # detect records from bridged Nostr users that we should handle
            op = Op(repo=payload['repo'], action=p_op.get('action'),
                    path=p_op.get('path'), seq=payload['seq'], time=payload['time'])
            if not op.action or not op.path:
                logger.info(
                    f'bad payload! seq {op.seq} action {op.action} path {op.path}!')
                continue

            if op.repo in nostr_pubkeys and op.action == 'delete':
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
            elif not isinstance(block, dict):
                # https://github.com/snarfed/bridgy-fed/issues/1938
                logger.info(f"Skipping odd record we couldn't understand (#1938): {op} {p_op} {repr(block)}")
                continue

            op = op._replace(record=block)
            type = op.record.get('$type')
            if not type:
                logger.warning('commit record missing $type! {op.action} {op.repo} {op.path} {cid}')
                logger.warning(dag_json.encode(op.record).decode())
                continue
            elif type not in Nostr.SUPPORTED_RECORD_TYPES:
                continue

            # generally we only want records from bridged Bluesky users. the one
            # exception is follows of protocol bot users.
            if (op.repo not in nostr_pubkeys
                and not (type == 'app.bsky.graph.follow'
                         and op.record['subject'] in protocol_bot_pubkeys)):
                continue

            def is_ours(ref, also_nostr_users=False):
                """Returns True if the arg is a bridge user."""
                if match := AT_URI_PATTERN.match(ref['uri']):
                    pubkey = match.group('repo')
                    return pubkey and (pubkey in bridged_pubkeys
                                    or also_nostr_users and pubkey in nostr_pubkeys)

            if type == 'app.bsky.feed.repost':
                if not is_ours(op.record['subject'], also_nostr_users=True):
                    continue

            elif type == 'app.bsky.feed.like':
                if not is_ours(op.record['subject'], also_nostr_users=False):
                    continue

            elif type in ('app.bsky.graph.block', 'app.bsky.graph.follow'):
                if op.record['subject'] not in bridged_pubkeys:
                    continue

            elif type == 'app.bsky.feed.post':
                if reply := op.record.get('reply'):
                    if not is_ours(reply['parent'], also_nostr_users=True):
                        continue

            logger.debug(f'Got {op.action} {op.repo} {op.path}')
            delay = DELETE_TASK_DELAY if op.action == 'delete' else None
            try:
                create_task(queue='receive', id=obj_id, source_protocol=Nostr.LABEL,
                            authed_as=op.repo, received_at=op.time, delay=delay,
                            nostr=event)
                # when running locally, comment out above and uncomment this
                # logger.info(f'enqueuing receive task for {at_uri}')
            except ContextError:
                raise  # handled in subscriber()
            except BaseException:
                report_error(obj_id, exception=True)
