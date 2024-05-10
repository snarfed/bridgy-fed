"""Bridgy Fed firehose client. Enqueues receive tasks for events for bridged users.
 """
from collections import namedtuple
from datetime import timedelta
import itertools
import logging
import os
from queue import SimpleQueue
from threading import Event, Lock, Thread, Timer
import time

from carbox import read_car
import dag_json
from google.cloud import ndb
from granary.bluesky import AT_URI_PATTERN
from lexrpc.client import Client
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG

from atproto import ATProto, Cursor
from common import add, create_task, report_exception
import models
from models import Object

RECONNECT_DELAY = timedelta(seconds=30)
STORE_CURSOR_FREQ = timedelta(seconds=20)

logger = logging.getLogger(__name__)

# a commit operation. similar to arroba.repo.Write. record is None for deletes.
Op = namedtuple('Op', ['action', 'repo', 'path', 'seq', 'record'],
                # record is optional
                defaults=[None])

# contains Ops
new_commits = SimpleQueue()

atproto_dids = None
bridged_dids = None
dids_initialized = Event()
load_dids_lock = Lock()


def load_dids():
    with load_dids_lock:
        if dids_initialized.is_set():
            return

        # run in a separate thread since it needs to make its own NDB
        # context when it runs in the timer thread
        Thread(target=_load_dids).start()
        dids_initialized.wait()


def _load_dids():
    global atproto_dids, bridged_dids, load_dids_thread

    with ndb_client.context():
        if not DEBUG:
            Timer(STORE_CURSOR_FREQ.total_seconds(), _load_dids).start()

        atproto_dids = frozenset(key.id() for key in
                                 ATProto.query(ATProto.enabled_protocols != None
                                      ).iter(keys_only=True))

        others_queries = itertools.chain(*(
            cls.query(cls.copies.protocol == 'atproto').iter()
            for cls in set(models.PROTOCOLS.values())
            if cls and cls != ATProto))
        bridged_dids = frozenset(user.get_copy(ATProto) for user in others_queries)

        dids_initialized.set()
        logger.info(f'Loaded {len(atproto_dids)} ATProto, {len(bridged_dids)} bridged dids')


def subscribe(reconnect=True):
    """Subscribes to the relay's firehose.

    Relay hostname comes from the ``BGS_HOST`` environment variable.

    Args:
      reconnect (bool): whether to always reconnect after we get disconnected
    """
    logger.info(f'started thread to subscribe to {os.environ["BGS_HOST"]} firehose')

    while True:
        try:
            _subscribe()
        except BaseException:
            if DEBUG:
                raise
            report_exception()

        if not reconnect:
            return
        logger.info(f'disconnected! waiting {RECONNECT_DELAY} and then reconnecting')
        time.sleep(RECONNECT_DELAY.total_seconds())


def _subscribe():
    load_dids()

    cursor = Cursor.get_by_id(
        f'{os.environ["BGS_HOST"]} com.atproto.sync.subscribeRepos')
    assert cursor

    client = Client(f'https://{os.environ["BGS_HOST"]}')

    sub_cursor = cursor.cursor + 1 if cursor.cursor else None
    for header, payload in client.com.atproto.sync.subscribeRepos(cursor=sub_cursor):
        # parse header
        if header.get('op') == -1:
            logger.warning(f'Got error from relay! {payload}')
            continue
        elif header.get('t') == '#info':
            logger.info(f'Got info from relay: {payload}')
            continue
        elif header.get('t') != '#commit':
            continue

        # parse payload
        repo = payload.get('repo')
        assert repo
        if repo in bridged_dids:  # from a Bridgy Fed non-Bluesky user; ignore
            # logger.info(f'Ignoring record from our non-ATProto bridged user {repo}')
            continue

        blocks = {}
        if block_bytes := payload.get('blocks'):
            _, blocks = read_car(block_bytes)
            blocks = {block.cid: block for block in blocks}

        # detect records that reference an ATProto user, eg replies, likes,
        # reposts, mentions
        for p_op in payload.get('ops', []):
            op = Op(repo=repo, action=p_op.get('action'), path=p_op.get('path'),
                    seq=payload.get('seq'))
            if not op.action or not op.path:
                logger.info(
                    f'bad payload! seq {op.seq} has action {op.action} path {op.path}!')
                continue

            is_ours = repo in atproto_dids
            if is_ours and op.action == 'delete':
                logger.info(f'Got delete from our ATProto user: {op}')
                # TODO: also detect deletes of records that *reference* our bridged
                # users, eg a delete of a follow or like or repost of them.
                # not easy because we need to getRecord the record to check
                new_commits.put(op)
                continue

            cid = p_op.get('cid')
            block = blocks.get(cid)
            # our own commits are sometimes missing the record
            # https://github.com/snarfed/bridgy-fed/issues/1016
            if not cid or not block:
                continue

            op = Op(*op[:-1], record=block.decoded)
            type = op.record.get('$type')
            if not type:
                logger.warning('commit record missing $type! {op.action} {op.repo} {op.path} {cid}')
                logger.warning(dag_json.encode(op.record).decode())
                continue

            if is_ours:
                logger.info(f'Got one from our ATProto user: {op.action} {op.repo} {op.path}')
                new_commits.put(op)
                continue

            subjects = []

            def maybe_add(did_or_ref):
                if isinstance(did_or_ref, dict):
                    match = AT_URI_PATTERN.match(did_or_ref['uri'])
                    if match:
                        did = match.group('repo')
                    else:
                        return
                else:
                    did = did_or_ref

                if did and did in bridged_dids:
                    add(subjects, did)

            if type in ('app.bsky.feed.like', 'app.bsky.feed.repost'):
                maybe_add(op.record['subject'])

            elif type in ('app.bsky.graph.block', 'app.bsky.graph.follow'):
                maybe_add(op.record['subject'])

            elif type == 'app.bsky.feed.post':
                # replies
                if reply := op.record.get('reply'):
                    for ref in 'parent', 'root':
                        maybe_add(reply[ref])

                # mentions
                for facet in op.record.get('facets', []):
                    for feature in facet['features']:
                        if feature['$type'] == 'app.bsky.richtext.facet#mention':
                            maybe_add(feature['did'])

                # quote posts
                if embed := op.record.get('embed'):
                    if embed['$type'] == 'app.bsky.embed.record':
                        maybe_add(embed['record'])
                    elif embed['$type'] == 'app.bsky.embed.recordWithMedia':
                        maybe_add(embed['record']['record'])

            if subjects:
                logger.info(f'Got one re our ATProto users {subjects}: {op.action} {op.repo} {op.path}')
                new_commits.put(op)


def handle(limit=None):
    """Store Objects and create receive tasks for commits as they arrive.

    :meth:`Object.get_or_create` makes network calls, via eg :meth:`Object.as1`
    => :meth:`ATProto.pds_for` and :meth:`ATProto.handle`, so we don't want to
    do those in the critical path in :func:`subscribe`.

    Args:
      limit (int): return after handling this many commits
    """
    logger.info(f'started thread to store objects and enqueue receive tasks')
    load_dids()

    cursor = Cursor.get_by_id(
        f'{os.environ["BGS_HOST"]} com.atproto.sync.subscribeRepos')
    assert cursor

    count = 0
    while op := new_commits.get():
        at_uri = f'at://{op.repo}/{op.path}'

        # store object, enqueue receive task
        # TODO: for Object.bsky, does record have CIDs etc? how do we store?
        # dag-json? how are polls doing this?
        if op.action in ('create', 'update'):
            record_kwarg = {'bsky': op.record}
            obj_id = at_uri
        elif op.action == 'delete':
            obj_id = f'{at_uri}#delete'
            record_kwarg = {'our_as1': {
                'objectType': 'activity',
                'verb': 'delete',
                'id': obj_id,
                'actor': op.repo,
                'object': at_uri,
            }}
        else:
            logger.error(f'Unknown action {action} for {op.repo} {op.path}')
            continue

        try:
            # logger.info(f'enqueuing receive task for {at_uri}')
            obj = Object.get_or_create(id=obj_id, actor=op.repo, status='new',
                                       users=[ATProto(id=op.repo).key],
                                       source_protocol=ATProto.LABEL, **record_kwarg)
            create_task(queue='receive', obj=obj.key.urlsafe(), authed_as=op.repo)
        except BaseException:
            if DEBUG:
                raise
            report_exception()

        if util.now().replace(tzinfo=None) - cursor.updated > STORE_CURSOR_FREQ:
            # it's been long enough, update our stored cursor
            # logger.info(f'updating stored cursor to {op.seq}')
            cursor.cursor = op.seq
            cursor.put()

        count += 1
        if limit is not None and count >= limit:
            return

    assert False, "handle thread shouldn't reach here!"


if __name__ == '__main__':
    from oauth_dropins.webutil import appengine_config
    import activitypub, web

    with appengine_config.ndb_client.context():
        subscribe()
