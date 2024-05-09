"""Bridgy Fed firehose client. Enqueues receive tasks for events for bridged users.
 """
from collections import namedtuple
from datetime import timedelta
import itertools
import logging
import os
from queue import SimpleQueue
import time

from carbox import read_car
import dag_json
from granary.bluesky import AT_URI_PATTERN
from lexrpc.client import Client
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import error_reporting_client
from oauth_dropins.webutil.appengine_info import DEBUG

from atproto import ATProto, Cursor
from common import add, create_task
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


def subscribe(reconnect=True):
    """Subscribes to the relay's firehose.

    Relay hostname comes from the ``BGS_HOST`` environment variable.

    Args:
      reconnect (bool): whether to always reconnect after we get disconnected
    """
    logger.info(f'starting thread to consume firehose and detect our commits')

    query = ATProto.query(ATProto.enabled_protocols != None)
    atproto_dids = frozenset(key.id() for key in query.iter(keys_only=True))

    other_queries = itertools.chain(*(
        cls.query(cls.copies.protocol == 'atproto').iter()
        for cls in set(models.PROTOCOLS.values())
        if cls and cls != ATProto))
    bridged_dids = frozenset(user.get_copy(ATProto) for user in other_queries)

    logger.info(f'Loaded {len(atproto_dids)} ATProto, {len(bridged_dids)} bridged dids')
    logger.info(f'Subscribing to {os.environ["BGS_HOST"]} firehose')

    while True:
        try:
            _subscribe(atproto_dids=atproto_dids, bridged_dids=bridged_dids)
        except BaseException as err:
            logger.error(f'reporting error, atproto_firehose.subscribe: {err}')
            if DEBUG:
                raise
            error_reporting_client.report_exception()

        if not reconnect:
            return
        logger.info(f'disconnected! waiting {RECONNECT_DELAY} and then reconnecting')
        time.sleep(RECONNECT_DELAY.total_seconds())


def _subscribe(atproto_dids=None, bridged_dids=None):
    assert atproto_dids is not None and bridged_dids is not None, \
        (atproto_dids, bridged_dids)

    cursor = Cursor.get_by_id(
        f'{os.environ["BGS_HOST"]} com.atproto.sync.subscribeRepos')
    assert cursor

    client = Client(f'https://{os.environ["BGS_HOST"]}')

    for header, payload in client.com.atproto.sync.subscribeRepos(cursor=cursor.cursor):
        # parse header
        if header['op'] == -1:
            logger.warning(f'Got error from relay! {payload}')
            continue
        elif header['t'] == '#info':
            logger.info(f'Got info from relay: {payload}')
            continue
        elif header['t'] != '#commit':
            continue

        # parse payload
        repo = payload.get('repo')
        assert repo
        if repo in bridged_dids:  # from a Bridgy Fed non-Bluesky user; ignore
            # logger.info(f'Ignoring record from our non-ATProto bridged user {repo}')
            continue

        blocks = {}
        if payload['blocks']:
            _, blocks = read_car(payload['blocks'])
            blocks = {block.cid: block for block in blocks}

        # detect records that reference an ATProto user, eg replies, likes,
        # reposts, mentions
        for p_op in payload['ops']:
            op = Op(repo=repo, action=p_op['action'], path=p_op['path'],
                    seq=payload['seq'])
            assert op.action and op.path, (op.action, op.path)
            cid = p_op['cid']

            is_ours = repo in atproto_dids
            if is_ours and op.action == 'delete':
                logger.info(f'Got delete from our ATProto user: {op}')
                # TODO: also detect deletes of records that *reference* our bridged
                # users, eg a delete of a follow or like or repost of them.
                # not easy because we need to getRecord the record to check
                new_commits.put(op)
                continue

            block = blocks.get(cid)
            # our own commits are sometimes missing the record
            # https://github.com/snarfed/bridgy-fed/issues/1016
            if not block:
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
            obj = Object.get_or_create(id=obj_id, actor=op.repo, status='new',
                                       users=[ATProto(id=op.repo).key],
                                       source_protocol=ATProto.LABEL, **record_kwarg)
            create_task(queue='receive', obj=obj.key.urlsafe(), authed_as=op.repo)
        except BaseException as err:
            logger.error(f'reporting error, atproto_firehose.handle: {err}')
            if DEBUG:
                raise
            error_reporting_client.report_exception()

        if util.now().replace(tzinfo=None) - cursor.updated > STORE_CURSOR_FREQ:
            # it's been long enough, update our stored cursor
            cursor.cursor = op.seq
            cursor.put()

        count += 1
        if limit is not None and count >= limit:
            return

    assert False, "enqueue thread shouldn't reach here!"


if __name__ == '__main__':
    from oauth_dropins.webutil import appengine_config
    import activitypub, web

    with appengine_config.ndb_client.context():
        subscribe()
