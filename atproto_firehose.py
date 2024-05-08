"""Bridgy Fed firehose client. Enqueues receive tasks for events for bridged users.
 """
import itertools
import logging
import os

from carbox import read_car
import dag_json
from granary.bluesky import AT_URI_PATTERN
from lexrpc.client import Client

from atproto import ATProto
from common import add
import models

logger = logging.getLogger(__name__)


def subscribe():
    query = ATProto.query(ATProto.enabled_protocols != None)
    our_atproto_dids = frozenset(key.id() for key in query.iter(keys_only=True))

    other_queries = itertools.chain(*(
        cls.query(cls.copies.protocol == 'atproto').iter()
        for cls in set(models.PROTOCOLS.values())
        if cls and cls != ATProto))
    our_bridged_dids = frozenset(user.get_copy(ATProto) for user in other_queries)

    logger.info(f'Loaded {len(our_atproto_dids)} ATProto, {len(our_bridged_dids)} bridged dids')
    logger.info(f'Subscribing to {os.environ["BGS_HOST"]} firehose')

    client = Client(f'https://{os.environ["BGS_HOST"]}')
    cursor = None  # TODO

    for header, payload in client.com.atproto.sync.subscribeRepos(cursor=cursor):
        if header['op'] == -1:
            logger.warning(f'Got error from relay! {payload}')
            continue
        elif header['t'] == '#info':
            logger.info(f'Got info from relay: {payload}')
            continue
        elif header['t'] != '#commit':
            continue

        _, blocks = read_car(payload['blocks'])
        blocks = {block.cid: block for block in blocks}
        repo = payload.get('repo')

        if repo in our_bridged_dids:  # from a Bridgy Fed non-Bluesky user; ignore
            # logger.info(f'Ignoring record from our non-ATProto bridged user {repo}')
            continue

        # is this from one of our Bluesky users?
        is_ours = False
        if repo in our_atproto_dids:
            logger.info(f'Got record from our ATProto user {repo}, enqueueing')
            is_ours = True

        # detect records that reference an ATProto user, eg replies, likes,
        # reposts, mentions
        for op in payload['ops']:
            action = op['action']
            cid = op['cid']
            path = op['path']
            assert action, cid  # TODO: more graceful

            if action == 'delete':
                # TODO
                continue

            block = blocks.get(op['cid'])
            if not block:  # our own commits are sometimes missing the record (?!?)
                continue

            record = block.decoded
            type = record.get('$type')
            if not type:
                print('missing $type!', action, cid)
                print(dag_json.encode(record).decode())
                continue

            def ref_did(ref):
                match = AT_URI_PATTERN.match(ref['uri'])
                if match:
                    return match.group('repo')

            subjects = []
            def maybe_add(did):
                if did and did in our_atproto_dids:
                    add(subjects, did)

            if type in ('app.bsky.feed.like', 'app.bsky.feed.repost'):
                maybe_add(ref_did(record['subject']))

            elif type in ('app.bsky.graph.block', 'app.bsky.graph.follow'):
                maybe_add(record['subject'])

            elif type == 'app.bsky.feed.post':
                # replies
                if reply := record.get('reply'):
                    for ref in 'parent', 'root':
                        maybe_add(ref_did(reply[ref]))

                # mentions
                for facet in record.get('facets', []):
                    for feature in facet['features']:
                        if feature['$type'] == '#mention':
                            maybe_add(feature['did'])

                # TODO: quote posts
                # if embed = record.get('embed'):
                #     if embed['$type'] in ('app.bsky.embed.record',
                #                           'app.bsky.embed.recordWithMedia'):
                #         if embed['record']

            if is_ours or subjects:
                from_key = ATProto(id=repo).key
                at_uri = f'at://{repo}/{path}'
                notify_keys = []

                if not is_ours:
                    logger.info(f'Got {at_uri} that references {subjects}, enqueueing')
                    notify_keys = [ATProto(id=did).key for did in subjects]

                # store object, enqueue receive task
                # TODO: does record have CIDs etc? how do we store? dag-json?
                # how are polls doing this?
                obj = Object.get_or_create(
                    id=at_uri, bsky=record, actor=repo, users=[from_key],
                    notify=notify_keys, status='new', source_protocol=ATProto.ABBREV)
                common.create_task(queue='receive', obj=obj.key.urlsafe(),
                                   authed_as=repo)

    logger.info('Ran out of events! Relay closed connection?')


if __name__ == '__main__':
    from oauth_dropins.webutil import appengine_config
    import activitypub, web

    with appengine_config.ndb_client.context():
        subscribe()
