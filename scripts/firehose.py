"""Bridgy Fed firehose client. Enqueues receive tasks for events for our users .

Usage:
ve && env GOOGLE_APPLICATION_CREDENTIALS=service_account_creds.json \
  python firehose.py [RELAY_HOST [CURSOR]]
"""
import json
import os
import sys

from carbox import read_car
import dag_json
from granary.bluesky import AT_URI_PATTERN
from lexrpc.client import Client
from oauth_dropins.webutil import appengine_config

from arroba.datastore_storage import AtpRepo

from common import add


with appengine_config.ndb_client.context():
    dids = frozenset(key.id() for key in AtpRepo.query().iter(keys_only=True))

print(f'Loaded {len(dids)} dids')

assert len(sys.argv) <= 3
host = sys.argv[1] if len(sys.argv) >= 2 else 'bgs.bsky-sandbox.dev'
cursor = sys.argv[2] if len(sys.argv) == 3 else None
scheme = 'http' if host.split(':')[0] == 'localhost' else 'https'
client = Client(f'{scheme}://{host}')

for header, payload in client.com.atproto.sync.subscribeRepos(cursor=cursor):
    if header['op'] == -1:
        print('error!', header)
    elif header['t'] != '#commit':
        continue

    # is this from one of our bridged users?
    repo = payload.get('repo')
    if repo in dids:
        # TODO: send
        print('ours, from', repo)
        # continue

    # detect records that reference a bridged user, eg replies, likes,
    # reposts, mentions
    root, blocks = read_car(payload['blocks'])
    blocks = {block.cid: block for block in blocks}

    for op in payload['ops']:
        action = op['action']
        cid = op['cid']
        path = op['path']
        assert action, cid  # TODO: more graceful

        if action == 'delete':
            # TODO
            continue

        block = blocks.get(op['cid'])
        if not block:
            # TODO: ???
            print('missing block!!!', action, cid)
            print(dag_json.encode(payload).decode())
            for cid, block in blocks.items():
                print(cid, dag_json.encode(block.decoded).decode())
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
            if did and did in dids:
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
                    if feature['$type'] == '#mention' and feature['did'] in dids:
                        maybe_add(feature['did'])

            # TODO: quote posts
            # if embed = record.get('embed'):
            #     if embed['$type'] in ('app.bsky.embed.record',
            #                           'app.bsky.embed.recordWithMedia'):
            #         if embed['record']

        # print(action, type, repo, subjects)
        if subjects:
            print(subjects, dag_json.encode(record).decode())
