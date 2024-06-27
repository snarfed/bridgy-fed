"""Convert all stored Activity entities to Objects.

https://github.com/snarfed/bridgy-fed/issues/286

Run from repo top level directory:

source local/bin/activate.csh
env PYTHONPATH=. GOOGLE_APPLICATION_CREDENTIALS=service_account_creds.json \
  python scripts/migrate_activity_to_object.py
"""
from datetime import datetime
import json
import sys

import dateutil.parser
from google.cloud import ndb
from granary import as1
from oauth_dropins.webutil import appengine_config, util

import common
from models import Activity, Object, Target


seen = {}
latest_updated = datetime(1900, 1, 1)

with open('seen.json') as f:
    # maps object id to updated timestamp, or None
    seen = {k: datetime.fromisoformat(v) for k, v in json.load(f).items()}
    latest_updated = seen['_latest_updated']


def run():
    global latest_updated

    query = Activity.query().order(Activity.key)
    if len(sys.argv) > 1:
        print(f'Starting at {sys.argv[1]}')
        query = query.filter(Activity.key >= ndb.Key(Activity, sys.argv[1]))
    elif latest_updated:
        print(f'Starting at {latest_updated}')
        query = list(Activity.query(Activity.updated > latest_updated))
        query.sort(key=lambda a: a.key)
        # print(query.filter(Activity.updated > latest_updated).count())
        # print(len(query))
        # sys.exit()
    else:
        print('Starting at the beginning')

    id = obj = None
    obj = None
    num_activities = count = 0

    for a in query:
        if a.source() != id:
            # finished the current Object
            if obj:
                print(f'{num_activities} total', flush=True)
                obj.status = ('in progress' if obj.undelivered
                              else 'failed' if obj.failed
                              else 'complete' if obj.delivered
                              else 'new')
                print(f'  Storing object', flush=True)
                obj.put()
                seen[obj.key.id()] = obj.updated

                for field in 'actor', 'object':
                    inner = obj_as1.get(field)
                    if isinstance(inner, dict) and inner.get('id'):
                        id = inner['id']
                        updated = inner.get('updated')
                        if updated:
                            updated = dateutil.parser.parse(updated)
                        published = inner.get('published')
                        if published:
                            published = dateutil.parser.parse(published)

                        inner_obj = Object(
                            id=id,
                            source_protocol=obj.source_protocol,
                            as1=json.dumps(inner),
                            type=as1.object_type(inner),
                            created=(published or updated or obj.created
                                     ).replace(tzinfo=None),
                            updated=(updated or published or obj.updated
                                     ).replace(tzinfo=None),
                        )
                        if id not in seen or inner_obj.updated > seen[id]:
                            print(f'  Storing inner {field} {id}')
                            inner_obj.put()
                            seen[id] = inner_obj.updated

            count += 1

            id = a.source()
            if id == 'UI':
                id = json.loads(a.source_as2)['id']

            # start a new Object
            num_activities = 0
            print(f'Collecting {id} ..', end='', flush=True)
            assert util.is_web(id)

            obj_as1 = a.to_as1()
            type = as1.object_type(obj_as1)

            labels = []
            if obj_as1.get('objectType') == 'activity':
                labels.append('activity')
            if a.direction == 'out':
                labels.append('user')
            elif a.domain:
                if type in ('like', 'share', 'follow'):
                    labels.append('notification')
                elif type in ('note', 'article', 'post'):
                    labels.append('feed')

            obj = Object(
                id=id,
                domains=a.domain,
                source_protocol=('ui' if a.source() == 'UI'
                                 else 'webmention' if a.direction == 'out'
                                 else a.protocol),
                labels=labels,
                as1=json.dumps(obj_as1),
                # bsky=None,
                as2=a.source_as2,
                mf2=a.source_mf2,
                type=type,
                # deleted=None,
                delivered=[],
                undelivered=[],
                failed=[],
                created=a.created,
                updated=a.updated,
            )

        # add this Activity to current Object
        status = a.status
        if a.protocol == 'ostatus':
            # only 26 'complete' ostatus Activitys, all with different source URLs
            obj.status = 'ignored' if a.status == 'error' else a.status
        elif status != 'ignored':
            dest = (obj.delivered if a.status == 'complete'
                    else obj.failed if a.status == 'error'
                    else obj.undelivered)
            dest.append(Target(uri=a.target(), protocol='activitypub'))

        if a.created < obj.created:
            obj.created = a.created
        if a.updated > obj.updated:
            obj.updated = a.updated

        if a.updated > latest_updated:
            latest_updated = a.updated

        # if count == 20:
        #     break

        num_activities += 1
        print('.', end='', flush=True)


with appengine_config.ndb_client.context():
    try:
        run()
    finally:
        print(f'\n\nLatest updated: {latest_updated}', flush=True)
        if seen:
            seen['_latest_updated'] = latest_updated
            with open('seen.json', 'w') as f:
                json.dump({id: dt.isoformat() for id, dt in seen.items()}, f, indent=2)
