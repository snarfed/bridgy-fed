"""Opts a user out and deletes their bridged profiles in other networks.

https://github.com/snarfed/bridgy-fed/issues/783

Usage: opt_out.py [PROTOCOL] [USER_ID] [EXTRA_TARGETS ...]

PROTOCOL: protocol label, eg web, activitypub, atproto
USER_ID: key id of the user entity
EXTRA_TARGETS: bridged profiles will also be deleted here. currently AP only!

Run with:

source local/bin/activate.csh
env PYTHONPATH=. GOOGLE_APPLICATION_CREDENTIALS=service_account_creds.json \
  python scripts/opt_out.py ...
"""
import logging
import sys

from google.cloud import ndb
from oauth_dropins.webutil import appengine_info
appengine_info.DEBUG = False
from oauth_dropins.webutil import appengine_config, flask_util, util

import ids
from models import Object, Target
import protocol
from activitypub import ActivityPub
from atproto import ATProto
from web import Web
from app import app

appengine_config.error_reporting_client.host = 'localhost:9999'
appengine_config.error_reporting_client.secure = False

# logging.basicConfig(level=logging.DEBUG)


# Includes top 20-40 each from fedidb.org and fediverse.observer on 2024-01-23
AP_BASE_TARGETS = [
    # Diaspora
    # 'https://joindiaspora.com/',
    # 'https://diasp.org/',

    # Friendica
    'https://venera.social/inbox',

    # kbin (not sharedInbox)
    'https://kbin.social/i/inbox',

    # Lemmy (not sharedInbox)
    'https://alien.top/inbox',
    # 'https://enterprise.lemmy.ml/inbox',
    'https://lemmy.ml/inbox',
    'https://lemmy.world/inbox',
    'https://pasta.faith/inbox',

    # Mastodon
    'https://baraag.net/inbox',
    'https://c.im/inbox',
    'https://daystorm.netz.org/inbox',
    'https://fosstodon.org/inbox',
    'https://gc2.jp/inbox',
    'https://hachyderm.io/inbox',
    'https://indieweb.social/inbox',
    'https://infosec.exchange/inbox',
    'https://mas.to/inbox',
    'https://masto.ai/inbox',
    'https://mastodon.cloud/inbox',
    'https://mastodon.online/inbox',
    'https://mastodon.sdf.org/inbox',
    'https://mastodon.social/inbox',
    'https://mastodon.top/inbox',
    'https://mastodon.uno/inbox',
    'https://mastodon.world/inbox',
    'https://mastodonapp.uk/inbox',
    'https://mstdn.jp/inbox',
    'https://mstdn.social/inbox',
    'https://pawoo.net/inbox',
    'https://pravda.me/inbox',
    'https://r-sauna.fi/inbox',
    'https://techhub.social/inbox',
    'https://universeodon.com/inbox',

    # Misskey
    'https://misskey.io/inbox',

    # micro.blog
    'https://micro.blog/activitypub/shared/inbox',

    # PixelFed (not sharedInbox)
    'https://pixelfed.social/i/actor/inbox',

    # Twitter bridge
    # 'https://bird.makeup/inbox',
]


def run():
    assert len(sys.argv) >= 3
    proto, user_id, extra_targets = sys.argv[1], sys.argv[2], sys.argv[3:]

    from_proto = protocol.PROTOCOLS[proto]
    kind = from_proto._get_kind()

    if proto == 'activitypub' and user_id.count('@') == 1:
        instance, user = user_id.strip().removeprefix('https://').split('/@')
        user_id = f'@{user}@{instance}'
        print(f'Cleaned up user id to {user_id}')

    if (from_proto.owns_id(user_id) is False
            and from_proto.owns_handle(user_id) is not False):
        handle = user_id
        user_id = from_proto.handle_to_id(handle)
        print(f'Converted {proto} handle {handle} to user id {user_id}')
        assert from_proto.owns_id(user_id) is not False

    # can't do get_by_id because they might be opted out
    user = ndb.Key(kind, user_id).get()

    if not user:
        print(f"user {kind} {user_id} doesn't exist. Creating new and marking as opted out.")
        from_proto(id=user_id, manual_opt_out=True).put()
        return

    if user.manual_opt_out:
        # needed for key_for etc in misc downstream code below
        user.manual_opt_out = False
        user.put()

    delete_base_id = user.web_url() if from_proto is Web else user_id
    delete_id = f'{delete_base_id}#bridgy-fed-delete-{util.now().isoformat()}'
    delete_as1 = {
        'objectType': 'activity',
        'verb': 'delete',
        'id': delete_id,
        'actor': user_id,
        'object': {
            # needed to make Protocol.translate_ids convert this id as a user id
            # and not an object id
            'objectType': 'person',
            'id': user_id,
        },
    }
    obj = Object(id=delete_id, status='new', source_protocol=from_proto.LABEL,
                 our_as1=delete_as1)
    obj.put()


    targets = list(user.targets(obj, from_user=user).keys())

    if from_proto != ActivityPub:
        targets += [Target(protocol='activitypub', uri=t)
                    for t in AP_BASE_TARGETS + extra_targets]

    if from_proto != ATProto and user.get_copy(ATProto):
        targets += Target(protocol='atproto', uri=ATProto.PDS_URL)

    obj.undelivered = targets
    obj.put()

    for target in targets:
        assert util.is_web(target.uri), f'Non-URL target: {target.uri}'
        params = {
            'protocol': target.protocol,
            'url': target.uri,
            'obj': obj.key.urlsafe(),
            'user': user.key.urlsafe(),
            'force': 'true',
        }
        with app.test_request_context('/queue/send', base_url='https://fed.brid.gy/',
                                      data=params, headers={
                                          flask_util.CLOUD_TASKS_QUEUE_HEADER: '',
                                      }):
            # in ActivityPub, if the actor is already deleted on this instance,
            # it may return 502 here because it no longer has the actor's public
            # key, so it can't verify the HTTP Sig. (eg Mastodon does this; it
            # uses LD Sigs for its actor deletes instead.)
            #
            # an alternative is to use the instance actor:
            #
            #   activitypub.instance_actor().key.urlsafe()
            #
            # ...which gets accepted, but I'm not sure all
            # implementations accept the instance actor as authorized
            # to delete a different actor.
            protocol.send_task()

    if not user.manual_opt_out:
        user.manual_opt_out = True
        user.put()


with appengine_config.ndb_client.context(), \
     app.test_request_context(base_url='https://fed.brid.gy/'):
    run()
