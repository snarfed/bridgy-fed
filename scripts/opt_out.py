"""Opts a user out and deletes their bridged profiles in other networks.

https://github.com/snarfed/bridgy-fed/issues/783

Usage: opt_out.py [PROTOCOL] [USER_ID] [EXTRA_TARGETS ...]

PROTOCOL: protocol label, eg web, activitypub, atproto
USER_ID: key id of the user entity
EXTRA_TARGETS: bridged profiles will also be deleted here

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
import activitypub, atproto, web
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

    # can't do get_by_id because they might be opted out
    from_proto = protocol.PROTOCOLS[proto]
    kind = from_proto._get_kind()
    user = ndb.Key(kind, user_id).get()
    assert user, f'{kind} {user_id} not found'

    targets = [Target(uri=t, protocol='activitypub')
               for t in AP_BASE_TARGETS + extra_targets]

    if from_proto is web.Web:
        user_id = user.web_url()
    to_proto = activitypub.ActivityPub  # TODO: generalize

    to_user_id = ids.translate_user_id(id=user_id, from_proto=from_proto,
                                       to_proto=to_proto)
    delete_id = f'{to_user_id}#bridgy-fed-delete-{util.now().isoformat()}'
    obj = Object(id=delete_id, status='new', source_protocol=from_proto.LABEL,
                 undelivered=targets,
                 # use as2 so that we don't convert. if we try to convert an opted
                 # out user's id, we choke. should probably relax that.
                 as2={
                     'verb': 'Delete',
                     'id': delete_id,
                     # if the actor is already deleted on this instance, it may
                     # return 502 here because it no longer has the actor's
                     # public key, so it can't verify the HTTP Sig. (eg Mastodon
                     # does this; it uses LD Sigs for its actor deletes
                     # instead.)
                     #
                     # an alternative is to use the instance actor:
                     #
                     #   activitypub.instance_actor().key.urlsafe()
                     #
                     # ...which gets accepted, but I'm not sure all
                     # implementations accept the instance actor as authorized
                     # to delete a different actor.
                     'actor': to_user_id,
                     'object': to_user_id,
                 })
    obj.put()

    for target in targets:
        assert util.is_web(target.uri), f'Non-URL target: {target}'
        params = {
            'protocol': to_proto.LABEL,
            'url': target.uri,
            'obj': obj.key.urlsafe(),
            'user': user.key.urlsafe(),
            'force': 'true',
        }
        with app.test_request_context('/queue/send', base_url='https://fed.brid.gy/',
                                      data=params, headers={
                                          flask_util.CLOUD_TASKS_QUEUE_HEADER: '',
                                      }):
            protocol.send_task()


with appengine_config.ndb_client.context(), \
     app.test_request_context(base_url='https://fed.brid.gy/'):
    run()
