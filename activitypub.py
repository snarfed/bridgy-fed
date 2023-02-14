"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import datetime
import logging
import re
import threading

from cachetools import LRUCache
from flask import request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1, as2
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from common import CACHE_TIME, host_url, redirect_unwrap, redirect_wrap, TLD_BLOCKLIST
from models import Follower, Object, Target, User

logger = logging.getLogger(__name__)

SUPPORTED_TYPES = (
    'Accept',
    'Announce',
    'Article',
    'Audio',
    'Create',
    'Delete',
    'Follow',
    'Image',
    'Like',
    'Note',
    'Undo',
    'Update',
    'Video',
)
FETCH_OBJECT_TYPES = (
    'Announce',
)

# activity ids that we've already handled and can now ignore
seen_ids = LRUCache(100000)
seen_ids_lock = threading.Lock()


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>')
@flask_util.cached(cache, CACHE_TIME)
def actor(domain):
    """Serves a user's AS2 actor from the datastore."""
    tld = domain.split('.')[-1]
    if tld in TLD_BLOCKLIST:
        error('', status=404)

    user = User.get_by_id(domain)
    if not user:
        return f'User {domain} not found', 404
    elif not user.actor_as2:
        return f'User {domain} not fully set up', 404

    # TODO: unify with common.actor()
    actor = {
        **common.postprocess_as2(json_loads(user.actor_as2), user=user),
        'id': host_url(domain),
        # This has to be the domain for Mastodon etc interop! It seems like it
        # should be the custom username from the acct: u-url in their h-card,
        # but that breaks Mastodon's Webfinger discovery. Background:
        # https://github.com/snarfed/bridgy-fed/issues/302#issuecomment-1324305460
        # https://github.com/snarfed/bridgy-fed/issues/77
        'preferredUsername': domain,
        'inbox': host_url(f'{domain}/inbox'),
        'outbox': host_url(f'{domain}/outbox'),
        'following': host_url(f'{domain}/following'),
        'followers': host_url(f'{domain}/followers'),
        'endpoints': {
            'sharedInbox': host_url('inbox'),
        },
    }

    logger.info(f'Returning: {json_dumps(actor, indent=2)}')
    return actor, {
        'Content-Type': as2.CONTENT_TYPE,
        'Access-Control-Allow-Origin': '*',
    }


@app.post('/inbox')
@app.post(f'/<regex("{common.DOMAIN_RE}"):domain>/inbox')
def inbox(domain=None):
    """Handles ActivityPub inbox delivery."""
    body = request.get_data(as_text=True)
    logger.info(f'Got: {body}')

    # parse and validate AS2 activity
    try:
        activity = request.json
        assert activity
    except (TypeError, ValueError, AssertionError):
        error(f"Couldn't parse body as JSON", exc_info=True)

    type = activity.get('type')
    actor = activity.get('actor')
    actor_id = actor.get('id') if isinstance(actor, dict) else actor
    logger.info(f'Got {type} activity from {actor_id}: {json_dumps(activity, indent=2)}')

    obj_as2 = activity.get('object') or {}
    if isinstance(obj_as2, str):
        obj_as2 = {'id': obj_as2}

    id = activity.get('id')
    if not id:
        error('Activity has no id')

    # short circuit if we've already seen this activity id
    with seen_ids_lock:
        already_seen = id in seen_ids
        seen_ids[id] = True
        if already_seen or Object.get_by_id(id):
            msg = f'Already handled this activity {id}'
            logging.info(msg)
            return msg, 200

    activity_as1 = as2.to_as1(activity)
    as1_type = as1.object_type(activity_as1)
    activity_obj = Object(
        id=id, as2=json_dumps(activity), as1=json_dumps(activity_as1),
        source_protocol='activitypub', status='complete')
    activity_obj.put()

    if type == 'Accept':  # eg in response to a Follow
        return ''  # noop
    if type not in SUPPORTED_TYPES:
        error(f'Sorry, {type} activities are not supported yet.', status=501)

    # TODO: verify signature if there is one

    user = None
    if domain:
        user = User.get_by_id(domain)
        if not user:
            return f'User {domain} not found', 404

    if type == 'Undo' and obj_as2.get('type') == 'Follow':
        # skip actor fetch below; we don't need it to undo a follow
        undo_follow(redirect_unwrap(activity))
        return ''

    elif type == 'Update':
        obj_id = obj_as2.get('id')
        if not obj_id:
            error("Couldn't find obj_id of object to update")

        logger.info(f'updating Object {obj_id}')
        obj = Object.get_by_id(obj_id) or Object(id=obj_id)
        obj.populate(
            as2=json_dumps(obj_as2),
            as1=json_dumps(as2.to_as1(obj_as2)),
            source_protocol='activitypub',
        )
        obj.put()
        return 'OK'

    elif type == 'Delete':
        obj_id = obj_as2.get('id')
        if not obj_id:
            error("Couldn't find id of object to delete")

        obj = Object.get_by_id(obj_id)
        if obj:
            logger.info(f'Marking Object {obj_id} deleted')
            obj.deleted = True
            obj.put()

        # assume this is an actor
        # https://github.com/snarfed/bridgy-fed/issues/63
        logger.info(f'Deactivating Followers with src or dest = {obj_id}')
        followers = Follower.query(OR(Follower.src == obj_id,
                                      Follower.dest == obj_id)
                                   ).fetch()
        for f in followers:
            f.status = 'inactive'
        ndb.put_multi(followers)
        return 'OK'

    # fetch actor if necessary so we have name, profile photo, etc
    if actor and isinstance(actor, str):
        actor = activity['actor'] = common.get_as2(actor, user=user).json()

    # fetch object if necessary so we can render it in feeds
    if type in FETCH_OBJECT_TYPES and isinstance(activity.get('object'), str):
        obj_as2 = activity['object'] = \
            common.get_as2(activity['object'], user=user).json()

    activity_unwrapped = redirect_unwrap(activity)
    if type == 'Follow':
        return accept_follow(activity, activity_unwrapped, user)

    # send webmentions to each target
    activity_as2_str = json_dumps(activity_unwrapped)
    activity_as1 = as2.to_as1(activity_unwrapped)
    activity_as1_str = json_dumps(activity_as1)
    common.send_webmentions(as2.to_as1(activity), proxy=True,
                            source_protocol='activitypub',
                            as2=activity_as2_str, as1=activity_as1_str)

    # deliver original posts and reposts to followers
    if ((type == 'Create' and not activity.get('inReplyTo') and not obj_as2.get('inReplyTo'))
        or type == 'Announce'):
        # check that this activity is public. only do this check for Creates,
        # not Like, Follow, or other activity types, since Mastodon doesn't
        # currently mark those as explicitly public.
        if not as2.is_public(activity_unwrapped):
            logging.info('Dropping non-public activity')
            return ''

        if actor:
            actor_id = actor.get('id')
            if actor_id:
                logging.info(f'Finding followers of {actor_id}')
                activity_obj.domains = [
                    f.src for f in Follower.query(Follower.dest == actor_id,
                                                  projection=[Follower.src]).fetch()]

        activity_obj.as2 = activity_as2_str
        activity_obj.as1 = activity_as1_str
        activity_obj.labels = ['feed', 'activity']
        activity_obj.put()
        logging.info(f'Wrote Object {id} for {len(activity_obj.domains)} followers')

    return 'OK'


def accept_follow(follow, follow_unwrapped, user):
    """Replies to an AP Follow request with an Accept request.

    Args:
      follow: dict, AP Follow activity
      follow_unwrapped: dict, same, except with redirect URLs unwrapped
      user: :class:`User`
    """
    logger.info('Replying to Follow with Accept')

    followee = follow.get('object')
    followee_unwrapped = follow_unwrapped.get('object')
    followee_id = (followee_unwrapped.get('id')
                   if isinstance(followee_unwrapped, dict) else followee_unwrapped)
    follower = follow.get('actor')
    if not followee or not followee_id or not follower:
        error(f'Follow activity requires object and actor. Got: {follow}')

    inbox = follower.get('inbox')
    follower_id = follower.get('id')
    if not inbox or not follower_id:
        error(f'Follow actor requires id and inbox. Got: {follower}')

    # rendered mf2 HTML proxy pages (in render.py) fall back to redirecting to
    # the follow's AS2 id field, but Mastodon's ids are URLs that don't load in
    # browsers, eg https://jawns.club/ac33c547-ca6b-4351-80d5-d11a6879a7b0
    # so, set a synthetic URL based on the follower's profile.
    # https://github.com/snarfed/bridgy-fed/issues/336
    follower_url = util.get_url(follower) or follower_id
    followee_url = util.get_url(followee_unwrapped) or followee_id
    follow_unwrapped.setdefault('url', f'{follower_url}#followed-{followee_url}')

    # store Follower
    follower = Follower.get_or_create(dest=user.key.id(), src=follower_id,
                                      last_follow=json_dumps(follow))
    follower.status = 'active'
    follower.put()

    # send AP Accept
    accept = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': util.tag_uri(common.PRIMARY_DOMAIN,
                           f'accept/{user.key.id()}/{follow.get("id")}'),
        'type': 'Accept',
        'actor': followee,
        'object': {
            'type': 'Follow',
            'actor': follower_id,
            'object': followee,
        }
    }
    resp = common.signed_post(inbox, data=accept, user=user)

    # send webmention
    common.send_webmentions(as2.to_as1(follow), proxy=True, source_protocol='activitypub',
                            as2=json_dumps(follow_unwrapped),
                            as1=json_dumps(as2.to_as1(follow_unwrapped)))

    return resp.text, resp.status_code


@ndb.transactional()
def undo_follow(undo_unwrapped):
    """Handles an AP Undo Follow request by deactivating the Follower entity.

    Args:
      undo_unwrapped: dict, AP Undo activity with redirect URLs unwrapped
    """
    logger.info('Undoing Follow')

    follow = undo_unwrapped.get('object', {})
    follower = follow.get('actor')
    followee = follow.get('object')
    if isinstance(followee, dict):
        followee = followee.get('id') or util.get_url(followee)
    if not follower or not followee:
        error(f'Undo of Follow requires object with actor and object. Got: {follow}')

    # deactivate Follower
    user_domain = util.domain_from_link(followee, minimize=False)
    follower_obj = Follower.get_by_id(Follower._id(dest=user_domain, src=follower))
    if follower_obj:
        logger.info(f'Marking {follower_obj.key} as inactive')
        follower_obj.status = 'inactive'
        follower_obj.put()
    else:
        logger.warning(f'No Follower found for {user_domain} {follower}')

    # TODO send webmention with 410 of u-follow


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/<any(followers,following):collection>')
@flask_util.cached(cache, CACHE_TIME)
def follower_collection(domain, collection):
    """ActivityPub Followers and Following collections.

    https://www.w3.org/TR/activitypub/#followers
    https://www.w3.org/TR/activitypub/#collections
    https://www.w3.org/TR/activitystreams-core/#paging
    """
    if not User.get_by_id(domain):
        return f'User {domain} not found', 404

    # page
    followers, new_before, new_after = common.fetch_followers(domain, collection)
    items = []
    for f in followers:
        f_as2 = f.to_as2()
        if f_as2:
            items.append(f_as2)

    page = {
        'type': 'CollectionPage',
        'partOf': request.base_url,
        'items': items,
    }
    if new_before:
        page['next'] = f'{request.base_url}?before={new_before}'
    if new_after:
        page['prev'] = f'{request.base_url}?after={new_after}'

    if 'before' in request.args or 'after' in request.args:
        page.update({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': request.url,
        })
        logger.info(f'Returning {json_dumps(page, indent=2)}')
        return page, {'Content-Type': as2.CONTENT_TYPE}

    # collection
    domain_prop = Follower.dest if collection == 'followers' else Follower.src
    count = Follower.query(
        Follower.status == 'active',
        domain_prop == domain,
    ).count()

    collection = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.base_url,
        'type': 'Collection',
        'summary': f"{domain}'s {collection}",
        'totalItems': count,
        'first': page,
    }
    logger.info(f'Returning {json_dumps(collection, indent=2)}')
    return collection, {'Content-Type': as2.CONTENT_TYPE}


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/outbox')
def outbox(domain):
    url = common.host_url(f"{domain}/outbox")
    return {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': url,
            'summary': f"{domain}'s outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': url,
                'items': [],
            },
        }, {'Content-Type': as2.CONTENT_TYPE}
