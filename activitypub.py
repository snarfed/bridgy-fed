"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
from base64 import b64encode
import datetime
from hashlib import sha256
import logging
import re
import threading

from cachetools import LRUCache
from flask import request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1, as2
from httpsig import HeaderVerifier
from httpsig.utils import parse_signature_header
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

    # parse and validate AS2 activity
    try:
        activity = request.json
        assert activity
    except (TypeError, ValueError, AssertionError):
        error(f"Couldn't parse body as JSON: {body}", exc_info=True)


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
            logger.info(msg)
            return msg, 200

    activity_unwrapped = redirect_unwrap(activity)
    activity_obj = Object(
        id=id,
        as2=json_dumps(activity_unwrapped),
        source_protocol='activitypub')
    activity_obj.put()

    if type == 'Accept':  # eg in response to a Follow
        return ''  # noop
    if type not in SUPPORTED_TYPES:
        error(f'Sorry, {type} activities are not supported yet.', status=501)

    # load user
    user = None
    if domain:
        user = User.get_by_id(domain)
        if not user:
            return f'User {domain} not found', 404

    # optionally verify signature
    # TODO: switch this from erroring to logging lots of detail. need to see
    # which headers, key shapes, etc we get in the wild.
    sig = request.headers.get('Signature')
    if sig:
        logger.info(f'Headers: {json_dumps(dict(request.headers), indent=2)}')
        # parse_signature_header lower-cases all keys
        keyId = parse_signature_header(sig).get('keyid')
        digest = request.headers.get('Digest') or ''
        expected = b64encode(sha256(request.data).digest()).decode()
        if not keyId:
            logger.warning('HTTP Signature missing keyId')
        elif not digest:
            logger.warning('Missing Digest header, required for HTTP Signature')
        elif digest.removeprefix('SHA-256=') != expected:
            logger.warning('Invalid Digest header, required for HTTP Signature')
        else:
            key_actor = json_loads(common.get_object(keyId, user=user).as2)
            key = key_actor.get("publicKey", {}).get('publicKeyPem')
            logger.info(f'Verifying signature for {request.path} with key {key}')
            try:
                if HeaderVerifier(request.headers, key, required_headers=['Digest'],
                                  method=request.method, path=request.path,
                                  sign_header='signature').verify():
                    logger.info('HTTP Signature verified!')
                else:
                    logger.warning('HTTP Signature verification failed')
            except BaseException as e:
                logger.warning(f'HTTP Signature verification failed: {e}')
    else:
        logger.info('No HTTP Signature')

    # handle activity!
    if type == 'Undo' and obj_as2.get('type') == 'Follow':
        # skip actor fetch below; we don't need it to undo a follow
        undo_follow(activity_unwrapped)
        activity_obj.status = 'complete'
        activity_obj.put()
        return 'OK'

    elif type == 'Update':
        obj_id = obj_as2.get('id')
        if not obj_id:
            error("Couldn't find obj_id of object to update")

        obj = Object.get_by_id(obj_id) or Object(id=obj_id)
        obj.populate(
            as2=json_dumps(obj_as2),
            source_protocol='activitypub',
        )
        obj.put()

        activity_obj.status = 'complete'
        activity_obj.put()
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
        activity_obj.status = 'complete'
        ndb.put_multi(followers + [activity_obj])
        return 'OK'

    # fetch actor if necessary so we have name, profile photo, etc
    if actor and isinstance(actor, str):
        actor = activity['actor'] = activity_unwrapped['actor'] = \
            json_loads(common.get_object(actor, user=user).as2)

    # fetch object if necessary so we can render it in feeds
    inner_obj = activity_unwrapped.get('object')
    if type in FETCH_OBJECT_TYPES and isinstance(inner_obj, str):
        obj = Object.get_by_id(inner_obj) or common.get_object(inner_obj, user=user)
        obj_as2 = activity['object'] = activity_unwrapped['object'] = \
            json_loads(obj.as2) if obj.as2 else as2.from_as1(json_loads(obj.as1))

    if type == 'Follow':
        resp = accept_follow(activity, activity_unwrapped, user)

    # send webmentions to each target
    activity_obj.as2 = json_dumps(activity_unwrapped)
    common.send_webmentions(as2.to_as1(activity), activity_obj, proxy=True)

    # deliver original posts and reposts to followers
    if ((type == 'Create' and not activity.get('inReplyTo') and not obj_as2.get('inReplyTo'))
        or type == 'Announce'):
        # check that this activity is public. only do this check for Creates,
        # not Like, Follow, or other activity types, since Mastodon doesn't
        # currently mark those as explicitly public.
        if not as2.is_public(activity_unwrapped):
            logger.info('Dropping non-public activity')
            return ''

        if actor:
            actor_id = actor.get('id')
            if actor_id:
                logger.info(f'Finding followers of {actor_id}')
                for f in Follower.query(Follower.dest == actor_id,
                                        projection=[Follower.src]):
                    if f.src not in activity_obj.domains:
                        activity_obj.domains.append(f.src)
                if activity_obj.domains and 'feed' not in activity_obj.labels:
                    activity_obj.labels.append('feed')

    if (activity_obj.as1.get('objectType') == 'activity'
        and 'activity' not in activity_obj.labels):
        activity_obj.labels.append('activity')

    activity_obj.put()
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
    return common.signed_post(inbox, data=accept, user=user)


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
