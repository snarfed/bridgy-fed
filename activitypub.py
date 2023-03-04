"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
from base64 import b64encode
import datetime
from hashlib import sha256
import logging
import re
import threading

from cachetools import LRUCache
from flask import abort, make_response, request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1, as2
from httpsig import HeaderVerifier
from httpsig.utils import parse_signature_header
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from common import CACHE_TIME, host_url, redirect_unwrap, redirect_wrap, TLD_BLOCKLIST
from models import Follower, Object, Target, User

logger = logging.getLogger(__name__)

SUPPORTED_TYPES = (  # AS1
    'accept',
    'article',
    'audio',
    'comment',
    'create',
    'delete',
    'follow',
    'image',
    'like',
    'note',
    'post',
    'share',
    'stop-following',
    'undo',
    'update',
    'video',
)
FETCH_OBJECT_TYPES = (
    'share',
)

# activity ids that we've already handled and can now ignore
seen_ids = LRUCache(100000)
seen_ids_lock = threading.Lock()


def error(msg, status=400):
    """Like flask_util.error, but wraps body in JSON."""
    logger.info(f'Returning {status}: {msg}')
    abort(status, response=make_response({'error': msg}, status))


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
        **common.postprocess_as2(user.actor_as2, user=user),
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
        assert activity and isinstance(activity, dict)
    except (TypeError, ValueError, AssertionError):
        error(f"Couldn't parse body as non-empty JSON mapping: {body}", exc_info=True)

    actor = activity.get('actor')
    actor_id = actor.get('id') if isinstance(actor, dict) else actor
    logger.info(f'Got {activity.get("type")} activity from {actor_id}: {json_dumps(activity, indent=2)}')

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

    obj = Object(id=id, as2=redirect_unwrap(activity), source_protocol='activitypub')
    obj.put()

    if obj.type == 'accept':  # eg in response to a Follow
        return 'OK'  # noop
    elif obj.type not in SUPPORTED_TYPES:
        error(f'Sorry, {obj.type} activities are not supported yet.', status=501)

    inner_obj = as1.get_object(obj.as1)
    inner_obj_id = inner_obj.get('id')

    # load user
    user = None
    if domain:
        user = User.get_by_id(domain)
        if not user:
            error(f'User {domain} not found', status=404)

    verify_signature(user)

    # check that this activity is public. only do this check for creates, not
    # like, follow, or other activity types, since Mastodon doesn't currently
    # mark those as explicitly public. Use as2's is_public instead of as1's
    # because as1's interprets unlisted as true.
    if obj.type in ('post', 'create') and not as2.is_public(obj.as2):
        logger.info('Dropping non-public activity')
        return 'OK'

    # store inner object
    if obj.type in ('post', 'create', 'update') and inner_obj.keys() > set(['id']):
        to_update = Object.get_by_id(inner_obj_id) or Object(id=inner_obj_id)
        to_update.populate(as2=obj.as2['object'], source_protocol='activitypub')
        to_update.put()

    # handle activity!
    if obj.type == 'stop-following':
        # granary doesn't yet handle three-actor undo follows, eg Eve undoes
        # Alice following Bob
        follower = as1.get_object(as1.get_object(activity, 'object'), 'actor')
        assert actor_id == follower.get('id')

        if not actor_id or not inner_obj_id:
            error(f'Undo of Follow requires object with actor and object. Got: {actor_id} {followee} {obj.as1}')

        # deactivate Follower
        followee_domain = util.domain_from_link(inner_obj_id, minimize=False)
        follower = Follower.get_by_id(Follower._id(dest=followee_domain, src=actor_id))
        if follower:
            logging.info(f'Marking {follower} inactive')
            follower.status = 'inactive'
            follower.put()
        else:
            logger.warning(f'No Follower found for {followee_domain} {actor_id}')

        # TODO send webmention with 410 of u-follow

        obj.status = 'complete'
        obj.put()
        return 'OK'

    elif obj.type == 'update':
        if not inner_obj_id:
            error("Couldn't find id of object to update")

        obj.status = 'complete'
        obj.put()
        return 'OK'

    elif obj.type == 'delete':
        if not inner_obj_id:
            error("Couldn't find id of object to delete")

        to_delete = Object.get_by_id(inner_obj_id)
        if to_delete:
            logger.info(f'Marking Object {inner_obj_id} deleted')
            to_delete.deleted = True
            to_delete.put()

        # assume this is an actor
        # https://github.com/snarfed/bridgy-fed/issues/63
        logger.info(f'Deactivating Followers with src or dest = {inner_obj_id}')
        followers = Follower.query(OR(Follower.src == inner_obj_id,
                                      Follower.dest == inner_obj_id)
                                   ).fetch()
        for f in followers:
            f.status = 'inactive'
        obj.status = 'complete'
        ndb.put_multi(followers + [obj])
        return 'OK'

    # fetch actor if necessary so we have name, profile photo, etc
    if actor and isinstance(actor, str):
        actor = obj.as2['actor'] = common.get_object(actor, user=user).as2

    # fetch object if necessary so we can render it in feeds
    if obj.type in FETCH_OBJECT_TYPES and inner_obj.keys() == set(['id']):
        inner_obj = obj.as2['object'] = common.get_object(inner_obj_id, user=user).as2

    if obj.type == 'follow':
        resp = accept_follow(obj, user)

    # send webmentions to each target
    common.send_webmentions(as2.to_as1(activity), obj, proxy=True)

    # deliver original posts and reposts to followers
    if obj.type in ('share', 'create', 'post') and actor and actor_id:
        logger.info(f'Delivering to followers of {actor_id}')
        for f in Follower.query(Follower.dest == actor_id,
                                Follower.status == 'active',
                                projection=[Follower.src]):
            if f.src not in obj.domains:
                obj.domains.append(f.src)
        if obj.domains and 'feed' not in obj.labels:
            obj.labels.append('feed')

    if obj.as1.get('objectType') == 'activity' and 'activity' not in obj.labels:
        obj.labels.append('activity')

    obj.put()
    return 'OK'


def verify_signature(user):
    """Verifies the current request's HTTP Signature.

    Args:
      user: :class:`User`

    Logs details of the result. Raises :class:`werkzeug.HTTPSignature` if the
    signature is missing or invalid, otherwise does nothing and returns None.
    """
    sig = request.headers.get('Signature')
    if not sig:
        error('No HTTP Signature', status=401)

    logger.info(f'Headers: {json_dumps(dict(request.headers), indent=2)}')

    # parse_signature_header lower-cases all keys
    keyId = parse_signature_header(sig).get('keyid')
    if not keyId:
        error('HTTP Signature missing keyId', status=401)

    digest = request.headers.get('Digest') or ''
    if not digest:
        error('Missing Digest header, required for HTTP Signature', status=401)

    expected = b64encode(sha256(request.data).digest()).decode()
    if digest.removeprefix('SHA-256=') != expected:
        error('Invalid Digest header, required for HTTP Signature', status=401)

    key_actor = common.get_object(keyId, user=user).as2
    key = key_actor.get("publicKey", {}).get('publicKeyPem')
    logger.info(f'Verifying signature for {request.path} with key {key}')
    try:
        verified = HeaderVerifier(request.headers, key,
                                  required_headers=['Digest'],
                                  method=request.method,
                                  path=request.path,
                                  sign_header='signature').verify()
    except BaseException as e:
        error(f'HTTP Signature verification failed: {e}', status=401)

    if verified:
        logger.info('HTTP Signature verified!')
    else:
        error('HTTP Signature verification failed', status=401)


def accept_follow(obj, user):
    """Replies to an AP Follow request with an Accept request.

    Args:
      obj: :class:`Object`
      user: :class:`User`
    """
    logger.info('Replying to Follow with Accept')

    followee = obj.as2.get('object')
    followee_id = followee.get('id') if isinstance(followee, dict) else followee
    follower = obj.as2.get('actor')
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
    followee_url = util.get_url(followee) or followee_id
    obj.as2.setdefault('url', f'{follower_url}#followed-{followee_url}')

    # store Follower
    follower_obj = Follower.get_or_create(dest=user.key.id(), src=follower_id,
                                          last_follow=obj.as2)
    follower_obj.status = 'active'
    follower_obj.put()

    # send AP Accept
    followee_actor_url = host_url(user.key.id())
    accept = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': util.tag_uri(common.PRIMARY_DOMAIN,
                           f'accept/{user.key.id()}/{obj.key.id()}'),
        'type': 'Accept',
        'actor': followee_actor_url,
        'object': {
            'type': 'Follow',
            'actor': follower_id,
            'object': followee_actor_url,
        }
    }
    return common.signed_post(inbox, data=accept, user=user)


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
