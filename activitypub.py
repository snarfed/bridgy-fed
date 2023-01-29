"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import datetime
import logging
import re

from flask import request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as1, as2
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from common import CACHE_TIME, redirect_unwrap, redirect_wrap
from models import Follower, Object, User

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


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>')
@flask_util.cached(cache, CACHE_TIME, http_5xx=True)
def actor(domain):
    """Fetches a domain's h-card and converts to AS2 actor."""
    _, _, actor, _ = common.actor(domain)
    return (actor, {
        'Content-Type': as2.CONTENT_TYPE,
        'Access-Control-Allow-Origin': '*',
    })


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

    obj = activity.get('object') or {}
    if isinstance(obj, str):
        obj = {'id': obj}

    if type == 'Accept':  # eg in response to a Follow
        return ''  # noop
    if type not in SUPPORTED_TYPES:
        error(f'Sorry, {type} activities are not supported yet.', status=501)

    # TODO: verify signature if there is one

    if type == 'Undo' and obj.get('type') == 'Follow':
        # skip actor fetch below; we don't need it to undo a follow
        undo_follow(redirect_unwrap(activity))
        return ''
    elif type == 'Update':
        if obj.get('type') == 'Person':
            return ''  # noop
        else:
            error(f'Sorry, {type} activities are not supported yet.', status=501)
    elif type == 'Delete':
        # we currently only actually delete followers for Deletes that are sent
        # to the shared inbox, not individual users' inboxes, to help scaling
        # background: https://github.com/snarfed/bridgy-fed/issues/284
        if domain:
            logger.info('Skipping Delete sent to individual user inbox')
            return 'OK'

        id = obj.get('id') if isinstance(obj, dict) else obj
        if not isinstance(id, str):
            error("Couldn't find id of object to delete")
            # assume this is an actor
            # https://github.com/snarfed/bridgy-fed/issues/63
        logger.info(f'Deactivating Followers with src or dest = {id}')
        followers = Follower.query(OR(Follower.src == id,
                                      Follower.dest == id)
                                   ).fetch()
        for f in followers:
            f.status = 'inactive'
        ndb.put_multi(followers)
        return 'OK'

    user = User.get_or_create(domain) if domain else None

    # fetch actor if necessary so we have name, profile photo, etc
    if actor and isinstance(actor, str):
        actor = activity['actor'] = common.get_as2(actor, user=user).json()

    activity_unwrapped = redirect_unwrap(activity)
    if type == 'Follow':
        return accept_follow(activity, activity_unwrapped, user)

    # send webmentions to each target
    activity_as2_str = json_dumps(activity_unwrapped)
    activity_as1 = as2.to_as1(activity_unwrapped)
    as1_type = as1.object_type(activity_as1)
    activity_as1_str = json_dumps(activity_as1)
    sent = common.send_webmentions(as2.to_as1(activity), proxy=True,
                                   source_protocol='activitypub',
                                   as2=activity_as2_str, as1=activity_as1_str,
                                   type=as1_type)

    if not sent and type in ('Create', 'Announce'):
        # check that this activity is public. only do this check for Creates,
        # not Like, Follow, or other activity types, since Mastodon doesn't
        # currently mark those as explicitly public.
        if not as2.is_public(activity_unwrapped):
            logging.info('Dropping non-public activity')
            return ''

        # normal post, deliver to BF followers
        source = util.get_first(activity, 'url') or activity.get('id')
        domains = []
        if actor:
            actor_id = actor.get('id')
            if actor_id:
                logging.info(f'Finding followers of {actor_id}')
                domains = [f.src for f in
                           Follower.query(Follower.dest == actor_id,
                                          projection=[Follower.src]).fetch()]

        key = Object(id=source, source_protocol='activitypub', domains=domains,
                     status='complete', as2=activity_as2_str, as1=activity_as1_str,
                     type=as1_type).put()
        logging.info(f'Wrote Object {key} with {len(domains)} follower domains')

    return ''


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
    followee_domain = util.domain_from_link(followee_id, minimize=False)
    # follow use_instead, if any
    followee_domain = User.get_or_create(followee_domain).key.id()
    follower = Follower.get_or_create(dest=followee_domain, src=follower_id,
                                      last_follow=json_dumps(follow))
    follower.status = 'active'
    follower.put()

    # send AP Accept
    accept = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': util.tag_uri(common.PRIMARY_DOMAIN,
                           f'accept/{followee_domain}/{follow.get("id")}'),
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
                            as1=json_dumps(as2.to_as1(follow_unwrapped)),
                            type='follow')

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
