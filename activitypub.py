"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
import datetime
import logging
import re

from flask import request
from google.cloud import ndb
from google.cloud.ndb import OR
from granary import as2
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from common import CACHE_TIME, redirect_unwrap, redirect_wrap
from models import Activity, Follower, User

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
    'Video',
)


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>')
@flask_util.cached(cache, CACHE_TIME)
def actor(domain):
    """Fetches a domain's h-card and converts to AS2 actor."""
    actor = common.actor(domain)
    return (actor, {
        'Content-Type': as2.CONTENT_TYPE,
        'Access-Control-Allow-Origin': '*',
    })


@app.post(f'/inbox')
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
        error('Sorry, %s activities are not supported yet.' % type,
                     status=501)

    # TODO: verify signature if there is one

    if type == 'Undo' and obj.get('type') == 'Follow':
        # skip actor fetch below; we don't need it to undo a follow
        undo_follow(redirect_unwrap(activity))
        return ''
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
    as1 = as2.to_as1(activity)
    source_as2 = json_dumps(activity_unwrapped)
    sent = common.send_webmentions(as1, proxy=True, protocol='activitypub',
                                   source_as2=source_as2)

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
        key = Activity(source=source, target='Public', direction='in',
                       protocol='activitypub', domain=domains, status='complete',
                       source_as2=source_as2).put()
        logging.info(f'Wrote Activity {key} with {len(domains)} follower domains')

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
    if isinstance(followee_unwrapped, dict):
        followee_unwrapped = followee_unwrapped.get('id')
    follower = follow.get('actor')
    if not followee or not followee_unwrapped or not follower:
        error('Follow activity requires object and actor. Got: %s' % follow)

    inbox = follower.get('inbox')
    follower_id = follower.get('id')
    if not inbox or not follower_id:
        error('Follow actor requires id and inbox. Got: %s', follower)

    # store Follower
    followee_domain = util.domain_from_link(followee_unwrapped, minimize=False)
    # follow use_instead, if any
    followee_domain = User.get_or_create(followee_domain).key.id()
    follower = Follower.get_or_create(dest=followee_domain, src=follower_id,
                                      last_follow=json_dumps(follow))
    follower.status = 'active'
    follower.put()

    # send AP Accept
    accept = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': util.tag_uri(common.PRIMARY_DOMAIN, 'accept/%s/%s' % (
            (followee_domain, follow.get('id')))),
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
    common.send_webmentions(as2.to_as1(follow), proxy=True, protocol='activitypub',
                            source_as2=json_dumps(follow_unwrapped))

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
        error('Undo of Follow requires object with actor and object. Got: %s' % follow)

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


# TODO: unify with following_collection
@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/followers')
@flask_util.cached(cache, CACHE_TIME)
def followers_collection(domain):
    """ActivityPub Followers collection.

    https://www.w3.org/TR/activitypub/#followers
    https://www.w3.org/TR/activitypub/#collections
    https://www.w3.org/TR/activitystreams-core/#paging
    """
    if not User.get_by_id(domain):
        return f'User {domain} not found', 404

    logger.info(f"Counting {domain}'s followers")
    count = Follower.query(
        Follower.status == 'active',
        Follower.dest == domain,
    ).count()

    ret = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'summary': f"{domain}'s followers",
        'type': 'Collection',
        'totalItems': count,
        'items': [],  # TODO
    }
    logger.info(f'Returning {json_dumps(ret, indent=2)}')
    return ret


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/following')
@flask_util.cached(cache, CACHE_TIME)
def following_collection(domain):
    """ActivityPub Following collection.

    https://www.w3.org/TR/activitypub/#following
    https://www.w3.org/TR/activitypub/#collections
    https://www.w3.org/TR/activitystreams-core/#paging
    """
    if not User.get_by_id(domain):
        return f'User {domain} not found', 404

    logger.info(f"Counting {domain}'s following")
    count = Follower.query(
        Follower.status == 'active',
        Follower.src == domain,
    ).count()

    ret = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'summary': f"{domain}'s following",
        'type': 'Collection',
        'totalItems': count,
        'items': [],  # TODO
    }
    logger.info(f'Returning {json_dumps(ret, indent=2)}')
    return ret
