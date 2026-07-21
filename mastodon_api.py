"""Serves the Mastodon API, backed by Bridgy Fed users and objects."""
from datetime import timezone
import functools
import logging

from authlib.integrations.flask_oauth2.resource_protector import current_token
from flask import request
from granary import as1
from granary.mastodon import from_as1
from webutil import util
from webutil.flask_util import get_required_param, error
from werkzeug.exceptions import BadGateway, HTTPException

import activitypub
from activitypub import ActivityPub
from flask_app import app
import ids
from mastodon_oauth import require_oauth
import models
from models import Follower, Object, PROTOCOLS
import webfinger

logger = logging.getLogger(__name__)

# how many results to return for list endpoints; we don't support paging yet
LIMIT = 20

# how many ancestors to include in a status's context
MAX_ANCESTORS = 20


def auth(fn):
    """Requires a valid bearer token, resolves it to a :class:`models.User`.

    Passes the resolved user to the wrapped view function as a ``user`` kwarg.
    """
    @require_oauth()
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not (user := current_token.get_user()):
            error('Account not found', status=401)
        return fn(*args, user=user, **kwargs)

    return wrapper


def account(user):
    """Converts a :class:`models.User` to a Mastodon ``Account``."""
    obj_as1 = user.obj.as1 if user.obj and user.obj.as1 else {}

    account = from_as1(obj_as1)
    addr = user.handle_as(ActivityPub)
    account.update({
        'id': addr,
        'uri': user.id_as(ActivityPub),
        'username': user.handle,
        'acct': addr,
        'display_name': user.name(),
        'created_at': (obj_as1.get('published')
                       or user.created.replace(tzinfo=timezone.utc).isoformat()),
    })
    return account


def status(obj):
    """Converts a :class:`models.Object` to a Mastodon ``Status``."""
    status = from_as1(obj.as1)

    if from_proto := PROTOCOLS.get(obj.source_protocol):
        status['uri'] = ids.translate_object_id(
            id=obj.key.id(), from_=from_proto, to=ActivityPub)

    if obj.users and (author := obj.users[0].get()):
        status['account'] = account(author)

    return status


def load_object(id):
    obj = Object.get_by_id(id)
    if not obj or not obj.as1:
        error('Status not found', status=404)
    return obj


@app.get('/api/v1/accounts/verify_credentials')
@auth
def verify_credentials(user):
    return account(user)


@app.get('/api/v1/accounts/lookup')
@auth
def accounts_lookup(user):
    acct = get_required_param('acct')
    if '@' not in acct:
        error('Status not found', status=404)

    if not acct.startswith('@'):
        acct = '@' + acct

    return account(webfinger.load_user(acct))


@app.get('/api/v1/accounts/relationships')
@auth
def accounts_relationships(user):
    relationships = []

    for addr in (request.args.getlist('id[]') + request.args.getlist('id')):
        # TODO: parallelize
        # TODO: unify with search
        try:
            target = activitypub.load_user(addr, create=False)
        except HTTPException as e:
            logger.info(e)
            try:
                target = webfinger.load_user(addr)
            except HTTPException as e:
                logger.info(e)
                continue

        following = bool(Follower.query(Follower.from_ == user.key,
                                        Follower.to == target.key,
                                        Follower.status == 'active'
                                        ).get(keys_only=True))
        followed_by = bool(Follower.query(Follower.from_ == target.key,
                                          Follower.to == user.key,
                                          Follower.status == 'active'
                                          ).get(keys_only=True))
        relationships.append({
            'id': target.handle_as(ActivityPub),
            'following': following,
            'showing_reblogs': following,
            'followed_by': followed_by,
            # TODO
            'blocking': False,
            'blocked_by': False,
            'domain_blocking': False,
            'endorsed': False,
            'muting': False,
            'muting_notifications': False,
            'notifying': False,
            'requested': False,
            'note': '',
        })

    return relationships


@app.get('/api/v1/accounts/<path:addr>')
@auth
def accounts_get(user, addr):
    return account(webfinger.load_user(addr))


@app.get('/api/v1/accounts/<path:addr>/statuses')
@auth
def accounts_statuses(user, addr):
    # TODO: max_id, since_id, min_id, limit, only_media, exclude_replies,
    # exclude_reblogs, pinned, tagged
    target = webfinger.load_user(addr)
    objects = Object.query(Object.users == target.key,
                           Object.type.IN(as1.POST_TYPES),
                          ).order(-Object.created
                          ).fetch(LIMIT)
    return [status(obj) for obj in objects if obj.as1]


@app.get('/api/v1/accounts/<path:addr>/followers')
@auth
def accounts_followers(user, addr):
    followers, _, _ = Follower.fetch_page('followers', webfinger.load_user(addr))
    return [account(f.user) for f in followers]


@app.get('/api/v1/accounts/<path:addr>/following')
@auth
def accounts_following(user, addr):
    following, _, _ = Follower.fetch_page('following', webfinger.load_user(addr))
    return [account(f.user) for f in following]


@app.get('/api/v1/blocks')
@auth
def blocks(user):
    # TODO
    return []


@app.get('/api/v1/favourites')
@auth
def favourites(user):
    likes = Object.query(Object.users == user.key,
                         Object.type == 'like',
                        ).order(-Object.created
                        ).fetch(LIMIT)

    statuses = []
    for like in likes:
        target_id = as1.get_id(like.as1, 'object')
        # TODO: parallelize
        # TODO: convert target_id to native protocol?
        if target_id and (target := Object.get_by_id(target_id)) and target.as1:
            statuses.append(status(target))

    return statuses


@app.get('/api/v1/statuses/<path:id>')
@auth
def statuses_get(user, id):
    return status(load_object(id))


@app.get('/api/v1/statuses/<path:id>/context')
@auth
def statuses_context(user, id):
    obj = load_object(id)

    ancestors = []
    parent_id = as1.get_object(obj.as1, 'inReplyTo').get('id')
    while (parent_id and len(ancestors) < MAX_ANCESTORS
           and (parent := Object.get_by_id(parent_id)) and parent.as1):
        ancestors.insert(0, status(parent))
        # TODO: convert to native protocol?
        parent_id = as1.get_id(parent.as1, 'inReplyTo')

    return {
        'ancestors': ancestors,
        # descendants aren't indexed, so we can't look them up efficiently
        'descendants': [],
    }


@app.get('/api/v1/statuses/<path:id>/favourited_by')
@auth
def statuses_favourited_by(user, id):
    load_object(id)
    # likes aren't indexed by target, so we can't look them up efficiently
    return []


@app.get('/api/v1/statuses/<path:id>/reblogged_by')
@auth
def statuses_reblogged_by(user, id):
    load_object(id)
    # reposts aren't indexed by target, so we can't look them up efficiently
    return []


@app.get('/api/v1/timelines/public')
@auth
def timelines_public(user):
    objects = Object.query(Object.feed == user.key
                           ).order(-Object.created
                           ).fetch(LIMIT)
    return [status(obj) for obj in objects if obj.as1]


@app.get('/api/v1/timelines/tag/<hashtag>')
@auth
def timelines_tag(user, hashtag):
    return []


@app.get('/api/v2/search')
@auth
def search(user):
    q = get_required_param('q')
    resolve = request.args.get('resolve', '').lower() == 'true'

    user = None
    if request.args.get('type') == 'accounts':
        try:
            user = activitypub.load_user(q, create=resolve)
        except HTTPException as e:
            logger.info(e)
            try:
                user = webfinger.load_user(q)
            except HTTPException as e:
                logger.info(e)

    return {
        'accounts': [account(user)] if user else [],
        'statuses': [],
        'hashtags': [],
    }
