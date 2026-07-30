"""Serves the Mastodon API, backed by Bridgy Fed users and objects."""
from datetime import timezone
import functools
import logging
import os

from authlib.integrations.flask_oauth2.resource_protector import current_token
from flask import request
from google.cloud import ndb
from granary import as1, bluesky
from granary.mastodon import from_as1
from webutil import util
from webutil.flask_util import get_required_param, error
from werkzeug.exceptions import BadGateway, HTTPException

import activitypub
from activitypub import ActivityPub
from arroba import datastore_storage
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

# https://docs.joinmastodon.org/entities/Notification/#type
AS1_TO_NOTIFICATION_TYPE = {
    'like': 'favourite',
    'share': 'reblog',
    'follow': 'follow',
}


def auth(fn):
    """Requires a valid bearer token, resolves it to a :class:`models.User`.

    Passes the resolved user to the wrapped view function as a ``user`` kwarg.
    """
    @require_oauth()
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not (user := current_token.get_user()):
            error('Account not found', status=401)
        logger.info(f'Logged in as {user.key.id()} for {request.url}')
        return fn(*args, user=user, **kwargs)

    return wrapper


def to_account(user):
    """Converts a :class:`models.User` to a Mastodon ``Account``.

    Returns ``None`` if user can't be converted.
    """
    obj_as1 = user.obj.as1 if user.obj and user.obj.as1 else {}

    try:
        account = from_as1(obj_as1) or {}
    except:
        logger.info(user.key.id(), obj_as1)
        raise

    username = obj_as1.get('preferredUsername')
    acct = None
    if addr := user.handle_as(ActivityPub):
        acct = addr.removeprefix('@')
        if not username:
            username = acct.split('@')[0]

    account.update({
        'id': addr,
        'uri': user.id_as(ActivityPub),
        'username': username,
        'acct': acct,
        'display_name': user.name(),
        'created_at': (obj_as1.get('published')
                       or user.created.replace(tzinfo=timezone.utc).isoformat()),
    })
    return account


def to_status(obj):
    """Converts a :class:`models.Object` to a Mastodon ``Status``.

    Returns None if ``obj`` can't be converted, eg its AS1 ``objectType``/``verb``
    isn't supported, or its account can't be fetched or converted.
    """
    try:
        status = from_as1(obj.as1)
    except:
        logger.info(obj.key.id(), obj.as1)
        raise

    if not status:
        return None

    if from_proto := PROTOCOLS.get(obj.source_protocol):
        status['uri'] = ids.translate_object_id(
            id=obj.key.id(), from_=from_proto, to=ActivityPub)

    # TODO: parallelize/optimize
    if owner := load_owner(obj):
        status['account'] = to_account(owner)

    if not status['account']:
        return None

    if status.get('reblog') is not None:
        target_id = as1.get_id(obj.as1, 'object')
        if target_id and (target := Object.get_by_id(target_id)) and target.as1:
            status['reblog'] = to_status(target) or None
        else:
            status['reblog'] = None

    return status


def to_notification(obj):
    """Converts a :class:`models.Object` to a Mastodon ``Notification``.

    Returns None if ``obj`` can't be converted, eg its account can't be fetched or
    converted.
    """
    type = AS1_TO_NOTIFICATION_TYPE.get(obj.as1.get('verb'), 'mention')

    notif = {
        'id': obj.key.id(),
        'type': type,
        'created_at': (obj.as1.get('published')
                       or obj.created.replace(tzinfo=timezone.utc).isoformat()),
        'account': None,  # populated below
    }

    # TODO: parallelize/optimize

    if type in ('mention', 'quote'):
        notif['status'] = to_status(obj)
        if notif['status']:
            notif['account'] = notif['status']['account']

    elif type in ('favourite', 'follow', 'reblog'):
        target_id = as1.get_id(obj.as1, 'object')
        if target_id and (target := Object.get_by_id(target_id)) and target.as1:
            notif['status'] = to_status(target)

        if owner := load_owner(obj):
            notif['account'] = to_account(owner)

    if not notif['account']:
        return None

    return notif


def load_user(handle, resolve=False):
    try:
        return webfinger.load_user(handle, allow_opt_out=True)
    except HTTPException as e:
        logger.info(e)
        try:
            username, server = util.parse_acct_uri(handle)
            if username == server:
                handle = username
        except ValueError:
            pass
        try:
            return models.load_user(handle, proto=ActivityPub, create=resolve,
                                    allow_opt_out=True)
        except (AttributeError, RuntimeError, ValueError) as e:
            logger.info(e)


def load_object(id):
    obj = Object.get_by_id(id)
    if not obj or not obj.as1:
        error('Status not found', status=404)
    return obj


def load_owner(obj):
    """Loads the :class:`models.User` that owns ``obj``, if any.

    Returns None if ``obj`` has no owner, or if the owner can't be loaded, eg
    if their handle can't be resolved to a protocol.
    """
    if obj.users:
        return obj.users[0].get()

    if owner_id := as1.get_owner(obj.as1):
        try:
            return models.load_user(owner_id, create=True, allow_opt_out=True)
        except RuntimeError:
            logger.info(f"Couldn't load owner {owner_id}", exc_info=True)

    return None


#
# API endpoints
#

@app.get('/health')
def health():
    return {'status': 'UP'}


@app.get('/api/v2/instance')
def instance():
    return {
        'domain': 'brid.gy',
        'title': 'Bridgy Fed',
        'version': os.getenv('GAE_VERSION'),
        'source_url': 'https://github.com/snarfed/bridgy-fed',
        'description': 'Bridging the new social internet',
        'usage': {
            'users': {
                # TODO (from activitypub.nodeinfo)
                # 'active_month': None,
            }
        },
        'thumbnail': {
            'url': 'https://fed.brid.gy/static/bridgy_logo_with_alpha.png',
            'description': 'Hand-painted sketch of a bridge with just a few brush strokes',
            # 'blurhash': 'UeKUpFxuo~R%0nW;WCnhF6RjaJt757oJodS$',
            # 'versions': {
            #     '@1x': 'https://files.mastodon.social/site_uploads/files/000/000/001/@1x/57c12f441d083cde.png',
            #     '@2x': 'https://files.mastodon.social/site_uploads/files/000/000/001/@2x/57c12f441d083cde.png'
            # }
        },
        'icon': [{
            'src': 'https://fed.brid.gy/static/favicon.ico',
            'size': '32x32',
        }, {
            'src': 'https://brid.gy/static/bridgy_logo_with_alpha_128.png',
            'size': '128x128',
        }, {
            'src': 'https://fed.brid.gy/static/bridgy_logo_with_alpha.png',
            'size': '1200x600',
        }, {
            'src': 'https://fed.brid.gy/static/bridgy_logo_with_alpha_square_1024.png',
            'size': '1024x1024',
        }],
        'languages': ['en'],
        'configuration': {
            'urls': {
                'streaming': None,
                'status': None,
                'about': 'https://fed.brid.gy/docs',
                'privacy_policy': 'https://fed.brid.gy/docs#privacy',
                'terms_of_service': 'https://fed.brid.gy/docs#terms',
            },
            # 'vapid': {
            #     'public_key': '...'
            # },
            'accounts': {
                'max_featured_tags': 0,
                'max_pinned_statuses': 1,
            },
            # 'statuses': {
            #     'max_characters': 500,
            #     'max_media_attachments': 4,
            #     'characters_reserved_per_url': 23
            # },
            'media_attachments': {
                # 'description_limit': ,
                # 'image_matrix_limit': ,
                'image_size_limit': bluesky.MAX_MEDIA_SIZE_BYTES,
                'supported_mime_types': [
                    'image/jpeg',
                    'image/png',
                    'image/gif',
                    'image/webp',
                    'image/avif',
                    'video/mp4',
                ],
                # 'video_frame_rate_limit': None,
                # 'video_matrix_limit': None,
                'video_size_limit': datastore_storage.BLOB_MAX_BYTES,
            },
            'limited_federation': False,
        },
        'registrations': {
            'enabled': True,
            'approval_required': False,
            'reason_required': False,
            'message': None,
            # 'min_age': 16,
            'url': None,
        },
        'api_versions': {'mastodon': 6},
        'rules': [{
            'id': '1',
            'text': 'You agree not to deliberately attack, breach, or otherwise harm the service. If you manage to access private keys or other sensitive data, you agree to report the vulnerability and not use or disclose that data.',
            'hint': '',
        }],
        'contact': {
            'email': 'feedback@brid.gy',
            'account': {
                'id': '@anewsocial@mastodon.social',
                'username': '@anewsocial@mastodon.social',
                'acct': '@anewsocial@mastodon.social',
                'display_name': 'A New Social',
                'locked': False,
                'bot': False,
                'discoverable': True,
                'indexable': False,
                'group': False,
                'created_at': '2024-06-28T00:00:00.000Z',
                'note': '<p>Social media should be centered around people, not platforms. Let&#39;s build bridges, not walls. That&#39;s why we&#39;re building Bridgy Fed and Bounce.</p><p>Learn more: <a href="https://anew.social" target="_blank" rel="nofollow noopener" translate="no"><span class="invisible">https://</span><span class="">anew.social</span><span class="invisible"></span></a></p>',
                'url': 'https://mastodon.social/@anewsocial',
                'uri': 'https://mastodon.social/users/anewsocial',
                'avatar': 'https://files.mastodon.social/accounts/avatars/112/696/499/069/491/559/original/fbe51fe98b509adf.png',
                'avatar_static': 'https://files.mastodon.social/accounts/avatars/112/696/499/069/491/559/original/fbe51fe98b509adf.png',
                'avatar_description': '',
                'header': 'https://files.mastodon.social/accounts/headers/112/696/499/069/491/559/original/2834aa5dde24424e.png',
                'header_static': 'https://files.mastodon.social/accounts/headers/112/696/499/069/491/559/original/2834aa5dde24424e.png',
                'header_description': '',
                # 'followers_count': 1552,
                # 'following_count': 9,
                # 'statuses_count': 176,
                'last_status_at': '2026-07-06',
                'hide_collections': None,
                'show_media': True,
                'show_media_replies': True,
                'show_featured': True,
                'noindex': False,
                'emojis': [],
                'roles': [],
                'fields': [{
                    'name': 'A New Social',
                    'value': '<a href="https://www.anew.social" target="_blank" rel="nofollow noopener me" translate="no"><span class="invisible">https://www.</span><span class="">anew.social</span><span class="invisible"></span></a>',
                    'verified_at': None,
                },{
                    'name': 'Blog',
                    'value': '<a href="https://blog.anew.social" target="_blank" rel="nofollow noopener me" translate="no"><span class="invisible">https://</span><span class="">blog.anew.social</span><span class="invisible"></span></a>',
                    "verified_at": None,
                }],
            },
        },
    }

@app.get('/api/v1/instance/extended_description')
def instance_extended_description():
    return {
        'updated_at': util.now().isoformat(),
        'content': '<p>Bridges other networks to the fediverse. See <a href="https://fed.brid.gy/docs">the docs</a> for more.</p>',
    }


@app.get('/api/v1/instance/privacy_policy')
def instance_privacy_policy():
    return {
        'updated_at': util.now().isoformat(),
        'content': '<p>See <a href="/docs#privacy">our privacy policy</a>.</p>',
    }


@app.get('/api/v1/instance/terms_of_service')
def instance_terms_of_service():
    return {
        'effective_date': '2025-08-23',
        'effective': True,
        # copied from templates/docs.html
        'content': """\
<p>Bridgy Fed is both a service and an <a href='https://github.com/snarfed/bridgy-fed'>open source project</a>. The open source code is placed into the public domain, via the <a href='https://creativecommons.org/publicdomain/zero/1.0/'>CC0</a> license, and may be used by anyone for any purpose. The rest of these terms apply to the service.

<p>The Bridgy Fed service, served on *.brid.gy, is freely available to individuals and organizations to use for their own accounts.

<p>If you have a free, non-commercial product or hosting platform, you're welcome to integrate the Bridgy Fed service into it directly. Please <a href='mailto:letsbuild@anew.social'>let us know</a>, we'd love to hear about your project!

<p>If you'd like to integrate the Bridgy Fed service into a commercial or paid product or service, that's great too! <a href='mailto:letsbuild@anew.social'>Please contact us</a>, we can help. We'll probably also ask for, and expect, a reasonable <a href='https://www.patreon.com/c/ANewSocial'>donation</a>.

<p>You agree not to deliberately attack, breach, or otherwise harm the service. If you manage to access private keys or other sensitive data, you agree to <a href='#vulnerability'>report the vulnerability</a> and not use or disclose that data.
</p>
<p>Otherwise, you may use the service for any purpose you see fit. However, we may terminate or block your access for any reason, or no reason at all. (We've never done this, and we expect we never will. Just playing it safe.)
</p>
<p>Do you an administer an instance or other service that Bridgy Fed interacts with? If you have any concerns or questions, feel free to <a href='https://github.com/snarfed/bridgy-fed/issues'>file an issue</a>!</p>
""",
    }


@app.get('/api/v1/accounts/verify_credentials')
@auth
def verify_credentials(user):
    return to_account(user)


@app.get('/api/v1/accounts/lookup')
@auth
def accounts_lookup(user):
    if user := load_user(get_required_param('acct')):
        return to_account(user)

    error('Not found', status=404)


@app.get('/api/v1/accounts/relationships')
@auth
def accounts_relationships(user):
    relationships = []

    for addr in (request.args.getlist('id[]') + request.args.getlist('id')):
        # TODO: parallelize
        # TODO: unify with search
        if not (target := load_user(addr)):
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
    if user := load_user(addr):
        return to_account(user)

    error('Not found', status=404)


@app.get('/api/v1/accounts/<path:addr>/statuses')
@auth
def accounts_statuses(user, addr):
    # TODO: max_id, since_id, min_id, limit, only_media, exclude_replies,
    # exclude_reblogs, pinned, tagged
    target = load_user(addr)
    objects = Object.query(Object.users == target.key,
                           Object.type.IN(as1.POST_TYPES | set(['share'])),
                          ).order(-Object.created
                          ).fetch(LIMIT)
    return [s for obj in objects
            if obj.as1 and not obj.deleted and as1.is_public(obj.as1)
            and (s := to_status(obj))]


@app.get('/api/v1/accounts/<path:addr>/followers')
@auth
def accounts_followers(user, addr):
    followers, _, _ = Follower.fetch_page('followers', load_user(addr))
    return [to_account(f.user) for f in followers]


@app.get('/api/v1/accounts/<path:addr>/following')
@auth
def accounts_following(user, addr):
    following, _, _ = Follower.fetch_page('following', load_user(addr))
    return [to_account(f.user) for f in following]


@app.get('/api/v1/blocks')
@auth
def blocks(user):
    # TODO
    return []


@app.get('/api/v1/domain_blocks')
@auth
def domain_blocks_get(user):
    blocklists = ndb.get_multi(user.blocks)
    return [domain for list in blocklists for domain in list.domain_blocklist]


@app.get('/api/v1/favourites')
@auth
def favourites(user):
    likes = Object.query(Object.users == user.key,
                         Object.type == 'like',
                        ).order(-Object.created
                        ).fetch(LIMIT)
    ids = [as1.get_id(like.as1, 'object') for like in likes]
    objs = ndb.get_multi(Object(id=id).key for id in ids if id)
    return [status for obj in objs if obj and obj.as1 and (status := to_status(obj))]


@app.get('/api/v1/statuses')
@auth
def statuses_multiple(user):
    ids = request.args.getlist('id[]') + request.args.getlist('id')
    objs = ndb.get_multi(Object(id=id).key for id in ids)
    return [s for obj in objs
                  if obj and obj.as1 and not obj.deleted and as1.is_public(obj.as1)
            and (s := to_status(obj))]


@app.get('/api/v1/statuses/<path:id>')
@auth
def statuses_single(user, id):
    obj = load_object(id)
    if not (status := to_status(obj)):
        error('Status not found', status=404)
    return status


@app.get('/api/v1/statuses/<path:id>/context')
@auth
def statuses_context(user, id):
    obj = load_object(id)

    ancestors = []
    parent_id = as1.get_object(obj.as1, 'inReplyTo').get('id')
    while (parent_id and len(ancestors) < MAX_ANCESTORS
           and (parent := Object.get_by_id(parent_id)) and parent.as1):
        if parent_status := to_status(parent):
            ancestors.insert(0, parent_status)
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


@app.get('/api/v1/timelines/home')
@auth
def timelines_home(user):
    objects = Object.query(Object.feed == user.key
                           ).order(-Object.created
                           ).fetch(LIMIT)
    statuses = [to_status(obj) for obj in objects
                if obj.as1 and not obj.deleted and as1.is_public(obj.as1)]
    # TODO: formalize
    return [s for s in statuses
            if s and s.get('account')
            and (not s['reblog'] or s['reblog'].get('account'))]


@app.get('/api/v1/timelines/public')
@auth
def timelines_public(user):
    objects = Object.query(Object.type.IN(as1.POST_TYPES | set(['share'])),
                           ).order(-Object.created
                           ).fetch(LIMIT)
    return [status for obj in objects
            if obj.as1 and not obj.deleted and as1.is_public(obj.as1)
            and (status := to_status(obj))]


@app.get('/api/v1/timelines/tag/<hashtag>')
@auth
def timelines_tag(user, hashtag):
    return []


@app.get('/api/v1/notifications')
@auth
def notifications_list(user):
    # TODO: unbridged notifs
    objects = Object.query(Object.notify == user.key
                           ).order(-Object.updated
                           ).fetch(LIMIT)
    return [notif for obj in objects
            if obj.as1 and not obj.deleted and as1.is_public(obj.as1)
            and (notif := to_notification(obj))]


@app.get('/api/v1/notifications/<path:id>')
@auth
def notifications_get(user, id):
    obj = Object.get_by_id(id)
    if (obj and obj.as1 and not obj.deleted and as1.is_public(obj.as1)
            and user.key in obj.notify):
        if notif := to_notification(obj):
            return notif

    error('Notification not found', status=404)


@app.get('/api/v1/notifications/unread_count')
@auth
def notifications_unread_count(user):
    # we don't currently track read vs unread
    return {'count': 0}


@app.get('/api/v2/search')
@auth
def search(user):
    resp = {
        'accounts': [],
        'statuses': [],
        'hashtags': [],
    }

    q = get_required_param('q').strip()
    resolve = request.args.get('resolve', '').lower() == 'true'
    type = request.args.get('type')

    if not type or type == 'accounts':
        if user := load_user(q, resolve=True):
            if acct := to_account(user):
                resp['accounts'] = [acct]

    if not type or type == 'statuses':
        if obj := Object.get_by_id(q):
            if status := to_status(obj):
                resp['statuses'] = [status]

    return resp
