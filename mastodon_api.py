"""Serves the Mastodon API, backed by Bridgy Fed users and objects."""
from datetime import timedelta, timezone
import functools
import logging
import os
from urllib.parse import unquote

from authlib.integrations.flask_oauth2.resource_protector import current_token
from flask import request
from google.cloud import ndb
from granary import as1, bluesky
from granary.mastodon import decode_id, encode_id, from_as1
from webutil.appengine_info import DEBUG, LOCAL_SERVER
from webutil import util
from webutil.flask_util import (
    bool_param,
    error,
    get_required_param,
    handle_exception,
    MODERN_HEADERS,
)
from werkzeug.exceptions import HTTPException, MethodNotAllowed, NotFound

import activitypub
from activitypub import ActivityPub
from arroba import datastore_storage
from atproto import ATProto
import common
import domains
from domains import DOMAINS, PRIMARY_DOMAIN
from flask_app import app
import ids
from mastodon_oauth import require_oauth
import memcache
import models
from models import Follower, Object, PROTOCOLS
from ui import UIProtocol
import webfinger

logger = logging.getLogger(__name__)

# limits for list endpoints
DEFAULT_LIMIT = 20
MAX_LIMIT = 40

# how many ancestors to include in a status's context
MAX_ANCESTORS = 20

# how many descendants to include in a status's context, and how many levels of
# replies to walk down to find them
# https://docs.joinmastodon.org/methods/statuses/#context
MAX_DESCENDANTS = 40
MAX_DESCENDANT_DEPTH = 20

# https://docs.joinmastodon.org/entities/Notification/#type
AS1_TO_NOTIFICATION_TYPE = {
    'like': 'favourite',
    'share': 'reblog',
    'follow': 'follow',
}

# how many notifications /api/v2/notifications fetches and then aggregates into
# groups. the datastore can't group, so we over-fetch and collapse in memory,
# which means notifications_count under-counts groups bigger than this.
GROUPED_NOTIF_OBJECT_FETCHES = 100

# notification types that /api/v2/notifications groups by default, ie when the
# grouped_types[] query param isn't provided
# https://docs.joinmastodon.org/methods/grouped_notifications/#get-grouped
GROUPED_NOTIF_TYPES = ('favourite', 'reblog', 'follow')

# how many accounts each notification group includes in sample_account_ids
GROUPED_NOTIF_SAMPLE_ACCOUNTS = 8

MEMOIZE_EXPIRATION = timedelta(seconds=15)


def cache_global(fn):
    return memcache.memoize(
        key=lambda **_: request.full_path,
        expire=MEMOIZE_EXPIRATION,
        )(fn)


def cache_user(fn):
    return memcache.memoize(
        key=lambda user, **_: f'{user.key.id()} {request.full_path}',
        expire=MEMOIZE_EXPIRATION,
        )(fn)


def non_none(seq):
    return [elem for elem in seq if elem is not None]


def auth(granary_source=False):
    """Requires a valid bearer token, resolves it to a :class:`models.User`.

    Passes the resolved user to the wrapped view function as a ``user`` kwarg.

    Args:
      * granary_source (bool): if true, generates a :class:`granary.source.Source`
        for the user and passes it as the ``source`` kwarg.
    """
    def decorator(fn):
        @require_oauth()
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not (user := current_token.get_user()):
                error('Account not found', status=401)
            logger.info(f'Logged in as {user.key.id()} for {request.url}')

            if not user.is_enabled(ActivityPub):
                error(f"{user.handle_or_id()} isn't bridged to the fediverse",
                      status=403)

            if granary_source:
                if not (source := current_token.granary_source()):
                    error(f"{user.LABEL} accounts not supported yet", status=501)
                kwargs['source'] = source

            return fn(*args, user=user, **kwargs)

        return wrapper

    return decorator


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
        'id': encode_id(user.key.id()),
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

    If :func:`prefetch_statuses` has run on ``obj``, uses the ``owner``,
    ``target``, and ``quoted`` it stashed on it, so that converting a whole page
    of objects doesn't need a datastore round trip per object. Otherwise loads
    ``obj``'s owner, reblog target, and quoted post, if any, individually.

    Returns None if ``obj`` can't be converted, eg its AS1 ``objectType``/``verb``
    isn't supported, or its account can't be fetched or converted.
    """
    if as1.object_type(obj.as1) not in as1.POST_TYPES | {'share'}:
        return None

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

    if hasattr(obj, 'owner'):
        # unlike load_owner, a prefetched owner is never None just because a
        # user hasn't been created yet; treat that as fully unresolved, instead
        # of falling back to whatever placeholder account from_as1 built
        status['account'] = to_account(obj.owner) if obj.owner else None
    elif owner := load_owner(obj):
        status['account'] = to_account(owner)

    if not status['account']:
        return None

    # TODO: if there's a repost loop, ie two share objects whose object fields
    # point to each other, this will recurse (loop) forever
    if status['reblog']:
        # try to hydrate the original post
        status['reblog'] = target_to_status(obj)
        if not status['reblog']:
            # reposts aren't renderable without their original post
            return None

    # TODO: if there's a quote loop, eg an object that quotes itself, this will
    # recurse (loop) forever
    if status['quote']:
        # try to hydrate the quoted post
        quoted = (getattr(obj, 'quoted', None)
                  or Object.get_by_id(as1.quoted_posts(obj.as1)[0]))

        if quoted and quoted.as1:
            if quoted_status := to_status(quoted):
                status['quote'] = {
                    'state': 'accepted',
                    'quoted_status': quoted_status,
                }

    return status


def target_to_status(obj):
    """Converts ``obj``'s object to a status.

    Uses the ``target`` stashed by :func:`prefetch_statuses`, if it's run on
    ``obj``, instead of loading it.

    Returns:
      dict: Mastodon API Status, or None if ``obj`` has no ``object`` or it's not
        in the datastore.
    """
    if not (target := getattr(obj, 'target', None)):
        if id := as1.get_id(obj.as1, 'object'):
            target = Object.get_by_id(id)

    if target and target.as1:
        return to_status(target)


def to_notification(obj):
    """Converts a :class:`models.Object` to a Mastodon ``Notification``.

    Uses the ``owner`` and ``target`` stashed by :func:`prefetch_statuses`, if
    it's run on ``obj``; see :func:`to_status`.

    Returns None if ``obj`` can't be converted, eg its account can't be fetched or
    converted.
    """
    type = AS1_TO_NOTIFICATION_TYPE.get(obj.as1.get('verb'), 'mention')

    notif = {
        'id': encode_id(obj.key.id()),
        'type': type,
        'created_at': (obj.as1.get('published')
                       or obj.created.replace(tzinfo=timezone.utc).isoformat()),
        'account': None,  # populated below
    }

    if type in ('mention', 'quote'):
        notif['status'] = to_status(obj)
        if notif['status']:
            notif['account'] = notif['status']['account']

    elif type in ('favourite', 'follow', 'reblog'):
        notif['status'] = target_to_status(obj)

        owner = obj.owner if hasattr(obj, 'owner') else load_owner(obj)
        if owner:
            notif['account'] = to_account(owner)

    if not notif['account']:
        return None

    return notif


def to_relationship(user, **values):
    return {
        'id': encode_id(user.key.id()),
        'following': False,
        'followed_by': False,
        'showing_reblogs': False,
        'blocking': False,
        'blocked_by': False,
        'domain_blocking': False,
        'endorsed': False,
        'muting': False,
        'muting_notifications': False,
        'notifying': False,
        'requested': False,
        'note': '',
        **values,
    }


def to_statuses(objects):
    """Converts objects to statuses, handling the ``only_media`` query param.

    Args:
      objects (sequence of :class:`models.Object`)

    Returns:
      list of dict: Mastodon API statuses
    """
    only_media = bool_param('only_media')
    return [s for s in non_none(to_status(obj) for obj in objects)
            if not (only_media and not s.get('media_attachments'))]


def prefetch_statuses(objs):
    """Prefetches the owners and reblog/favourite/follow targets of ``objects``.

    Batches the datastore gets for the whole list of objects into a small,
    fixed number of round trips, instead of :func:`to_status` and
    :func:`to_notification` each doing their own gets one object at a time.

    Stashes what it loads on each object in attributes: ``owner`` is its owning
    :class:`models.User`, or None; ``target`` is the :class:`models.Object`
    referenced by its AS1 ``object`` field, or None; ``quoted`` is the
    :class:`models.Object` it quotes, or None.

    Args:
      objs (sequence of :class:`models.Object`)
    """
    # de-dupe
    objs = list({obj.key: obj for obj in objs}.values())

    for obj in objs:
        # owner user
        if obj.users:
            obj.owner = obj.users[0].get_async()
        elif ((owner := as1.get_owner(obj.as1))
              and (proto := obj.owner_protocol(remote=False))
              and (id := ids.normalize_user_id(id=owner, proto=proto))):
            obj.owner = proto.get_by_id_async(id)
        else:
            obj.owner = None

        # target object
        obj.target = None
        if target := as1.get_id(obj.as1, 'object'):
            obj.target = Object.get_by_id_async(target)

        # quoted post
        obj.quoted = None
        if quoted := as1.quoted_posts(obj.as1):
            obj.quoted = Object.get_by_id_async(quoted[0])

    for obj in objs:
        if obj.owner:
            obj.owner = obj.owner.get_result()
        if obj.target:
            obj.target = obj.target.get_result()
        if obj.quoted:
            obj.quoted = obj.quoted.get_result()

    redirects = [(obj, obj.owner.use_instead.get_async()) for obj in objs
                 if obj.owner and obj.owner.use_instead]
    for obj, future in redirects:
        obj.owner = future.get_result()

    if nested := non_none([o.target for o in objs] + [o.quoted for o in objs]):
        prefetch_statuses(nested)


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
                                    allow_opt_out=True, resolve=True)
        except (AttributeError, RuntimeError, ValueError) as e:
            logger.info(e)


def load_account_id(id):
    """Loads a :class:`models.User` by their native id.

    This is the id we return in ``Account``s, from :func:`to_account`.

    Returns None if the id's protocol can't be determined, or if they're not in
    the datastore.
    """
    try:
        return models.load_user(decode_id(id), allow_opt_out=True)
    except (RuntimeError, ValueError) as e:
        logger.info(e)


def visible(obj):
    """Returns True if ``obj`` exists and should be visible in this API.

    Args:
      obj (models.Object or None)

    Returns:
      bool:
    """
    return bool(obj and obj.as1 and not obj.deleted and as1.is_public(obj.as1))


def load_object(id):
    obj = Object.get_by_id(decode_id(id))
    if not obj or not obj.as1:
        error('Status not found', status=404)
    return obj


def undo(user, source, activity_id, verb, object_id):
    """Undoes a follow or block, either natively or internally.

    Args:
      user (models.User)
      source (granary.source.Source)
      activity_id (str): id of the activity to undo
      verb (str): the activity's AS1 verb, eg ``follow``
      object_id (str): id of the activity's object, eg the followed user
    """
    if not UIProtocol.owns_id(activity_id):
        source.delete(activity_id)
        return

    # we created this activity ourselves, in the datastore
    id = f'ui:undo-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
    undo_as1 = {
        'objectType': 'activity',
        'verb': 'undo',
        'id': id,
        'actor': user.key.id(),
        'object': {
            'objectType': 'activity',
            'verb': verb,
            'id': activity_id,
            'actor': user.key.id(),
            'object': object_id,
        },
    }
    common.create_task(queue='receive', id=id, source_protocol='ui',
                       users=[user.key.urlsafe().decode()],
                       authed_as=user.key.id(), our_as1=undo_as1)


def load_owner(obj, remote=False):
    """Loads the :class:`models.User` that owns ``obj``, if any.

    Args:
      obj (models.Object)
      create (bool): whether to fetch the owner's actor over the network and
        store it as a new :class:`activitypub.ActivityPub` user in the datastore
        if necessary

    Returns None if ``obj`` has no owner, or if the owner can't be loaded, eg
    if their handle can't be resolved to a protocol.
    """
    if obj.users:
        return obj.users[0].get()

    if owner_id := as1.get_owner(obj.as1):
        try:
            return models.load_user(owner_id, create=remote, allow_opt_out=True)
        except RuntimeError:
            logger.info(f"Couldn't load owner {owner_id}", exc_info=True)

    return None


def limit():
    """Returns the limit query param, if it's between 1 and ``MAX_LIMIT``.

    ...otherwise returns ``DEFAULT_LIMIT``.

    Returns:
      int:
    """
    if limit := request.args.get('limit'):
        try:
            return min(max(int(limit), 1), MAX_LIMIT)
        except (ValueError, TypeError):
            pass

    return DEFAULT_LIMIT


def paginate(query):
    """Applies the ``max_id``, ``since_id``, and ``min_id`` query params.

    https://docs.joinmastodon.org/api/guidelines/#pagination

    Args:
      query (google.cloud.ndb.Query): on :class:`models.Object`

    Returns:
      google.cloud.ndb.Query: the query, ordered by ``Object.created``, descending
      except for ``min_id``, which returns the oldest posts newer than it
    """
    def obj_created(param):
        if id := request.args.get(param):
            if obj := Object.get_by_id(decode_id(id)):
                return obj.created

    order = -Object.created
    if max := obj_created('max_id'):
        query = query.filter(Object.created < max)
    if since := obj_created('since_id'):
        query = query.filter(Object.created > since)
    if min := obj_created('min_id'):
        query = query.filter(Object.created > min)
        order = Object.created

    return query.order(order)


def paginate_and_fetch(*filters):
    """Paginates a :meth:`models.Object` query and returns its results, newest first.

    Args:
      *filters: passed to :meth:`models.Object.query`

    Returns:
      list of :class:`models.Object`: newest first
    """
    query = paginate(Object.query(*filters))
    objects = query.fetch(limit())

    # min_id makes paginate sort ascending, to pick the oldest objects newer than
    # it, so flip back to newest first
    if not query.order_by[0].reverse:
        objects.reverse()

    return objects


def link_header(objects):
    """Returns a ``Link`` response header with ``next`` and ``prev`` page URLs.

    Only uses the newest and oldest objects, by ``created``, which is what
    :func:`paginate` sorts and filters on. Order doesn't matter.
    https://docs.joinmastodon.org/api/guidelines/#pagination

    Args:
      objects (sequence of :class:`models.Object`)

    Returns:
      dict: response headers, empty if ``objects`` is empty
    """
    if not objects:
        return {}

    newest = max(objects, key=lambda obj: obj.created)
    oldest = min(objects, key=lambda obj: obj.created)
    params = [(name, val) for name, vals in request.args.lists() for val in vals
              if name not in ('max_id', 'since_id', 'min_id')]
    next_url = util.add_query_params(
        request.base_url, params + [('max_id', encode_id(oldest.key.id()))])
    prev_url = util.add_query_params(
        request.base_url, params + [('min_id', encode_id(newest.key.id()))])

    return {
        'Link': f'<{next_url}>; rel="next", <{prev_url}>; rel="prev"',
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Expose-Headers
        'Access-Control-Expose-Headers': 'Link',
    }


#
# API endpoints
#

@app.before_request
def require_primary_domain():
    """Only serves the Mastodon API on PRIMARY_DOMAIN.

    Serving this API on multiple brid.gy subdomains would mean multiple ATProto OAuth
    client ids, and ATProto OAuth DPoP tokens are bound to their client id, and
    oauth-dropins doesn't support multiple client ids in the same project.

    /api/v1/instance is excluded since it's in activitypub.py.
    """
    if (not (DEBUG or LOCAL_SERVER)
            and request.path.startswith('/api/')
            and request.path != '/api/v1/instance'
            and request.host != PRIMARY_DOMAIN):
        return f"Bridgy Fed's Mastodon API is only served on https://{PRIMARY_DOMAIN}/", 404


@app.route('/api/<path:_>', methods=['OPTIONS'])
def cors_preflight_options(_):
    return 'OK', {
        **MODERN_HEADERS,
        'Cache-Control': 'public, max-age=31536000',  # 1y
    }


@app.errorhandler(HTTPException)
def json_error(e):
    """Renders API errors as JSON instead of HTML.

    Mastodon API clients deserialize every response as JSON, so an HTML error
    page makes them report an opaque parse error instead of showing ours.
    https://docs.joinmastodon.org/entities/Error/
    """
    if not request.path.startswith('/api/'):
        return handle_exception(e)

    # cors_preflight_options matches every /api/ path, if this endpoint only has
    # OPTIONS registered, it's not a real endpoint
    if isinstance(e, MethodNotAllowed) and e.valid_methods == ['OPTIONS']:
        e = NotFound("Sorry, Bridgy Fed doesn't support this.")

    headers = {name: val for name, val in e.get_headers()
               if name.lower() not in ('content-type', 'content-length')}
    return {
        'error': e.name.lower().replace(' ', '_'),
        'error_description': e.description,
    }, e.code, headers


@app.get('/health')
def health():
    return {'status': 'UP'}


@app.get('/api/v2/instance', provide_automatic_options=False)
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
            'statuses': {
                'max_characters': 500,
                'max_media_attachments': 8,
                'characters_reserved_per_url': 23,
            },
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
            'polls': {
                'max_options': 0,
                'max_characters_per_option': 0,
                'min_expiration': 0,
                'max_expiration': 0,
            },
            'translation': {
                'enabled': False,
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

@app.get('/api/v1/instance/extended_description', provide_automatic_options=False)
def instance_extended_description():
    return {
        'updated_at': util.now().isoformat(),
        'content': '<p>Bridges other networks to the fediverse. See <a href="https://fed.brid.gy/docs">the docs</a> for more.</p>',
    }


@app.get('/api/v1/instance/privacy_policy', provide_automatic_options=False)
def instance_privacy_policy():
    return {
        'updated_at': util.now().isoformat(),
        'content': '<p>See <a href="/docs#privacy">our privacy policy</a>.</p>',
    }


@app.get('/api/v1/instance/terms_of_service', provide_automatic_options=False)
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


@app.get('/api/v1/accounts/verify_credentials', provide_automatic_options=False)
@auth()
def verify_credentials(user):
    return to_account(user)


@app.get('/api/v1/preferences', provide_automatic_options=False)
@auth()
def preferences(user):
    # TODO
    return {
        'posting:default:visibility': 'public',
        'posting:default:sensitive': False,
        'posting:default:language': None,
        'reading:expand:media': 'default',
        'reading:expand:spoilers': False,
    }


@app.get('/api/v1/accounts/lookup', provide_automatic_options=False)
@auth()
@cache_global
def accounts_lookup(user):
    if user := load_user(get_required_param('acct')):
        return to_account(user)

    error('Not found', status=404)


@app.get('/api/v1/accounts/relationships', provide_automatic_options=False)
@auth()
# not cached since clients reread this immediately after following/unfollowing someone
def accounts_relationships(user):
    relationships = []

    others = []
    for id in request.args.getlist('id[]') + request.args.getlist('id'):
        if other := load_account_id(id):
            others.append(other)

    followings = [Follower.query(Follower.from_ == user.key,
                                 Follower.to == other.key,
                                 Follower.status == 'active'
                                 ).get_async(keys_only=True)
                  for other in others]
    followed_bys = [Follower.query(Follower.from_ == other.key,
                                   Follower.to == user.key,
                                   Follower.status == 'active'
                                   ).get_async(keys_only=True)
                    for other in others]

    for other, following, followed_by in zip(others, followings, followed_bys):
        relationships.append(to_relationship(
            other,
            following=bool(following.get_result()),
            followed_by=bool(followed_by.get_result())))

    return relationships


@app.post('/api/v1/accounts/<path:id>/<any(follow,block):verb>',
          provide_automatic_options=False)
@auth(granary_source=True)
def accounts_follow_or_block(user, source, id, verb):
    if not (target := load_account_id(id)):
        error('Account not found', status=404)

    activity_as1 = {
        'objectType': 'activity',
        'verb': verb,
        'actor': user.key.id(),
    }

    if target_id := target.get_copy(user):
        # the account is bridged to the user's protocol. write the activity
        # there, natively
        activity_as1['object'] = target_id
        result = source.create(activity_as1)
        if not result.content:
            error(result.error_plain or f"Couldn't {verb} this account", status=502)

    else:
        # not bridged to the user's protocol. write the activity to an
        # Object in the datastore
        id = f'ui:{verb}-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
        activity_as1.update({
            'id': id,
            'object': target.key.id(),
        })
        common.create_task(queue='receive', id=id, our_as1=activity_as1,
                           source_protocol='ui', users=[user.key.urlsafe().decode()],
                           authed_as=user.key.id())

    return to_relationship(target, **{f'{verb}ing': True})


@app.post('/api/v1/accounts/<path:id>/unfollow', provide_automatic_options=False)
@auth(granary_source=True)
def accounts_unfollow(user, source, id):
    if not (target := load_account_id(id)):
        error('Account not found', status=404)

    # TODO: if the follow hasn't been bridged back from the PDS to our datastore yet,
    # we won't find it here. look it up on the PDS directly as a fallback
    follower = Follower.query(Follower.from_ == user.key,
                              Follower.to == target.key,
                              Follower.status == 'active').get()
    if follower and follower.follow:
        undo(user, source, activity_id=follower.follow.id(), verb='follow',
             object_id=target.key.id())

    return to_relationship(target, following=False)


@app.post('/api/v1/accounts/<path:id>/unblock', provide_automatic_options=False)
@auth(granary_source=True)
def accounts_unblock(user, source, id):
    if not (target := load_account_id(id)):
        error('Account not found', status=404)

    # TODO: if the block hasn't been bridged back from the PDS to our datastore yet,
    # we won't find it here. look it up on the PDS directly as a fallback
    for obj in Object.query(Object.users == user.key, Object.type == 'block'):
        if as1.get_id(obj.as1, 'object') == target.key.id() and not obj.deleted:
            undo(user, source, activity_id=obj.key.id(), verb='block',
                 object_id=target.key.id())

    return to_relationship(target, blocking=False)


@app.get('/api/v1/follow_requests', provide_automatic_options=False)
@auth()
def follow_requests(user):
    # TODO
    return []


@app.get('/api/v1/accounts/<path:id>', provide_automatic_options=False)
@auth()
@cache_global
def accounts_get(user, id):
    if user := load_account_id(id):
        return to_account(user)

    error('Not found', status=404)


@app.get('/api/v1/accounts/<path:id>/statuses', provide_automatic_options=False)
@auth()
@cache_global
def accounts_statuses(user, id):
    # TODO: tagged
    if not (user := load_account_id(id)):
        error('Not found', status=404)

    if pinned := bool_param('pinned'):
        objects = []
        if user.obj and user.obj.as1:
            featured = as1.get_ids(as1.get_object(user.obj.as1, 'featured'), 'items')
            objects = ndb.get_multi(Object(id=id).key for id in featured)

    else:
        objects = paginate_and_fetch(Object.users == user.key,
                                     Object.type.IN(as1.POST_TYPES | set(['share'])))

    objects = [obj for obj in objects
               if visible(obj)
               and not (bool_param('exclude_replies') and obj.type == 'comment')
               and not (bool_param('exclude_reblogs') and obj.type == 'share')]
    prefetch_statuses(objects)

    statuses = to_statuses(objects)
    # pinned statuses aren't paginated
    headers = {} if pinned else link_header(objects)
    return statuses, headers


@app.get('/api/v1/accounts/<path:id>/followers', provide_automatic_options=False)
@auth()
@cache_global
def accounts_followers(user, id):
    if not (other := load_account_id(id)):
        error('Not found', status=404)

    followers, _, _ = Follower.fetch_page('followers', other)
    return [to_account(f.user) for f in followers]


@app.get('/api/v1/accounts/<path:id>/following', provide_automatic_options=False)
@auth()
@cache_global
def accounts_following(user, id):
    if not (other := load_account_id(id)):
        error('Not found', status=404)

    following, _, _ = Follower.fetch_page('following', other)
    return [to_account(f.user) for f in following]


@app.get('/api/v1/accounts/<path:id>/featured_tags', provide_automatic_options=False)
@auth()
def accounts_featured_tags(user, id):
    # TODO
    return []


@app.get('/api/v1/accounts/<path:id>/lists', provide_automatic_options=False)
@auth()
def accounts_lists(user, id):
    # TODO
    return []


@app.get('/api/v1/accounts/<path:id>/endorsements', provide_automatic_options=False)
@auth()
def accounts_endorsements(user, id):
    # TODO
    return []


@app.get('/api/v1/accounts/familiar_followers', provide_automatic_options=False)
@auth()
def accounts_familiar_followers(user):
    # TODO
    ids = request.args.getlist('id[]') + request.args.getlist('id')
    return [{'id': id, 'accounts': []} for id in ids]


@app.get('/api/v1/followed_tags', provide_automatic_options=False)
@auth()
def followed_tags(user):
    # TODO
    return []


@app.get('/api/v1/blocks', provide_automatic_options=False)
@auth()
def blocks(user):
    # TODO
    return []


@app.get('/api/v1/bookmarks', provide_automatic_options=False)
@auth()
def bookmarks(user):
    # TODO
    return []


@app.get('/api/v1/domain_blocks', provide_automatic_options=False)
@auth()
@cache_user
def domain_blocks_get(user):
    blocklists = ndb.get_multi(user.blocks)
    return [domain for list in blocklists for domain in list.domain_blocklist]


@app.get('/api/v1/favourites', provide_automatic_options=False)
@auth()
# not cached since clients reread this immediately after liking a post
def favourites(user):
    likes = Object.query(Object.users == user.key,
                         Object.type == 'like',
                        ).order(-Object.created
                        ).fetch(limit())
    ids = [as1.get_id(like.as1, 'object') for like in likes]
    objs = [obj for obj in ndb.get_multi(Object(id=id).key for id in ids if id)
            if obj and obj.as1]
    prefetch_statuses(objs)
    return to_statuses(objs)


@app.get('/api/v1/statuses', provide_automatic_options=False)
@auth()
@cache_global
def statuses_multiple(user):
    ids = [decode_id(id) for id in
           request.args.getlist('id[]') + request.args.getlist('id')]
    objs = [obj for obj in ndb.get_multi(Object(id=id).key for id in ids)
            if visible(obj)]
    prefetch_statuses(objs)
    return to_statuses(objs)


@app.get('/api/v1/statuses/<path:id>', provide_automatic_options=False)
@auth()
# not cached since clients reread this immediately after reposting
# (except we don't populate reblogged anyway yet)
def statuses_single(user, id):
    obj = load_object(id)
    if not (status := to_status(obj)):
        error('Status not found', status=404)
    return status


@app.post('/api/v1/statuses', provide_automatic_options=False)
@auth(granary_source=True)
def statuses_create(user, source):
    params = request.get_json(silent=True) or request.values
    if not (text := params.get('status')):
        error('Missing required parameter: status')

    # make AS1 note object
    # TODO: media_ids, poll, sensitive, spoiler_text, visibility, language
    reply_obj = None
    if in_reply_to_id := params.get('in_reply_to_id'):
        reply_obj = load_object(in_reply_to_id)

    note = {
        'objectType': 'comment' if in_reply_to_id else 'note',
        'author': user.key.id(),
        'content': text,
    }

    source_protocol = user.LABEL
    if reply_obj and not reply_obj.get_copy(user):
        # the original post isn't bridged to the user's protocol. write the reply
        # to an Object in the datastore
        source_protocol = 'ui'
        id = f'ui:comment-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
        note.update({
            'id': id,
            'inReplyTo': reply_obj.key.id(),
        })
        common.create_task(queue='receive', id=id, our_as1=note,
                           source_protocol='ui', users=[user.key.urlsafe().decode()],
                           authed_as=user.key.id())

    else:
        # create the post on the user's protocol, natively
        if reply_obj:
            note['inReplyTo'] = reply_obj.id_as(user)

        result = source.create(note)
        if not result.content:
            error(result.error_plain or "Couldn't create this status", status=502)

        # construct response status
        id = result.content['id']
        note['id'] = id
        if reply_obj:
            note['inReplyTo'] = reply_obj.key.id()

    obj = Object(id=id, source_protocol=source_protocol, users=[user.key],
                 our_as1=note)
    obj.owner = user
    return to_status(obj)


@app.put('/api/v1/statuses/<path:id>', provide_automatic_options=False)
@auth(granary_source=True)
def statuses_update(user, source, id):
    if not (text := get_required_param('status')):
        error('Missing required parameter: status')

    obj = load_object(id)

    if UIProtocol.owns_id(obj.key.id()):
        # we created this status ourselves, in the datastore
        update_id = f'ui:update-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
        update_as1 = {
            'objectType': 'activity',
            'verb': 'update',
            'id': update_id,
            'actor': user.key.id(),
            'object': {**obj.as1, 'content': text},
        }
        common.create_task(queue='receive', id=update_id, source_protocol='ui',
                           users=[user.key.urlsafe().decode()],
                           authed_as=user.key.id(), our_as1=update_as1)

    else:
        # TODO: media_ids, poll, sensitive, spoiler_text
        note = {
            'objectType': 'note',
            'id': obj.id_as(user),
            'author': user.key.id(),
            'content': text,
            'inReplyTo': as1.get_id(obj.as1, 'inReplyTo'),
            'published': obj.as1.get('published'),
        }
        result = source.update(note)
        if not result.content:
            error(result.error_plain or "Couldn't update this status", status=502)

    obj.our_as1 = {**obj.as1, 'content': text}
    return to_status(obj)


@app.delete('/api/v1/statuses/<path:id>', provide_automatic_options=False)
@auth(granary_source=True)
def statuses_delete(user, source, id):
    obj = load_object(id)

    if UIProtocol.owns_id(obj.key.id()):
        # we created this status ourselves, in the datastore
        id = f'ui:delete-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
        common.create_task(queue='receive', id=id, source_protocol='ui',
                           users=[user.key.urlsafe().decode()],
                           authed_as=user.key.id(), our_as1={
                               'objectType': 'activity',
                               'verb': 'delete',
                               'id': id,
                               'object': obj.key.id(),
                               'actor': user.key.id(),
                           })

    else:
        source.delete(obj.id_as(user))

    return to_status(obj)


@app.post('/api/v1/statuses/<path:id>/<any(favourite,reblog):verb>',
          provide_automatic_options=False)
@auth(granary_source=True)
def statuses_favourite_or_reblog(user, source, id, verb):
    obj = load_object(id)

    verb = 'like' if verb == 'favourite' else 'share'
    activity_as1 = {
        'objectType': 'activity',
        'verb': verb,
        'actor': user.key.id(),
    }

    if obj.get_copy(user):
        # original post is bridged to the user's protocol. write the activity
        # there, natively
        activity_as1['object'] = obj.id_as(user)
        result = source.create(activity_as1)
        if not result.content:
            error(result.error_plain or f"Couldn't {verb} this status", status=502)

    else:
        # not bridged to the user's protocol. write the activity to an
        # Object in the datastore
        id = f'ui:{verb}-{user.LABEL}-{user.handle}-{util.now().isoformat()}'
        activity_as1.update({
            'id': id,
            'object': obj.key.id(),
        })
        common.create_task(queue='receive', id=id, our_as1=activity_as1,
                           source_protocol='ui', users=[user.key.urlsafe().decode()],
                           authed_as=user.key.id())

    status = to_status(obj) or {}
    status['favourited' if verb == 'like' else 'reblogged'] = True
    return status


@app.post('/api/v1/statuses/<path:id>/<any(unfavourite,unreblog):verb>',
          provide_automatic_options=False)
@auth(granary_source=True)
def statuses_unfavourite_or_unreblog(user, source, id, verb):
    orig_obj = load_object(id)

    # TODO: optimize
    #
    # TODO: if the like/repost hasn't been bridged back from the PDS to our datastore
    # yet, we won't find it here. look it up on the PDS directly as a fallback
    type = 'like' if verb == 'unfavourite' else 'share'
    for obj in Object.query(Object.users == user.key, Object.type == type):
        if as1.get_id(obj.as1, 'object') == orig_obj.key.id() and not obj.deleted:
            undo(user, source, activity_id=obj.key.id(), verb=type,
                 object_id=orig_obj.key.id())

    status = to_status(orig_obj) or {}
    status['favourited' if verb == 'unfavourite' else 'reblogged'] = False
    return status


@app.get('/api/v1/statuses/<path:id>/context', provide_automatic_options=False)
@auth()
@cache_global
def statuses_context(user, id):
    obj = load_object(id)

    ancestors = []
    parent_id = as1.get_object(obj.as1, 'inReplyTo').get('id')

    # TODO: if there's an inReplyTo loop, ie two objects with inReplyTos that
    # point to each other, and to_status below fails and returns None on them, this
    # will loop forever
    while (parent_id and len(ancestors) < MAX_ANCESTORS
           and (parent := Object.get_by_id(parent_id)) and parent.as1):
        if parent_status := to_status(parent):
            ancestors.insert(0, parent_status)
        # TODO: convert to native protocol?
        parent_id = as1.get_id(parent.as1, 'inReplyTo')

    # walk down the reply tree breadth first
    #
    # TODO: filter to objects owned by users who are either fediverse native or
    # bridged there
    #
    # TODO: consider adding an Object.in_reply_to_root computed property. then
    # this would all collapse to a single query on that
    descendants = []
    frontier = [obj.key]
    for _ in range(MAX_DESCENDANT_DEPTH):
        replies = Object.query(Object.in_reply_to.IN(frontier)
                               ).fetch(MAX_DESCENDANTS - len(descendants))
        frontier = []
        for reply in replies:
            if visible(reply) and (status := to_status(reply)):
                descendants.append(status)
                frontier.append(reply.key)

        if not frontier or len(descendants) >= MAX_DESCENDANTS:
            break

    return {
        'ancestors': ancestors,
        'descendants': descendants,
    }


@app.get('/api/v1/statuses/<path:id>/favourited_by', provide_automatic_options=False)
@auth()
def statuses_favourited_by(user, id):
    load_object(id)
    # likes aren't indexed by target, so we can't look them up efficiently
    return []


@app.get('/api/v1/statuses/<path:id>/reblogged_by', provide_automatic_options=False)
@auth()
def statuses_reblogged_by(user, id):
    load_object(id)
    # reposts aren't indexed by target, so we can't look them up efficiently
    return []


@app.get('/api/v1/timelines/home', provide_automatic_options=False)
@auth()
@cache_user
def timelines_home(user):
    # user keys
    followees = [f.to for f in Follower.query(Follower.from_ == user.key,
                                              Follower.status == 'active')]
    if not followees:
        return []

    # query each followee separately, since datastore can't do a disjunction this
    # big, then merge. we only project created here so that we don't load all
    # limit() objects per followee just to throw most of them away.
    num = limit()
    queries = [paginate(Object.query(Object.users == followee,
                                     Object.type.IN(('note', 'article', 'share'))))
               for followee in followees]
    futures = [query.fetch_async(num, projection=[Object.created])
               for query in queries]

    # min_id makes paginate sort ascending, to pick the oldest posts newer than
    # it, so sort the same way here, then reverse, since we return newest first
    descending = queries[0].order_by[0].reverse
    merged = sorted((obj for future in futures for obj in future.get_result()),
                    key=lambda obj: obj.created, reverse=descending)
    # dict.fromkeys so that we can de-dupe by key
    keys = list(dict.fromkeys(obj.key for obj in merged))[:num]
    if not descending:
        keys.reverse()

    objects = [obj for obj in ndb.get_multi(keys) if visible(obj)]
    prefetch_statuses(objects)
    return to_statuses(objects), link_header(objects)


@app.get('/api/v1/timelines/public', provide_automatic_options=False)
@auth()
@cache_global
def timelines_public(user):
    local = bool_param('local')
    remote = bool_param('remote')

    objs = paginate_and_fetch(Object.type.IN(('note', 'article', 'share')))
    objects = [obj for obj in objs
               if visible(obj)
               # local means from the user's network
               and not (local and obj.source_protocol != user.LABEL)
               # remote means native from the fediverse, ie not from Bridgy Fed
               and not (remote and obj.source_protocol != 'activitypub')]
    prefetch_statuses(objects)
    return to_statuses(objects), link_header(objects)


@app.get('/api/v1/timelines/tag/<hashtag>', provide_automatic_options=False)
@auth()
def timelines_tag(user, hashtag):
    return []


@app.get('/api/v1/conversations', provide_automatic_options=False)
@auth()
def conversations(user):
    # TODO
    return []


@app.get('/api/v1/lists', provide_automatic_options=False)
@auth()
def lists(user):
    # TODO
    return []


@app.get('/api/v1/lists/<path:id>', provide_automatic_options=False)
@auth()
def lists_get(user, id):
    # TODO
    error('List not found', status=404)


@app.get('/api/v1/lists/<path:id>/accounts', provide_automatic_options=False)
@auth()
def lists_accounts(user, id):
    # TODO
    error('List not found', status=404)


@app.get('/api/v1/markers', provide_automatic_options=False)
@auth()
def markers(user):
    # TODO
    return {}


@app.get('/api/v1/notifications', provide_automatic_options=False)
@auth()
@cache_user
def notifications_list(user):
    # TODO: unbridged notifs
    objs = paginate_and_fetch(Object.notify == user.key)
    objects = [obj for obj in objs if visible(obj)]
    prefetch_statuses(objects)
    return (non_none([to_notification(obj) for obj in objects]),
            link_header(objects))


@app.get('/api/v1/notifications/<path:id>', provide_automatic_options=False)
@auth()
@cache_user
def notifications_get(user, id):
    obj = Object.get_by_id(decode_id(id))
    if visible(obj) and user.key in obj.notify:
        if notif := to_notification(obj):
            return notif

    error('Notification not found', status=404)


@app.get('/api/v1/notifications/unread_count', provide_automatic_options=False)
@auth()
@cache_user
def notifications_unread_count(user):
    # we don't currently track read vs unread
    return {'count': 0}


@app.get('/api/v2/notifications', provide_automatic_options=False)
@auth()
@cache_user
def grouped_notifications_list(user):
    """https://docs.joinmastodon.org/methods/grouped_notifications/#get-grouped"""
    # TODO: unbridged notifs
    query = paginate(Object.query(Object.notify == user.key))
    objects = [obj for obj in query.fetch(GROUPED_NOTIF_OBJECT_FETCHES)
               if visible(obj)]

    # min_id makes paginate sort ascending, to pick the oldest notifications newer
    # than it, so flip back to newest first, which the grouping below depends on
    ascending = not query.order_by[0].reverse
    if ascending:
        objects.reverse()

    prefetch_statuses(objects)

    grouped_types = request.args.getlist('grouped_types[]') or GROUPED_NOTIF_TYPES
    groups = {}    # maps type to NotificationGroup
    accounts = {}  # maps encoded id to Account
    statuses = {}  # maps encoded id to Status
    group_objs = {}  # maps group key to its notification Objects

    for obj in objects:
        if not (notif := to_notification(obj)):
            continue

        type = notif['type']
        account = notif['account']
        status = notif.get('status')

        if type not in grouped_types:
            key = f'ungrouped-{notif["id"]}'
        elif status:
            key = f'{type}-{status["id"]}'
        else:
            key = type

        accounts.setdefault(account['id'], account)
        if status:
            statuses.setdefault(status['id'], status)
        # objects are newest first, so the last one for each group is its oldest
        group_objs.setdefault(key, []).append(obj)

        if not (group := groups.get(key)):
            groups[key] = {
                'group_key': key,
                'type': type,
                'notifications_count': 1,
                'most_recent_notification_id': notif['id'],
                'page_max_id': notif['id'],
                'page_min_id': notif['id'],
                'latest_page_notification_at': notif['created_at'],
                'sample_account_ids': [account['id']],
                'status_id': status['id'] if status else None,
            }
            continue

        group['notifications_count'] += 1
        group['page_min_id'] = notif['id']
        if (account['id'] not in group['sample_account_ids']
                and len(group['sample_account_ids']) < GROUPED_NOTIF_SAMPLE_ACCOUNTS):
            group['sample_account_ids'].append(account['id'])

    # limit counts groups, not notifications. min_id asks for the oldest
    # notifications newer than it, so keep the oldest groups for it.
    num = limit()
    kept = list(groups.values())
    kept = kept[-num:] if ascending else kept[:num]

    account_ids = dict.fromkeys(id for group in kept
                                for id in group['sample_account_ids'])
    status_ids = dict.fromkeys(group['status_id'] for group in kept
                               if group['status_id'])

    resp = {
        'accounts': [accounts[id] for id in account_ids],
        'statuses': [statuses[id] for id in status_ids],
        'notification_groups': kept,
    }

    headers = link_header([obj for group in kept
                           for obj in group_objs[group['group_key']]])
    return resp, headers

    # TODO:
    # account_id
    # supported_types


@app.get('/api/v2/search', provide_automatic_options=False)
@auth()
@cache_global
def search(user):
    resp = {
        'accounts': [],
        'statuses': [],
        'hashtags': [],
    }

    q = unquote(get_required_param('q').strip())
    resolve = bool_param('resolve')
    type = request.args.get('type')

    if not type or type == 'accounts':
        if user := load_user(q, resolve=resolve):
            if acct := to_account(user):
                resp['accounts'] = [acct]

    if not type or type == 'statuses':
        # Phanpy does an odd thing to load individual statuses: it searches
        # for them with the format '[domain]/s/[id]'. no clue why yet
        for domain in DOMAINS:
            q = q.removeprefix(f'{domain}/s/')

        if obj := Object.get_by_id(decode_id(q)):
            if status := to_status(obj):
                resp['statuses'] = [status]
        elif resolve and ActivityPub.owns_id(q) is not False:
            if obj := ActivityPub.load(q, remote=True, raise_=False):
                obj.owner = load_owner(obj, remote=True)
                if status := to_status(obj):
                    resp['statuses'] = [status]

    return resp
