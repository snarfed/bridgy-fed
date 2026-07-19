"""Serves the Mastodon client API, backed by Bridgy Fed users and objects."""
from datetime import timezone
import functools
import logging

from authlib.integrations.flask_oauth2.resource_protector import current_token
from webutil import util
from webutil.flask_util import error

from activitypub import ActivityPub
from flask_app import app
from mastodon_oauth import require_oauth

logger = logging.getLogger(__name__)


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


@app.get('/api/v1/accounts/verify_credentials')
@auth
def verify_credentials(user):
    # TODO: move to granary.mastodon
    obj_as1 = user.obj.as1 if user.obj and user.obj.as1 else {}
    image = util.get_url(obj_as1, 'image')
    return {
        'id': user.key.id(),
        'uri': user.id_as(ActivityPub),
        'username': user.handle,
        'acct': user.handle_as(ActivityPub),
        'display_name': user.name(),
        'url': user.web_url(),
        'avatar': image,
        'avatar_static': image,
        'header': '',
        'header_static': '',
        'note': obj_as1.get('summary') or '',
        'locked': False,
        'bot': False,
        'created_at': (obj_as1.get('published')
                       or user.created.replace(tzinfo=timezone.utc).isoformat()),
        'followers_count': 0,
        'following_count': 0,
        'statuses_count': 0,
    }


@app.get('/api/v1/accounts/lookup')
@auth
def accounts_lookup(user):
    return {}


@app.get('/api/v1/accounts/relationships')
@auth
def accounts_relationships(user):
    return []


@app.get('/api/v1/accounts/<id>')
@auth
def accounts_get(user, id):
    return {}


@app.get('/api/v1/accounts/<id>/statuses')
@auth
def accounts_statuses(user, id):
    return []


@app.get('/api/v1/accounts/<id>/followers')
@auth
def accounts_followers(user, id):
    return []


@app.get('/api/v1/accounts/<id>/following')
@auth
def accounts_following(user, id):
    return []


@app.get('/api/v1/blocks')
@auth
def blocks(user):
    return []


@app.get('/api/v1/favourites')
@auth
def favourites(user):
    return []


@app.get('/api/v1/statuses/<id>')
@auth
def statuses_get(user, id):
    return {}


@app.get('/api/v1/statuses/<id>/context')
@auth
def statuses_context(user, id):
    return {
        'ancestors': [],
        'descendants': [],
    }


@app.get('/api/v1/statuses/<id>/favourited_by')
@auth
def statuses_favourited_by(user, id):
    return []


@app.get('/api/v1/statuses/<id>/reblogged_by')
@auth
def statuses_reblogged_by(user, id):
    return []


@app.get('/api/v1/timelines/public')
@auth
def timelines_public(user):
    return []


@app.get('/api/v1/timelines/tag/<hashtag>')
@auth
def timelines_tag(user, hashtag):
    return []


@app.get('/api/v2/search')
@auth
def search(user):
    return {
        'accounts': [],
        'statuses': [],
        'hashtags': [],
    }
