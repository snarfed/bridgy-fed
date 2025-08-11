"""UI pages."""
from functools import wraps
import html
import itertools
import logging
import re
import time

from flask import request
from google.cloud.ndb import tasklets
from google.cloud.ndb.key import Key
from google.cloud.ndb.query import OR
from google.cloud.ndb.model import get_multi, Model
from granary import as1, as2, atom, microformats2, rss
import oauth_dropins
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import (
    canonicalize_request_domain,
    error,
    flash,
    get_flashed_messages,
    get_required_param,
    Found,
    MovedPermanently,
)
from oauth_dropins.webutil.util import json_loads, json_dumps
import requests
import werkzeug.exceptions
from werkzeug.exceptions import NotFound

import activitypub
from activitypub import ActivityPub
import atproto
from atproto import ATProto, BlueskyOAuthStart
import common
from common import (
    CACHE_CONTROL,
    DOMAIN_RE,
    ErrorButDoNotRetryTask,
    PROTOCOL_DOMAINS,
    render_template,
)
from flask_app import app
from flask import redirect, session
import ids
import memcache
import models
from models import (
    fetch_objects,
    fetch_page,
    Follower,
    Object,
    PAGE_SIZE,
    PROTOCOLS,
    USER_STATUS_DESCRIPTIONS,
)
from nostr import Nostr
from protocol import Protocol
from web import Web
import webfinger

logger = logging.getLogger(__name__)

BLOG_REDIRECT_DOMAINS = (
    'snarfed.org',
    # would be nice to do this! but we're currently on their default theme, which
    # doesn't have microformats:
    # https://indieweb.org/Ghost#Rejected_microformats2_markup_in_default_theme
    # ...also it's usually nicer to write custom microblog posts, instead of posting
    # the blog post itself, which will usually get rendered as just the title and link
    # 'blog.anew.social',
)

TEMPLATE_VARS = {
    'ActivityPub': ActivityPub,
    'as1': as1,
    'as2': as2,
    'ATProto': ATProto,
    'ids': ids,
    'logs': logs,
    'Nostr': Nostr,
    'PROTOCOLS': PROTOCOLS,
    'Web': Web,
}

# precompute this because we get a ton of requests for non-existing users
# from weird open redirect referrers:
# https://github.com/snarfed/bridgy-fed/issues/422
with app.test_request_context('/'):
    USER_NOT_FOUND_HTML = render_template('user_not_found.html', **TEMPLATE_VARS)


def load_user(protocol, id):
    """Loads and returns the current request's user.

    Args:
      protocol (str):
      id (str):

    Returns:
      models.User:

    Raises:
      :class:`werkzeug.exceptions.HTTPException` on error or redirect
    """
    assert id

    if id in PROTOCOL_DOMAINS:
        error(f'{protocol} user {id} not found', status=404)

    cls = PROTOCOLS[protocol]

    if cls.ABBREV == 'ap' and not id.startswith('@'):
        id = '@' + id
    elif cls.ABBREV == 'bsky':
        id = id.removeprefix('@')

    filters = [cls.key == cls(id=id).key]
    if cls.ABBREV != 'web':
        # also query by handle, except for web. Web.handle is custom username, which
        # isn't unique
        filters.append(cls.handle == id)

    redirect_user = None
    for user in cls.query(OR(*filters)):
        if user.use_instead:
            if not (user := user.use_instead.get()):
                continue

        if id not in (user.key.id(), user.handle):
            # keep looking for an exact match. if we don't find one, we'll redirect
            # to this one later
            redirect_user = user
            continue
        elif not user.status and (user.enabled_protocols
                                  or user.DEFAULT_SERVE_USER_PAGES):
            assert not user.use_instead
            return user

    if redirect_user:
        error('', status=302, location=user.user_page_path())

    # TODO: switch back to USER_NOT_FOUND_HTML
    # not easy via exception/abort because this uses Werkzeug's built in
    # NotFound exception subclass, and we'd need to make it implement
    # get_body to return arbitrary HTML.
    error(f'{protocol} user {id} not found', status=404)


def require_login(fn):
    """Decorator that requires and loads the current request's logged in user.

    Passes the userin the ``user`` kwarg, as a :class:`models.User`.

    HTTP POST params:
      key (str): url-safe ndb key

    Raises:
      :class:`werkzeug.exceptions.HTTPException` on error or redirect
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = Key(urlsafe=get_required_param('key'))
        if key not in [login_to_user_key(l) for l in get_logins()]:
            logger.warning(f'not logged in for {key}')
            raise Found(location='/login')
        elif not (user := key.get()):
            raise Found(location='/login')

        return fn(*args, user=user, **kwargs)

    return wrapper


def get_logins():
    """Returns the user's current logged in sessions:

    Returns:
      list of :class:`oauth_dropins.models.BaseAuth`
    """
    logins = [l for l in get_multi(oauth_dropins.get_logins()) if l]
    return sorted(logins, key=lambda l: (l.key.kind(), l.user_display_name()))


def login_to_user_key(login):
    """"Converts an oauth-dropins auth entity to a :model:`User` key.

    Args:
      login (oauth_dropins.models.BaseAuth)

    Returns:
      ndb.key.Key:
    """
    match login.site_name():
        case 'Bluesky':
            return ATProto(id=login.key.id()).key
        case 'Mastodon':
            if login.user_json and (id := json_loads(login.user_json).get('uri')):
                return ActivityPub(id=id).key
            logger.warning(f'Mastodon auth entity {login.key.id()} has no user_json or uri')
            return None
        case 'Pixelfed':
            user, server = login.key.id().strip('@').split('@')
            return ActivityPub(id=f'https://{server}/users/{user}').key
        case 'Threads':
            username = json_loads(login.user_json).get('username')
            handle = f'@{username}@threads.net'
            if user := ActivityPub.query(ActivityPub.handle == handle).get():
                return user.key
            if not (actor_id := webfinger.fetch_actor_url(handle)):
                for msg in get_flashed_messages:
                    if 'HTTP 404' in msg:
                        flash('You need to <a href="https://help.instagram.com/169559812696339">turn on fediverse sharing</a> first.', escape=False)
                return None
            return ActivityPub(id=actor_id).key
        case _:
            assert False, repr(login)


def render(template, **vars):
    """Renders a Jinja2 template and adds our standard template variables.

    Args:
      template (str): file name
    """
    return render_template(template, **TEMPLATE_VARS, logins=get_logins(), **vars)


@app.route('/')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def front_page():
    """View for the front page."""
    return render('index.html')


@app.route('/docs')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def docs():
    """View for the docs page."""
    return render('docs.html')


@app.route('/login')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def login():
    """View for the front page."""
    return render('login.html')


@app.post('/logout')
def logout():
    """Logs the user out of all current login sessions."""
    oauth_dropins.logout()
    flash(f"OK, you're now logged out.")
    return redirect('/', code=302)


@app.route('/settings')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def settings():
    """User settings page. Requires logged in session."""
    auth_entity = request.args.get('auth_entity')
    logged_in_as = Key(urlsafe=auth_entity) if auth_entity else None

    def site_logo(login):
        return f'/oauth_dropins_static/{login.site_name().lower()}_icon.png'

    users = []
    logins_and_user_keys = []
    for login in get_logins():
        if user_key := login_to_user_key(login):
            if login.key == logged_in_as:
                cls = Model._lookup_model(user_key.kind())
                user = cls.get_or_create(id=user_key.id(), allow_opt_out=True,
                                         reload=True)
                user.logo = site_logo(login)
                users.append(user)
            else:
                logins_and_user_keys.append((login, user_key))

    loaded = get_multi(key for _, key in logins_and_user_keys)
    for (login, _), user in zip(logins_and_user_keys, loaded):
        if user:
            user.logo = site_logo(login)
            users.append(user)

    if not users:
        return redirect('/login', code=302)

    return render(
        'settings.html',
        **locals(),
        USER_STATUS_DESCRIPTIONS=USER_STATUS_DESCRIPTIONS,
    )


@app.post('/settings/enable')
@require_login
def enable(user=None):
    """Enables bridging for a given account.

    Args:
      user (models.User)
    """
    enabled = []

    for proto in set(PROTOCOLS.values()):
        if (proto and not isinstance(user, proto)
                and proto.LABEL not in ('ui', 'web')
                and not user.is_enabled(proto)):
            try:
                user.enable_protocol(proto)
            except ErrorButDoNotRetryTask as e:
                msg = str(e)
                if resp := e.get_response():
                    if resp.is_json:
                        msg = resp.json['error']
                flash(f"Couldn't enable bridging to {proto.PHRASE}: {msg}")
                return redirect('/settings', code=302)

            proto.bot_follow(user)
            enabled.append(proto)

    if enabled:
        flash(f'Now bridging {user.handle_or_id()} to {",".join(p.PHRASE for p in enabled)}.')
    else:
        flash(f'{user.handle_or_id()} is already bridging.')

    return redirect('/settings', code=302)


@app.post('/settings/disable')
@require_login
def disable(user=None):
    """Disables bridging for a given account.

    Args:
      user (models.User)
    """
    if not user.enabled_protocols:
        flash(f'{user.handle_or_id()} is not currently bridging.')
        return redirect('/settings', code=302)

    enabled = list(user.enabled_protocols)
    for proto in user.enabled_protocols:
        user.delete(PROTOCOLS[proto])
        user.disable_protocol(PROTOCOLS[proto])

    flash(f'Disabled bridging {user.handle_or_id()} to {",".join(PROTOCOLS[p].PHRASE for p in enabled)}.')
    return redirect('/settings', code=302)


@app.post('/settings/set-username')
@require_login
def set_username(user=None):
    """Enables bridging for a given account.

    Args:
      user (models.User)

    Query params:
      protocol (str)
      username (str)
    """
    proto = PROTOCOLS[flask_util.get_required_param('protocol')]
    username = flask_util.get_required_param('username')

    try:
        proto.set_username(user, username)
        flash(f"Setting username on {proto.PHRASE} to {username}...")
    except NotImplementedError:
        flash(f"Custom usernames aren't supported on {proto.PHRASE}.")
    except (ValueError, RuntimeError) as e:
        flash(f"Couldn't set username on {proto.PHRASE} to {username}: {e}")

    return redirect('/settings', code=302)


@app.post('/settings/toggle-notifs')
@require_login
def toggle_notifs(user=None):
    """Toggles DM notifications for a given account.

    Args:
      user (models.User)
    """
    if user.send_notifs == 'all':
        user.send_notifs = 'none'
        verb = 'disabled'
    else:
        user.send_notifs = 'all'
        verb = 'enabled'

    user.put()

    flash(f'DM notifications {verb} for {user.handle_or_id()}.')
    return redirect('/settings', code=302)


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>')
# WARNING: this overrides the /ap/... actor URL route in activitypub.py, *only*
# for handles with leading @ character. be careful when changing this route!
@app.get(f'/ap/@<id>', defaults={'protocol': 'ap'})
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def profile(protocol, id):
    user = load_user(protocol, id)
    query = Object.query(Object.users == user.key)
    objects, before, after = fetch_objects(query, by=Object.updated, user=user)
    num_followers, num_following = user.count_followers()
    return render('profile.html', **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/home')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def home(protocol, id):
    user = load_user(protocol, id)
    query = Object.query(Object.feed == user.key)
    objects, before, after = fetch_objects(query, by=Object.created, user=user)

    # this calls Object.actor_link serially for each object, which loads the
    # actor from the datastore if necessary. TODO: parallelize those fetches
    return render('home.html', **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/notifications')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def notifications(protocol, id):
    user = load_user(protocol, id)

    query = Object.query(Object.notify == user.key)
    objects, before, after = fetch_objects(query, by=Object.updated, user=user)

    format = request.args.get('format')
    if format:
        return serve_feed(objects=objects, format=format, as_snippets=True,
                          user=user, title=f'Bridgy Fed notifications for {id}',
                          quiet=request.args.get('quiet'))

    # notifications tab UI page
    return render('notifications.html', **locals())


@app.get(f'/user-page')
@flask_util.headers(CACHE_CONTROL)
def find_user_page_form():
    return render('find_user_page.html')


@app.post(f'/user-page')
def find_user_page():
    id = request.form['id']

    proto = Protocol.for_id(id)

    resolved_id = None
    if not proto:
        proto, resolved_id = Protocol.for_handle(id)
        if not proto:
            flash(f"Couldn't determine network for {id}.")
            return render('find_user_page.html'), 404

    try:
        user = load_user(proto.LABEL, resolved_id or id)
    except NotFound:
        flash(f"User {id} on {proto.PHRASE} isn't signed up.")
        return render('find_user_page.html'), 404

    return redirect(user.user_page_path(), code=302)


@app.post(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/update-profile')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def update_profile(protocol, id):
    user = load_user(protocol, id)
    link = f'<a href="{user.web_url()}">{user.handle_or_id()}</a>'

    try:
        user.reload_profile()
    except (requests.RequestException, werkzeug.exceptions.HTTPException) as e:
        _, msg = util.interpret_http_exception(e)
        flash(f"Couldn't update profile for {link}: {msg}", escape=False)
        return redirect(user.user_page_path(), code=302)

    if not user.obj:
        flash(f"Couldn't update profile for {link}", escape=False)
        return redirect(user.user_page_path(), code=302)

    common.create_task(queue='receive', obj_id=user.obj_key.id(),
                       authed_as=user.key.id())
    flash(f'Updating profile from {link}...', escape=False)

    if user.LABEL == 'web':
        if user.status:
            logger.info(f'Disabling web user {user.key.id()}')
            user.delete()
        else:
            for label in list(user.DEFAULT_ENABLED_PROTOCOLS) + user.enabled_protocols:
                try:
                    PROTOCOLS[label].set_username(user, id)
                except (AssertionError, ValueError, RuntimeError, NotImplementedError):
                    pass

    return redirect(user.user_page_path(), code=302)


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/<any(followers,following):collection>')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def followers_or_following(protocol, id, collection):
    user = load_user(protocol, id)
    id = user.key.id()
    handle = user.handle

    followers, before, after = Follower.fetch_page(collection, user)
    num_followers, num_following = user.count_followers()

    # followers on protocols where we're not currently bridged shouldn't count.
    # ideally we'd remove all of them from the count, but we don't currently have a
    # good (efficient) way to include that in the query in count_followers(), so for
    # now, just revise the follower count down for the ones we see in the page that
    # we've fetched and will display.
    #
    # https://github.com/snarfed/bridgy-fed/issues/1966#issuecomment-2985666899
    num_followers = min(num_followers, len(followers))

    return render(
        f'{collection}.html',
        address=request.args.get('address'),
        follow_url=request.values.get('url'),
        **locals(),
    )


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/feed')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def feed(protocol, id):
    user = load_user(protocol, id)
    query = Object.query(Object.feed == user.key)
    objects, _, _ = fetch_objects(query, by=Object.created, user=user)
    return serve_feed(objects=objects, format=request.args.get('format', 'html'),
                      user=user, title=f'Bridgy Fed feed for {id}')


def serve_feed(*, objects, format, user, title, as_snippets=False, quiet=False):
    """Generates a feed based on :class:`Object` s.

    Args:
      objects (sequence of models.Object)
      format (str): ``html``, ``atom``, or ``rss``
      user (models.User)
      title (str)
      as_snippets (bool): if True, render short snippets for objects instead of
        full contents
      quiet (bool): if True, exclude follows, unfollows, likes, and reposts

    Returns:
      str or (str, dict) tuple: Flask response
    """
    if format not in ('html', 'atom', 'rss'):
        error(f'format {format} not supported; expected html, atom, or rss')

    objects = [obj for obj in objects if not obj.deleted]
    if quiet:
        objects = [obj for obj in objects if obj.type not in
                   ('delete', 'follow', 'stop-following', 'like', 'share',
                    'undo', 'update')]

    if as_snippets:
        activities = [{
            'objectType': 'note',
            'id': obj.key.id(),
            'content': f'{obj.actor_link(image=False, user=user)} {obj.phrase} {obj.content}',
            'updated': obj.updated.isoformat(),
            'url': as1.get_url(obj.as1) or as1.get_url(as1.get_object(obj.as1)),
        } for obj in objects]
    else:
        activities = [obj.as1 for obj in objects]

    # hydrate authors, actors, objects from stored Objects
    futures = []
    for a in activities:
        futures.extend(models.hydrate(a))
    tasklets.wait_all(futures)

    actor = (user.obj.as1 if user.obj and user.obj.as1
             else {'displayName': user.handle, 'url': user.web_url()})

    # TODO: inject/merge common.pretty_link into microformats2.render_content
    # (specifically into hcard_to_html) somehow to convert Mastodon URLs to @-@
    # syntax. maybe a fediverse kwarg down through the call chain?
    if format == 'html':
        entries = [microformats2.object_to_html(a) for a in activities]
        return render('feed.html', **locals())

    elif format == 'atom':
        body = atom.activities_to_atom(activities, actor=actor, title=title,
                                       request_url=request.url)
        return body, {'Content-Type': atom.CONTENT_TYPE}

    elif format == 'rss':
        # RSS requires email to generate an author element, so fill in blank one
        # where necessary
        for a in activities:
            for field in ('actor', 'author', 'object'):
                if val := as1.get_object(a, field):
                    if as1.object_type(val) in as1.ACTOR_TYPES:
                        val.setdefault('email', '_@_._')

        body = rss.from_activities(activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}


@app.get('/log')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def log():
    return logs.log()


@app.get(f'/internal/<any({",".join(BLOG_REDIRECT_DOMAINS)}):host>/<path:path>')
@flask_util.headers(CACHE_CONTROL)
def blog_redirect(host, path):
    return MovedPermanently(location=f'https://{host}/{path}')


@app.post('/admin/memcache-evict')
def memcache_evict():
    if request.headers.get('Authorization') != app.config['SECRET_KEY']:
        return '', 401

    key = Key(urlsafe=flask_util.get_required_param('key'))
    memcache.evict(key)

    return ''
