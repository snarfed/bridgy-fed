"""UI pages."""
import datetime
import itertools
import logging
import os
import re
import time

from flask import render_template, request
from google.cloud.ndb import tasklets
from google.cloud.ndb.key import Key
from google.cloud.ndb.query import OR
from google.cloud.ndb.model import get_multi
from granary import as1, as2, atom, microformats2, rss
import oauth_dropins
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import (
    canonicalize_request_domain,
    error,
    flash,
)
from oauth_dropins.webutil.util import json_loads, json_dumps
import requests
from requests_oauth2client import DPoPTokenSerializer
from requests_oauth2client.flask.auth import FlaskSessionAuthMixin
import werkzeug.exceptions
from werkzeug.exceptions import NotFound

from activitypub import ActivityPub, instance_actor
import atproto
from atproto import ATProto, BlueskyOAuthStart
import common
from common import CACHE_CONTROL, DOMAIN_RE, PROTOCOL_DOMAINS
from flask_app import app
from flask import redirect, session
import ids
import memcache
from models import (
    fetch_objects,
    fetch_page,
    Follower,
    Object,
    PAGE_SIZE,
    PROTOCOLS,
    USER_STATUS_DESCRIPTIONS,
)
from protocol import Protocol
from web import Web

# precompute this because we get a ton of requests for non-existing users
# from weird open redirect referrers:
# https://github.com/snarfed/bridgy-fed/issues/422
with app.test_request_context('/'):
    USER_NOT_FOUND_HTML = render_template('user_not_found.html')

logger = logging.getLogger(__name__)

TEMPLATE_VARS = {
    'ActivityPub': ActivityPub,
    'as1': as1,
    'as2': as2,
    'ATProto': ATProto,
    'ids': ids,
    'isinstance': isinstance,
    'logs': logs,
    'PROTOCOLS': PROTOCOLS,
    'set': set,
    'util': util,
    'Web': Web,
}


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


def get_logins():
    """Returns the user's current logged in sessions:

    Returns:
      list of :class:`oauth_dropins.models.BaseAuth`
    """
    logins = get_multi(oauth_dropins.get_logins())
    return sorted(logins, key=lambda l: (l.key.kind(), l.user_display_name()))


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
    return render('login.html',
        bluesky_button=BlueskyOAuthStart.button_html(
            '/oauth/bluesky/start', image_prefix='/oauth_dropins_static/'),
        mastodon_button=oauth_dropins.mastodon.Start.button_html(
            '/oauth/mastodon/start', image_prefix='/oauth_dropins_static/'),
        pixelfed_button=oauth_dropins.pixelfed.Start.button_html(
            '/oauth/pixelfed/start', image_prefix='/oauth_dropins_static/'),
    )


@app.route('/settings')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def settings():
    """User settings page. Requires logged in session."""
    auth_entity = request.args.get('auth_entity')
    logged_in_as = Key(urlsafe=auth_entity).id() if auth_entity else None

    users = []
    user_keys = []

    for login in get_logins():
        proto = key = None
        match login.site_name():
            case 'Mastodon':
                proto = ActivityPub
                if login.user_json and (id := json_loads(login.user_json).get('uri')):
                    pass
                else:
                    logger.warning(f'Mastodon auth entity {login.key.id()} has no user_json or uri')
                    continue
            case 'Pixelfed':
                proto = ActivityPub
                user, server = login.key.id().strip('@').split('@')
                id = f'https://{server}/users/{user}'
            case 'Bluesky':
                proto = ATProto
                id = login.key.id()
            case _:
                assert False, repr(login)

        if logged_in_as:
            users.append(proto.get_or_create(id, allow_opt_out=True))
        else:
            user_keys.append(proto(id=id).key)

    users.extend(u for u in get_multi(user_keys) if u)
    if not users:
        return redirect('/login', code=302)

    return render(
        'settings.html',
        **locals(),
        USER_STATUS_DESCRIPTIONS=USER_STATUS_DESCRIPTIONS,
    )

@app.post('/logout')
def logout():
    """Logs the user out of all current login sessions."""
    oauth_dropins.logout()
    flash(f"OK, you're now logged out.")
    return redirect('/', code=302)


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
    redir = redirect(user.user_page_path(), code=302)

    try:
        user.reload_profile()
    except (requests.RequestException, werkzeug.exceptions.HTTPException) as e:
        _, msg = util.interpret_http_exception(e)
        flash(f"Couldn't update profile for {link}: {msg}")
        return redir

    if not user.obj:
        flash(f"Couldn't update profile for {link}")
        return redir

    common.create_task(queue='receive', obj_id=user.obj_key.id(),
                       authed_as=user.key.id())
    flash(f'Updating profile from {link}...')

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

    return redir


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/<any(followers,following):collection>')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def followers_or_following(protocol, id, collection):
    user = load_user(protocol, id)
    id = user.key.id()
    handle = user.handle

    followers, before, after = Follower.fetch_page(collection, user)
    num_followers, num_following = user.count_followers()
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
    fields = 'author', 'actor', 'object'
    gets = []
    for a in activities:
        for field in fields:
            val = as1.get_object(a, field)
            if val and val.keys() <= set(['id']):
                def hydrate(a, f):
                    def maybe_set(future):
                        if future.result() and future.result().as1:
                            a[f] = future.result().as1
                    return maybe_set

                # TODO: extract a Protocol class method out of User.profile_id,
                # then use that here instead. the catch is that we'd need to
                # determine Protocol for every id, which is expensive.
                #
                # same TODO is in models.fetch_objects
                id = val['id']
                if id.startswith('did:'):
                    id = f'at://{id}/app.bsky.actor.profile/self'

                future = Object.get_by_id_async(id)
                future.add_done_callback(hydrate(a, field))
                gets.append(future)

    tasklets.wait_all(gets)

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
            for field in fields:
                if val := as1.get_object(a, field):
                    if as1.object_type(val) in as1.ACTOR_TYPES:
                        val.setdefault('email', '_@_._')

        body = rss.from_activities(activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}



@app.get('/.well-known/nodeinfo')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def nodeinfo_jrd():
    """
    https://nodeinfo.diaspora.software/protocol.html
    """
    return {
        'links': [{
            'rel': 'http://nodeinfo.diaspora.software/ns/schema/2.1',
            'href': common.host_url('nodeinfo.json'),
        }, {
            "rel": "https://www.w3.org/ns/activitystreams#Application",
            "href": instance_actor().id_as(ActivityPub),
        }],
    }, {
        'Content-Type': 'application/jrd+json',
    }


@app.get('/nodeinfo.json')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@memcache.memoize(expire=datetime.timedelta(hours=1))
@flask_util.headers(CACHE_CONTROL)
def nodeinfo():
    """
    https://nodeinfo.diaspora.software/schema.html
    """
    atp = ATProto.query(ATProto.enabled_protocols != None).count()
    ap = ActivityPub.query(ActivityPub.enabled_protocols != None).count()
    web = Web.query(Web.status == None).count()
    total = atp + ap + web

    logger.info(f'Users: ap: {ap}')
    logger.info(f'Users: atproto: {atp}')
    logger.info(f'Users: web: {web}')
    logger.info(f'Users: total: {total}')

    return {
        'version': '2.1',
        'software': {
            'name': 'bridgy-fed',
            'version': os.getenv('GAE_VERSION'),
            'repository': 'https://github.com/snarfed/bridgy-fed',
            'homepage': 'https://fed.brid.gy/',
        },
        'protocols': [
            'activitypub',
            'atprotocol',
            'webmention',
        ],
        'services': {
            'outbound': [],
            'inbound': [],
        },
        'usage': {
            'users': {
                'total': total,
                # 'activeMonth':
                # 'activeHalfyear':
            },
            # these are too heavy
            # 'localPosts': Object.query(Object.source_protocol.IN(('web', 'webmention')),
            #                            Object.type.IN(['note', 'article']),
            #                            ).count(),
            # 'localComments': Object.query(Object.source_protocol.IN(('web', 'webmention')),
            #                               Object.type == 'comment',
            #                               ).count(),
        },
        'openRegistrations': True,
        'metadata': {
            'users': {
                'activitypub': ap,
                'atprotocol': atp,
                'webmention': web,
            },
        },
    }, {
        # https://nodeinfo.diaspora.software/protocol.html
        'Content-Type': 'application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"',
    }


@app.get('/api/v1/instance')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def instance_info():
    """
    https://docs.joinmastodon.org/methods/instance/#v1
    """
    return {
        'uri': 'fed.brid.gy',
        'title': 'Bridgy Fed',
        'version': os.getenv('GAE_VERSION'),
        'short_description': 'Bridging the new social internet',
        'description': 'Bridging the new social internet',
        'email': 'feedback@brid.gy',
        'thumbnail': 'https://fed.brid.gy/static/bridgy_logo_with_alpha.png',
        'registrations': True,
        'approval_required': False,
        'invites_enabled': False,
        'contact_account': {
            'username': 'snarfed.org',
            'acct': 'snarfed.org',
            'display_name': 'Ryan',
            'url': 'https://snarfed.org/',
        },
    }


@app.get('/log')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def log():
    return logs.log()
