"""UI pages."""
import datetime
import itertools
import logging
import os
import re
import time

from flask import g, render_template, request
from google.cloud.ndb import tasklets
from google.cloud.ndb.query import AND, OR
from google.cloud.ndb.stats import KindStat
from granary import as1, as2, atom, microformats2, rss
import humanize
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import (
    canonicalize_request_domain,
    error,
    flash,
    redirect,
)

import common
from common import DOMAIN_RE
from flask_app import app, cache
from models import fetch_objects, fetch_page, Follower, Object, PAGE_SIZE, PROTOCOLS
from protocol import Protocol

# precompute this because we get a ton of requests for non-existing users
# from weird open redirect referrers:
# https://github.com/snarfed/bridgy-fed/issues/422
with app.test_request_context('/'):
    USER_NOT_FOUND_HTML = render_template('user_not_found.html')

logger = logging.getLogger(__name__)

TEMPLATE_VARS = {
    'as1': as1,
    'as2': as2,
    'g': g,
    'isinstance': isinstance,
    'logs': logs,
    'PROTOCOLS': PROTOCOLS,
    'set': set,
    'util': util,
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
    if protocol == 'ap' and not id.startswith('@'):
        id = '@' + id

    cls = PROTOCOLS[protocol]
    user = cls.get_by_id(id)

    if protocol != 'web':
        if not user:
            user = cls.query(OR(cls.handle == id,
                                  cls.readable_id == id),
                               ).get()
            if user and user.use_instead:
                user = user.use_instead.get()

        if user and id not in (user.key.id(), user.handle):
            error('', status=302, location=user.user_page_path())

    elif user and id != user.key.id():  # use_instead redirect
        error('', status=302, location=user.user_page_path())

    if user and (user.direct or protocol == 'web'):
        assert not user.use_instead
        return user

    # TODO: switch back to USER_NOT_FOUND_HTML
    # not easy via exception/abort because this uses Werkzeug's built in
    # NotFound exception subclass, and we'd need to make it implement
    # get_body to return arbitrary HTML.
    error(f'{protocol} user {id} not found', status=404)


@app.route('/')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
def front_page():
    """View for the front page."""
    return render_template('index.html')


@app.route('/docs')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
def docs():
    """View for the docs page."""
    return render_template('docs.html')


@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>')
@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/feed')
@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/<any(followers,following):collection>')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def web_user_redirects(**kwargs):
    path = request.url.removeprefix(request.root_url).removeprefix('user/')
    return redirect(f'/web/{path}', code=301)


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
    return render_template('profile.html', **TEMPLATE_VARS, **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/home')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def home(protocol, id):
    user = load_user(protocol, id)
    query = Object.query(Object.feed == user.key)
    objects, before, after = fetch_objects(query, by=Object.created, user=user)

    # this calls Object.actor_link serially for each object, which loads the
    # actor from the datastore if necessary. TODO: parallelize those fetches
    return render_template('home.html', **TEMPLATE_VARS, **locals())


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
    return render_template('notifications.html', **TEMPLATE_VARS, **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/<any(followers,following):collection>')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def followers_or_following(protocol, id, collection):
    user = load_user(protocol, id)
    followers, before, after = Follower.fetch_page(collection, user)
    num_followers, num_following = user.count_followers()
    return render_template(
        f'{collection}.html',
        address=request.args.get('address'),
        follow_url=request.values.get('url'),
        **TEMPLATE_VARS,
        **locals(),
    )


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/feed')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def feed(protocol, id):
    user = load_user(protocol, id)
    query = Object.query(Object.feed == user.key)
    objects, _, _ = fetch_objects(query, by=Object.created, user=user)
    return serve_feed(objects=objects, format=request.args.get('format', 'html'),
                      user=user, title=f'Bridgy Fed feed for {id}')


def serve_feed(*, objects, format, user, title, as_snippets=False, quiet=False):
    """Generates a feed based on :class:`Object`s.

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
            'content_is_html': True,
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

                future = Object.get_by_id_async(val['id'])
                future.add_done_callback(hydrate(a, field))
                gets.append(future)

    tasklets.wait_all(gets)

    actor = (user.obj.as1 if user.obj and user.obj.as1
             else {'displayName': user.readable_id, 'url': user.web_url()})

    # TODO: inject/merge common.pretty_link into microformats2.render_content
    # (specifically into hcard_to_html) somehow to convert Mastodon URLs to @-@
    # syntax. maybe a fediverse kwarg down through the call chain?
    if format == 'html':
        entries = [microformats2.object_to_html(a) for a in activities]
        return render_template('feed.html', **TEMPLATE_VARS, **locals())
    elif format == 'atom':
        body = atom.activities_to_atom(activities, actor=actor, title=title,
                                       request_url=request.url)
        return body, {'Content-Type': atom.CONTENT_TYPE}
    elif format == 'rss':
        body = rss.from_activities(activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}


# TODO: re-enable for launch
# @app.get('/bridge-user')
# @canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
# @flask_util.cached(cache, datetime.timedelta(days=1))
# def bridge_user_page():
#     return render_template('bridge_user.html')


# @app.post('/bridge-user')
# def bridge_user():
#     handle = request.values['handle']

#     proto, id = Protocol.for_handle(handle)
#     if not proto:
#         flash(f"Couldn't determine protocol for {handle}")
#         return render_template('bridge_user.html'), 400

#     # TODO: put these into a PULL_PROTOCOLS constant?
#     if not proto.LABEL in ('activitypub', 'fake', 'web'):
#         flash(f"{proto.__name__} isn't supported")
#         return render_template('bridge_user.html'), 400

#     if not id:
#         id = proto.handle_to_id(handle)
#         if not id:
#             flash(f"Couldn't resolve {proto.__name__} handle {handle}")
#             return render_template('bridge_user.html'), 400

#     user = proto.get_or_create(id=id, propagate=True)

#     flash(f'Bridging <a href="{user.web_url()}">{user.handle}</a> into Bluesky. <a href="https://bsky.app/search">Try searching for them</a> in a minute!')
#     return render_template('bridge_user.html')


@app.get('/stats')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def stats():
    def count(kind):
        return humanize.intcomma(
            KindStat.query(KindStat.kind_name == kind).get().count)

    return render_template(
        'stats.html',
        users=count('MagicKey'),
        objects=count('Object'),
        followers=count('Follower'),
    )


@app.get('/.well-known/nodeinfo')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
def nodeinfo_jrd():
    """
    https://nodeinfo.diaspora.software/protocol.html
    """
    return {
        'links': [{
            'rel': 'http://nodeinfo.diaspora.software/ns/schema/2.1',
            'href': common.host_url('nodeinfo.json'),
        }],
    }, {
        'Content-Type': 'application/jrd+json',
    }


@app.get('/nodeinfo.json')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
def nodeinfo():
    """
    https://nodeinfo.diaspora.software/schema.html
    """
    user_total = None
    stat = KindStat.query(KindStat.kind_name == 'MagicKey').get()
    if stat:
        user_total = stat.count

    return {
        'version': '2.1',
        'software': {
            'name': 'bridgy-fed',
            'version': os.getenv('GAE_VERSION'),
            'repository': 'https://github.com/snarfed/bridgy-fed',
            'web_url': 'https://fed.brid.gy/',
        },
        'protocols': [
            'activitypub',
            'bluesky',
            'webmention',
        ],
        'services': {
            'outbound': [],
            'inbound': [],
        },
        'usage': {
            'users': {
                'total': user_total,
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
        'metadata': {},
    }, {
        # https://nodeinfo.diaspora.software/protocol.html
        'Content-Type': 'application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"',
    }


@app.get('/api/v1/instance')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
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
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
