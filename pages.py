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

from activitypub import ActivityPub
import common
from common import DOMAIN_RE
from flask_app import app, cache
from models import fetch_page, Follower, Object, PAGE_SIZE, PROTOCOLS
from protocol import Protocol

# precompute this because we get a ton of requests for non-existing users
# from weird open redirect referrers:
# https://github.com/snarfed/bridgy-fed/issues/422
with app.test_request_context('/'):
    USER_NOT_FOUND_HTML = render_template('user_not_found.html')

logger = logging.getLogger(__name__)

TEMPLATE_VARS = {
    'as2': as2,
    'g': g,
    'isinstance': isinstance,
    'logs': logs,
    'PROTOCOLS': PROTOCOLS,
    'set': set,
    'util': util,
}


def load_user(protocol, id):
    """Loads the current request's user into `g.user`.

    Args:
      protocol (str):
      id (str):

    Raises:
      :class:`werkzeug.exceptions.HTTPException` on error or redirect
    """
    assert id
    if protocol == 'ap' and not id.startswith('@'):
        id = '@' + id

    cls = PROTOCOLS[protocol]
    g.user = cls.get_by_id(id)

    if protocol != 'web':
        if not g.user:
            g.user = cls.query(OR(cls.handle == id,
                                  cls.readable_id == id),
                               ).get()
            if g.user and g.user.use_instead:
                g.user = g.user.use_instead.get()

        if g.user and id not in (g.user.key.id(), g.user.handle):
            error('', status=302, location=g.user.user_page_path())

    elif g.user and id != g.user.key.id():  # use_instead redirect
        error('', status=302, location=g.user.user_page_path())

    if not g.user or not g.user.direct or g.user.status == 'opt-out':
        # TODO: switch back to USER_NOT_FOUND_HTML
        # not easy via exception/abort because this uses Werkzeug's built in
        # NotFound exception subclass, and we'd need to make it implement
        # get_body to return arbitrary HTML.
        error(f'{protocol} user {id} not found', status=404)

    assert not g.user.use_instead


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
    load_user(protocol, id)
    query = Object.query(Object.users == g.user.key)
    objects, before, after = fetch_objects(query, by=Object.updated)
    num_followers, num_following = count_followers()
    return render_template('profile.html', **TEMPLATE_VARS, **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/home')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def home(protocol, id):
    load_user(protocol, id)
    query = Object.query(Object.feed == g.user.key)
    objects, before, after = fetch_objects(query, by=Object.created)

    # this calls Object.actor_link serially for each object, which loads the
    # actor from the datastore if necessary. TODO: parallelize those fetches
    return render_template('home.html', **TEMPLATE_VARS, **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/notifications')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def notifications(protocol, id):
    load_user(protocol, id)

    query = Object.query(Object.notify == g.user.key)
    objects, before, after = fetch_objects(query, by=Object.updated)

    format = request.args.get('format')
    if format:
        return serve_feed(objects=objects, format=format, as_snippets=True,
                          title=f'Bridgy Fed notifications for {id}',
                          quiet=request.args.get('quiet'))

    # notifications tab UI page
    return render_template('notifications.html', **TEMPLATE_VARS, **locals())


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/<any(followers,following):collection>')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def followers_or_following(protocol, id, collection):
    load_user(protocol, id)

    followers, before, after = Follower.fetch_page(collection)
    num_followers, num_following = count_followers()
    return render_template(
        f'{collection}.html',
        address=request.args.get('address'),
        follow_url=request.values.get('url'),
        ActivityPub=ActivityPub,
        **TEMPLATE_VARS,
        **locals(),
    )


# TODO: cache?
def count_followers():
    start = time.time()
    num_followers = Follower.query(Follower.to == g.user.key,
                                   Follower.status == 'active')\
                            .count()
    end = time.time()
    logger.info(f"Loading {g.user.key.id()}'s followers took {end - start}s")

    num_following = Follower.query(Follower.from_ == g.user.key,
                                   Follower.status == 'active')\
                            .count()

    return num_followers, num_following


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/feed')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
def feed(protocol, id):
    load_user(protocol, id)
    query = Object.query(Object.feed == g.user.key)
    objects, _, _ = fetch_objects(query, by=Object.created)
    return serve_feed(objects=objects, format=request.args.get('format', 'html'),
                      title=f'Bridgy Fed feed for {id}')


def serve_feed(*, objects, format, title, as_snippets=False, quiet=False):
    """Generates a feed based on :class:`Object`s.

    Args:
      objects (sequence of models.Object)
      format (str): ``html``, ``atom``, or ``rss``
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
                   ('follow', 'stop-following', 'like', 'share', 'update')]

    if as_snippets:
        activities = [{
            'objectType': 'note',
            'id': obj.key.id(),
            'content': f'{obj.actor_link(image=False)} {obj.phrase} {obj.content}',
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

    actor = (g.user.obj.as1 if g.user.obj and g.user.obj.as1
             else {'displayName': g.user.readable_id, 'url': g.user.web_url()})

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


@app.get('/bridge-user')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, datetime.timedelta(days=1))
def bridge_user_page():
    return render_template('bridge_user.html')


@app.post('/bridge-user')
def bridge_user():
    handle = request.values['handle']

    proto, id = Protocol.for_handle(handle)
    if not proto:
        flash(f"Couldn't determine protocol for {handle}")
        return render_template('bridge_user.html'), 400

    # TODO: put these into a PULL_PROTOCOLS constant?
    if not proto.LABEL in ('activitypub', 'fake', 'web'):
        flash(f"{proto.__name__} isn't supported")
        return render_template('bridge_user.html'), 400

    if not id:
        id = proto.handle_to_id(handle)
        if not id:
            flash(f"Couldn't resolve {proto.__name__} handle {handle}")
            return render_template('bridge_user.html'), 400

    user = proto.get_or_create(id=id, propagate=True)

    flash(f'Bridging <a href="{user.web_url()}">{user.handle}</a> into Bluesky. <a href="https://bsky.app/search">Try searching for them</a> in a minute!')
    return render_template('bridge_user.html')


def fetch_objects(query, by=None):
    """Fetches a page of :class:`models.Object` entities from a datastore query.

    Wraps :func:`models.fetch_page` and adds attributes to the returned
    :class:`models.Object` entities for rendering in ``objects.html``.

    Args:
      query (ndb.Query)
      by (ndb.model.Property): either :attr:`models.Object.updated` or
        :attr:`models.Object.created`

    Returns:
      (list of models.Object, str, str) tuple:
      (results, new ``before`` query param, new ``after`` query param)
      to fetch the previous and next pages, respectively
    """
    assert by is Object.updated or by is Object.created
    objects, new_before, new_after = fetch_page(query, Object, by=by)
    objects = [o for o in objects if not o.deleted]

    # synthesize human-friendly content for objects
    for i, obj in enumerate(objects):
        if obj.deleted:
            continue

        obj_as1 = obj.as1
        inner_obj = as1.get_object(obj_as1)

        # synthesize text snippet
        type = as1.object_type(obj_as1)
        if type == 'post':
            inner_type = inner_obj.get('objectType')
            if inner_type:
                type = inner_type

        phrases = {
            'article': 'posted',
            'comment': 'replied',
            'delete': 'deleted',
            'follow': 'followed',
            'invite': 'is invited to',
            'issue': 'filed issue',
            'like': 'liked',
            'note': 'posted',
            'post': 'posted',
            'repost': 'reposted',
            'rsvp-interested': 'is interested in',
            'rsvp-maybe': 'might attend',
            'rsvp-no': 'is not attending',
            'rsvp-yes': 'is attending',
            'share': 'reposted',
            'stop-following': 'unfollowed',
            'update': 'updated',
        }
        obj.phrase = phrases.get(type)

        content = (inner_obj.get('content')
                   or inner_obj.get('displayName')
                   or inner_obj.get('summary'))
        if content:
            content = util.parse_html(content).get_text()

        urls = as1.object_urls(inner_obj)
        id = common.unwrap(inner_obj.get('id', ''))
        url = urls[0] if urls else id
        if (type == 'update' and
            (obj.users and (g.user.is_web_url(id)
                            or id.strip('/') == obj.users[0].id())
             or obj.domains and id.strip('/') == f'https://{obj.domains[0]}')):
            obj.phrase = 'updated'
            obj_as1.update({
                'content': 'their profile',
                'url': id,
            })
        elif url:
            # heuristics for sniffing Mastodon and similar fediverse URLs and
            # converting them to more friendly @-names
            # TODO: standardize this into granary.as2 somewhere?
            if not content:
                fedi_url = re.match(
                    r'https://[^/]+/(@|users/)([^/@]+)(@[^/@]+)?(/(?:statuses/)?[0-9]+)?', url)
                if fedi_url:
                    content = '@' + fedi_url.group(2)
                    if fedi_url.group(4):
                        content += "'s post"
            content = common.pretty_link(url, text=content)

        obj.content = (obj_as1.get('content')
                       or obj_as1.get('displayName')
                       or obj_as1.get('summary'))
        obj.url = util.get_first(obj_as1, 'url')

        if type in ('like', 'follow', 'repost', 'share') or not obj.content:
            if obj.url:
                obj.phrase = common.pretty_link(obj.url, text=obj.phrase,
                                                attrs={'class': 'u-url'})
            if content:
                obj.content = content
                obj.url = url

    return objects, new_before, new_after


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
            'localPosts': Object.query(Object.source_protocol.IN(('web', 'webmention')),
                                       Object.type.IN(['note', 'article']),
                                       ).count(),
            'localComments': Object.query(Object.source_protocol.IN(('web', 'webmention')),
                                          Object.type == 'comment',
                                          ).count(),
        },
        'openRegistrations': True,
        'metadata': {},
    }, {
        # https://nodeinfo.diaspora.software/protocol.html
        'Content-Type': 'application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"',
    }


@app.get('/log')
@canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
