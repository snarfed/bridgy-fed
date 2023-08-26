"""UI pages."""
import datetime
import itertools
import logging
import os
import re

from flask import g, render_template, request
from google.cloud.ndb import tasklets
from google.cloud.ndb.query import AND, OR
from google.cloud.ndb.stats import KindStat
from granary import as1, as2, atom, microformats2, rss
import humanize
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import error, redirect

import common
from common import DOMAIN_RE
from flask_app import app, cache
from models import fetch_page, Follower, Object, PAGE_SIZE, PROTOCOLS

FOLLOWERS_UI_LIMIT = 999

# precompute this because we get a ton of requests for non-existing users
# from weird open redirect referrers:
# https://github.com/snarfed/bridgy-fed/issues/422
with app.test_request_context('/'):
    USER_NOT_FOUND_HTML = render_template('user_not_found.html')

logger = logging.getLogger(__name__)


def load_user(protocol, id):
    """Loads the current request's user into `g.user`.

    Args:
      protocol: str
      id: str

    Raises:
      :class:`werkzeug.exceptions.HTTPException` on error or redirect
    """
    assert id
    cls = PROTOCOLS[protocol]
    g.user = cls.get_by_id(id)

    if protocol != 'web':
        if not g.user:
            g.user = cls.query(cls.readable_id == id).get()
            if g.user and g.user.use_instead:
                g.user = g.user.use_instead.get()

        if g.user and id != g.user.readable_or_key_id():
            error('', status=302, location=g.user.user_page_path())

    elif g.user and id != g.user.key.id():  # use_instead redirect
        error('', status=302, location=g.user.user_page_path())

    if not g.user or not g.user.direct:
        # TODO: switch back to USER_NOT_FOUND_HTML
        # not easy via exception/abort because this uses Werkzeug's built in
        # NotFound exception subclass, and we'd need to make it implement
        # get_body to return arbitrary HTML.
        error(f'{protocol} user {id} not found', status=404)

    assert not g.user.use_instead


@app.route('/')
@flask_util.cached(cache, datetime.timedelta(days=1))
def front_page():
    """View for the front page."""
    return render_template('index.html')


@app.route('/docs')
@flask_util.cached(cache, datetime.timedelta(days=1))
def docs():
    """View for the docs page."""
    return render_template('docs.html')


@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>')
@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/feed')
@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/<any(followers,following):collection>')
def web_user_redirects(**kwargs):
    path = request.url.removeprefix(request.root_url).removeprefix('user/')
    return redirect(f'/web/{path}', code=301)


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>')
def user(protocol, id):
    load_user(protocol, id)

    query = Object.query(OR(Object.users == g.user.key,
                            Object.notify == g.user.key))
    objects, before, after = fetch_objects(query)

    followers = Follower.query(Follower.to == g.user.key,
                               Follower.status == 'active')\
                        .count(limit=FOLLOWERS_UI_LIMIT)
    followers = f'{followers}{"+" if followers == FOLLOWERS_UI_LIMIT else ""}'

    following = Follower.query(Follower.from_ == g.user.key,
                               Follower.status == 'active')\
                        .count(limit=FOLLOWERS_UI_LIMIT)
    following = f'{following}{"+" if following == FOLLOWERS_UI_LIMIT else ""}'

    return render_template(
        'user.html',
        follow_url=request.values.get('url'),
        logs=logs,
        util=util,
        address=request.args.get('address'),
        g=g,
        **locals(),
    )


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/<any(followers,following):collection>')
def followers_or_following(protocol, id, collection):
    load_user(protocol, id)

    followers, before, after = Follower.fetch_page(collection)
    return render_template(
        f'{collection}.html',
        address=request.args.get('address'),
        as2=as2,
        g=g,
        util=util,
        **locals()
    )


@app.get(f'/<any({",".join(PROTOCOLS)}):protocol>/<id>/feed')
def feed(protocol, id):
    format = request.args.get('format', 'html')
    if format not in ('html', 'atom', 'rss'):
        error(f'format {format} not supported; expected html, atom, or rss')

    load_user(protocol, id)

    objects = Object.query(OR(Object.feed == g.user.key,
                              # backward compatibility
                              AND(Object.users == g.user.key,
                                  Object.labels == 'feed'))) \
                    .order(-Object.created) \
                    .fetch(PAGE_SIZE)
    activities = [obj.as1 for obj in objects if not obj.deleted]

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

    actor = {
      'displayName': id,
      'url': g.user.web_url(),
    }
    title = f'Bridgy Fed feed for {id}'

    # TODO: inject/merge common.pretty_link into microformats2.render_content
    # (specifically into hcard_to_html) somehow to convert Mastodon URLs to @-@
    # syntax. maybe a fediverse kwarg down through the call chain?
    if format == 'html':
        entries = [microformats2.object_to_html(a) for a in activities]
        return render_template('feed.html', util=util, g=g, **locals())
    elif format == 'atom':
        body = atom.activities_to_atom(activities, actor=actor, title=title,
                                       request_url=request.url)
        return body, {'Content-Type': atom.CONTENT_TYPE}
    elif format == 'rss':
        body = rss.from_activities(activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}


def fetch_objects(query):
    """Fetches a page of Object entities from a datastore query.

    Wraps :func:`models.fetch_page` and adds attributes to the returned Object
    entities for rendering in objects.html.

    Args:
      query: :class:`ndb.Query`

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of Object entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    objects, new_before, new_after = fetch_page(query, Object)

    # synthesize human-friendly content for objects
    for i, obj in enumerate(objects):
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
        urls = as1.object_urls(inner_obj)
        id = common.redirect_unwrap(inner_obj.get('id', ''))
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
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
