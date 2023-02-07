"""UI pages."""
import calendar
import datetime
import logging
import re
import urllib.parse

from flask import redirect, render_template, request
from google.cloud.ndb.stats import KindStat
from granary import as1, as2, atom, microformats2, rss
import humanize
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import error, flash, redirect
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from common import DOMAIN_RE, PAGE_SIZE
from models import Follower, Object, User

FOLLOWERS_UI_LIMIT = 999

logger = logging.getLogger(__name__)


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


@app.get('/web-site')
@flask_util.cached(cache, datetime.timedelta(days=1))
def enter_web_site():
    return render_template('enter_web_site.html')


@app.post('/web-site')
def check_web_site():
    url = request.values['url']
    domain = util.domain_from_link(url, minimize=False)
    if not domain:
        error(f'No domain found in {url}')

    user = User.get_or_create(domain)
    try:
        user = user.verify()
    except BaseException as e:
        if util.is_connection_failure(e):
            flash(f"Couldn't connect to {url}")
            return render_template('enter_web_site.html')
        raise

    user.put()
    return redirect(f'/user/{user.key.id()}')


@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>')
def user(domain):
    user = User.get_by_id(domain)
    if not user:
        return render_template('user_not_found.html', domain=domain), 404
    elif user.key.id() != domain:
        return redirect(f'/user/{user.key.id()}', code=301)

    assert not user.use_instead

    query = Object.query(
        Object.domains == domain,
        Object.labels.IN(('notification', 'user')),
    )
    objects, before, after = fetch_objects(query, user)

    followers = Follower.query(Follower.dest == domain, Follower.status == 'active')\
                        .count(limit=FOLLOWERS_UI_LIMIT)
    followers = f'{followers}{"+" if followers == FOLLOWERS_UI_LIMIT else ""}'

    following = Follower.query(Follower.src == domain, Follower.status == 'active')\
                        .count(limit=FOLLOWERS_UI_LIMIT)
    following = f'{following}{"+" if following == FOLLOWERS_UI_LIMIT else ""}'

    return render_template(
        'user.html',
        follow_url=request.values.get('url'),
        logs=logs,
        util=util,
        address=request.args.get('address'),
        **locals(),
    )


@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/<any(followers,following):collection>')
def followers_or_following(domain, collection):
    if not (user := User.get_by_id(domain)):  # user var is used in template
        return render_template('user_not_found.html', domain=domain), 404

    followers, before, after = common.fetch_followers(domain, collection)

    for f in followers:
        f.url = f.src if collection == 'followers' else f.dest
        f.handle = re.sub(r'^https?://(.+)/(users/|@)(.+)$', r'@\3@\1', f.url)
        person = f.to_as1()
        if person and isinstance(person, dict):
            f.name = person.get('name') or ''
            f.picture = util.get_url(person, 'icon') or util.get_url(person, 'image')

    return render_template(
        f'{collection}.html',
        util=util,
        **locals()
    )


@app.get(f'/user/<regex("{DOMAIN_RE}"):domain>/feed')
def feed(domain):
    format = request.args.get('format', 'html')
    if format not in ('html', 'atom', 'rss'):
        error(f'format {format} not supported; expected html, atom, or rss')

    if not (user := User.get_by_id(domain)):
      return render_template('user_not_found.html', domain=domain), 404

    objects, _, _ = Object.query(
        Object.domains == domain, Object.labels == 'feed') \
        .order(-Object.created) \
        .fetch_page(PAGE_SIZE)
    activities = [json_loads(obj.as1) for obj in objects]

    actor = {
      'displayName': domain,
      'url': f'https://{domain}',
    }
    title = f'Bridgy Fed feed for {domain}'

    if format == 'html':
        entries = [microformats2.object_to_html(a) for a in activities]
        return render_template('feed.html', util=util, **locals())
    elif format == 'atom':
        body = atom.activities_to_atom(activities, actor=actor, title=title,
                                       request_url=request.url)
        return body, {'Content-Type': atom.CONTENT_TYPE}
    elif format == 'rss':
        body = rss.from_activities(activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}


def fetch_objects(query, user):
    """Fetches a page of Object entities from a datastore query.

    Wraps :func:`common.fetch_page` and adds attributes to the returned Object
    entities for rendering in objects.html.

    Args:
      query: :class:`ndb.Query`
      user: :class:`User`

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of Object entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    objects, new_before, new_after = common.fetch_page(query, Object)
    seen = set()

    # synthesize human-friendly content for objects
    for i, obj in enumerate(objects):
        obj_as1 = json_loads(obj.as1)

        # synthesize text snippet
        type = as1.object_type(obj_as1)
        phrases = {
            'article': 'posted',
            'comment': 'replied',
            'follow': 'followed',
            'invite': 'is invited to',
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
        }
        obj.phrase = phrases.get(type)

        # TODO: unify inner object loading? optionally fetch external?
        inner_obj = util.get_first(obj_as1, 'object') or {}
        if isinstance(inner_obj, str):
            inner_obj = Object.get_by_id(inner_obj)
            if inner_obj:
                inner_obj = json_loads(inner_obj.as1)

        content = (inner_obj.get('content')
                   or inner_obj.get('displayName')
                   or inner_obj.get('summary'))
        url = util.get_first(inner_obj, 'url') or inner_obj.get('id')
        if (obj.domains and
              inner_obj.get('id', '').strip('/') == f'https://{obj.domains[0]}'):
            obj.phrase = 'updated'
            obj_as1.update({
                'content': 'their profile',
                'url': f'https://{obj.domains[0]}',
            })
        elif url:
            content = common.pretty_link(url, text=content, user=user)

        obj.content = (obj_as1.get('content')
                       or obj_as1.get('displayName')
                       or obj_as1.get('summary'))
        obj.url = util.get_first(obj_as1, 'url')

        if (type in ('like', 'follow', 'repost', 'share') or
            not obj.content):
            if obj.url:
                obj.phrase = common.pretty_link(obj.url, text=obj.phrase, user=user)
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


@app.get('/log')
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
