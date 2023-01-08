"""UI pages."""
import calendar
import datetime
from itertools import islice
import logging
import re
import urllib.parse

from flask import redirect, render_template, request
from google.cloud.ndb.stats import KindStat
from granary import as2, atom, microformats2, rss
import humanize
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import error, flash, redirect
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
from models import Follower, User, Activity

PAGE_SIZE = 20
ACTIVITIES_FETCH_LIMIT = 200
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


@app.get(f'/responses/<regex("{common.DOMAIN_RE}"):domain>')  # deprecated
def user_deprecated(domain):
    return redirect(f'/user/{domain}', code=301)


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>')
def user(domain):
    user = User.get_by_id(domain)
    if not user:
        return render_template('user_not_found.html', domain=domain), 404
    elif user.use_instead:
        return redirect(f'/user/{user.use_instead.id()}', code=301)

    query = Activity.query(
        Activity.status.IN(('new', 'complete', 'error')),
        Activity.domain == domain,
    )
    activities, before, after = fetch_activities(query)

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


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>/followers')
def followers(domain):
    # unify with following
    if not (user := User.get_by_id(domain)):
      return render_template('user_not_found.html', domain=domain), 404

    query = Follower.query(
        Follower.status == 'active',
        Follower.dest == domain,
    ).order(-Follower.updated)
    followers, before, after = fetch_page(query, Follower)

    for f in followers:
        f.url = f.src
        f.handle = re.sub(r'^https?://(.+)/(users/|@)(.+)$', r'@\3@\1', f.src)
        if f.last_follow:
            last_follow = json_loads(f.last_follow)
            actor = last_follow.get('actor', {})
            f.name = actor.get('name') or ''
            f.picture = util.get_url(actor, 'icon')

    return render_template(
        'followers.html',
        util=util,
        **locals()
    )


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>/following')
def following(domain):
    if not (user := User.get_by_id(domain)):
      return render_template('user_not_found.html', domain=domain), 404

    query = Follower.query(
        Follower.status == 'active',
        Follower.src == domain,
    ).order(-Follower.updated)
    followers, before, after = fetch_page(query, Follower)

    for f in followers:
        f.url = f.dest
        f.handle = re.sub(r'^https?://(.+)/(users/|@)(.+)$', r'@\3@\1', f.dest)
        if f.last_follow:
            last_follow = json_loads(f.last_follow)
            followee = last_follow.get('object', {})
            # TODO: drop AS1-isms once we've backfilled existing entities to AS2
            f.name = followee.get('name') or followee.get('displayName') or ''
            f.picture = util.get_url(followee, 'icon') or util.get_url(followee, 'image')

    return render_template(
        'following.html',
        util=util,
        **locals()
    )


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>/feed')
def feed(domain):
    format = request.args.get('format', 'html')
    if format not in ('html', 'atom', 'rss'):
        error(f'format {format} not supported; expected html, atom, or rss')

    if not (user := User.get_by_id(domain)):
      return render_template('user_not_found.html', domain=domain), 404

    as2_activities, _, _ = Activity.query(
        Activity.domain == domain, Activity.direction == 'in'
        ).order(-Activity.created
        ).fetch_page(PAGE_SIZE)
    as1_activities = [as2.to_as1(json_loads(a.source_as2))
                      for a in as2_activities
                      if a.source_as2]
    as1_activities = [a for a in as1_activities
                      if a.get('verb') not in ('like', 'update', 'follow')]

    actor = {
      'displayName': domain,
      'url': f'https://{domain}',
    }
    title = f'Bridgy Fed feed for {domain}'

    if format == 'html':
        entries = [microformats2.object_to_html(a) for a in as1_activities]
        return render_template('feed.html', util=util, **locals())
    elif format == 'atom':
        body = atom.activities_to_atom(as1_activities, actor=actor, title=title,
                                       request_url=request.url)
        return body, {'Content-Type': atom.CONTENT_TYPE}
    elif format == 'rss':
        body = rss.from_activities(as1_activities, actor=actor, title=title,
                                   feed_url=request.url)
        return body, {'Content-Type': rss.CONTENT_TYPE}


@app.get('/responses')  # deprecated
def recent_deprecated():
    return redirect('/recent', code=301)


@app.get('/recent')
def recent():
    """Renders recent activities, with links to logs."""
    query = Activity.query(Activity.status.IN(('new', 'complete', 'error')))
    activities, before, after = fetch_activities(query)
    return render_template(
        'recent.html',
        show_domains=True,
        logs=logs,
        util=util,
        **locals(),
    )


def fetch_page(query, model_class):
    """Fetches a page of results from a datastore query.

    Uses the `before` and `after` query params (if provided; should be ISO8601
    timestamps) and the queried model class's `updated` property to identify the
    page to fetch.

    Populates a `log_url_path` property on each result entity that points to a
    its most recent logged request.

    Args:
      query: :class:`ndb.Query`
      model_class: ndb model class

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of query result entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    # if there's a paging param ('before' or 'after'), update query with it
    # TODO: unify this with Bridgy's user page
    def get_paging_param(param):
        val = request.values.get(param)
        try:
            return util.parse_iso8601(val.replace(' ', '+')) if val else None
        except BaseException:
            error(f"Couldn't parse {param}, {val!r} as ISO8601")

    before = get_paging_param('before')
    after = get_paging_param('after')
    if before and after:
        error("can't handle both before and after")
    elif after:
        query = query.filter(model_class.updated > after).order(model_class.updated)
    elif before:
        query = query.filter(model_class.updated < before).order(-model_class.updated)
    else:
        query = query.order(-model_class.updated)

    query_iter = query.iter()
    results = sorted(islice(query_iter, 0, PAGE_SIZE),
                     key=lambda r: r.updated, reverse=True)

    # calculate new paging param(s)
    has_next = results and query_iter.probably_has_next()
    new_after = (
        before if before
        else results[0].updated if has_next and after
        else None)
    if new_after:
        new_after = new_after.isoformat()

    new_before = (
        after if after else
        results[-1].updated if has_next
        else None)
    if new_before:
        new_before = new_before.isoformat()

    return results, new_before, new_after


def fetch_activities(query):
    """Fetches a page of Activity entities from a datastore query.

    Wraps :func:`fetch_page` and adds attributes to the returned Activity
    entities for rendering in activities.html.

    Args:
      query: :class:`ndb.Query`

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of Activity entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    orig_activities, new_before, new_after = fetch_page(query, Activity)
    activities = []
    seen = set()

    # synthesize human-friendly content for activities
    for i, activity in enumerate(orig_activities):
        a = activity.to_as1()

        # de-dupe
        ids = set((a[field] for field in ('id', 'url') if a.get(field)))
        if ids & seen:
            continue
        seen.update(ids)
        activities.append(activity)

        # synthesize text snippet
        verb = a.get('verb') or a.get('objectType')
        obj = util.get_first(a, 'object') or {}

        phrases = {
            'article': 'posted',
            'note': 'posted',
            'post': 'posted',
            'comment': 'replied',
            'like': 'liked',
            'follow': 'followed',
            'repost': 'reposted',
            'share': 'reposted',
            'rsvp-yes': 'is attending',
            'rsvp-no': 'is not attending',
            'rsvp-maybe': 'might attend',
            'rsvp-interested': 'is interested in',
            'invite': 'is invited to',
        }
        activity.phrase = phrases.get(verb)

        obj_content = obj.get('content') or obj.get('displayName')
        obj_url = util.get_first(obj, 'url')
        if obj_url:
            obj_content = util.pretty_link(obj_url, text=obj_content)

        activity.content = a.get('content') or a.get('displayName')
        activity.url = util.get_first(a, 'url')

        if (verb in ('like', 'follow', 'repost', 'share') or
            not activity.content):
            if activity.url:
                activity.phrase = util.pretty_link(activity.url, text=activity.phrase)
            if obj_content:
                activity.content = obj_content
                activity.url = obj_url

    return activities, new_before, new_after


@app.get('/stats')
def stats():
    def count(kind):
        return humanize.intcomma(
            KindStat.query(KindStat.kind_name == kind).get().count)

    return render_template(
        'stats.html',
        users=count('MagicKey'),
        activities=count('Response'),
        followers=count('Follower'),
    )


@app.get('/log')
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
