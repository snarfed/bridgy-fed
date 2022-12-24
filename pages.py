"""UI pages."""
import datetime
import logging

from flask import redirect, render_template, request
import humanize
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import error, flash, redirect
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app, cache
import common
#from models import ...

PAGE_SIZE = 20

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


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>')
def user(domain):
    user = User.get_by_id(domain)
    ...


@app.get(f'/user/<regex("{common.DOMAIN_RE}"):domain>/feed')
def feed(domain):
    ...


@app.get('/responses')  # deprecated
def recent_deprecated():
    return redirect('/recent', code=301)


@app.get('/recent')
def recent():
    """Renders recent activities, with links to logs."""
    ...
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
    ...


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
    ...


@app.get('/stats')
def stats():
    def count(kind):
        return humanize.intcomma(
            KindStat.query(KindStat.kind_name == kind).get().count)

    return render_template(
        'stats.html',
        ...,
    )


@app.get('/log')
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
