"""Render recent responses and logs."""
import calendar
from itertools import islice
import urllib.parse

from flask import render_template, request
from google.cloud.ndb.stats import KindStat
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import error

from app import app, cache
import common
from models import Response


@app.get('/responses')
@app.get(f'/responses/<regex("{common.DOMAIN_RE}"):domain>')
def responses(domain=None):
    """Renders recent Responses, with links to logs."""
    query = Response.query()\
        .filter(Response.status.IN(('new', 'complete', 'error')))\
        .order(-Response.updated)

    if domain:
        query = query.filter(Response.domain == domain)

    # if there's a paging param (responses_before or responses_after), update
    # query with it
    # TODO: unify this with Bridgy's user page
    def get_paging_param(param):
        val = request.values.get(param)
        try:
            return util.parse_iso8601(val.replace(' ', '+')) if val else None
        except BaseException:
            error(f"Couldn't parse {param}, {val!r} as ISO8601")

    before = get_paging_param('responses_before')
    after = get_paging_param('responses_after')
    if before and after:
        error("can't handle both responses_before and responses_after")
    elif after:
        query = query.filter(Response.updated > after).order(Response.updated)
    elif before:
        query = query.filter(Response.updated < before).order(-Response.updated)
    else:
        query = query.order(-Response.updated)

    query_iter = query.iter()
    responses = list(islice(query_iter, 0, 20))
    for r in responses:
        r.source_link = util.pretty_link(r.source())
        r.target_link = util.pretty_link(r.target())
        r.log_url_path = '/log?' + urllib.parse.urlencode({
          'key': r.key.id(),
          'start_time': calendar.timegm(r.updated.timetuple()),
        })

    vars = {
        'domain': domain,
        'responses': sorted(responses, key=lambda r: r.updated, reverse=True),
    }

    # calculate new paging param(s)
    new_after = (
        before if before
        else responses[0].updated
            if responses and query_iter.probably_has_next() and (before or after)
        else None)
    if new_after:
        vars['responses_after_link'] = f'?responses_after={new_after.isoformat()}#responses'

    new_before = (
        after if after else
        responses[-1].updated if
            responses and query_iter.probably_has_next()
        else None)
    if new_before:
        vars['responses_before_link'] = f'?responses_before={new_before.isoformat()}#responses'

    return render_template('responses.html', **vars)


@app.get('/stats')
def stats():
   return render_template(
       'stats.html',
       users=KindStat.query(KindStat.kind_name == 'MagicKey').get().count,
       responses=KindStat.query(KindStat.kind_name == 'Response').get().count,
       followers=KindStat.query(KindStat.kind_name == 'Follower').get().count,
   )


@app.get('/log')
@flask_util.cached(cache, logs.CACHE_TIME)
def log():
    return logs.log()
