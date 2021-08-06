"""Render recent responses and logs."""
import calendar
import urllib.parse

from flask import render_template
from oauth_dropins.webutil import logs, util

from app import app, cache
from models import Response


@app.get('/responses')
def responses():
    """Renders recent Responses, with links to logs."""
    responses = Response.query().order(-Response.updated).fetch(20)

    for r in responses:
        r.source_link = util.pretty_link(r.source())
        r.target_link = util.pretty_link(r.target())
        r.log_url_path = '/log?' + urllib.parse.urlencode({
          'key': r.key.id(),
          'start_time': calendar.timegm(r.updated.timetuple()),
        })

    return render_template('responses.html', responses=responses)


@app.get('/log')
@cache.cached(logs.CACHE_TIME.total_seconds())
def log():
    return logs.log()
