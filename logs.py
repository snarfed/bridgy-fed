"""Render recent responses and logs."""
import calendar
import urllib.parse

from flask import render_template
from oauth_dropins.webutil import util
from oauth_dropins.webutil import logs

from app import app
from models import Response


class LogHandler(logs.LogHandler):
  VERSION_IDS = ['1']


@app.get('/responses')
def responses():
    """Renders recent Responses, with links to logs."""
    responses = Response.query().order(-Response.updated).fetch(20)

    for r in responses:
        r.source_link = util.pretty_link(r.source())
        r.target_link = util.pretty_link(r.target())
        # TODO: uncomment once we've ported LogHandler to Flask
        # r.log_url_path = '/log?' + urllib.parse.urlencode({
        #   'key': r.key.id(),
        #   'start_time': calendar.timegm(r.updated.timetuple()),
        # })

    return render_template('responses.html', responses=responses)
