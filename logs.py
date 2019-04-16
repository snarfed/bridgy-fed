"""Render recent responses and logs."""
import calendar
import datetime
import urllib

import appengine_config

from oauth_dropins.webutil import util
from oauth_dropins.webutil.handlers import TemplateHandler
from oauth_dropins.webutil import logs
import webapp2

from models import Response

VERSION_1_DEPLOYED = datetime.datetime(2017, 10, 26, 16, 0)


class LogHandler(logs.LogHandler):
  VERSION_IDS = ['1']


class ResponsesHandler(TemplateHandler):
    """Renders recent Responses, with links to logs."""

    def template_file(self):
        return 'templates/responses.html'

    def template_vars(self):
        responses = Response.query().order(-Response.updated).fetch(20)

        for r in responses:
            r.source_link = util.pretty_link(r.source())
            r.target_link = util.pretty_link(r.target())
            r.log_url_path = '/log?' + urllib.urlencode({
              'key': r.key.id(),
              'start_time': calendar.timegm(r.updated.timetuple()),
            })

        return {
            'responses': responses,
        }


app = webapp2.WSGIApplication([
    ('/log', LogHandler),
    ('/responses', ResponsesHandler),
], debug=appengine_config.DEBUG)
