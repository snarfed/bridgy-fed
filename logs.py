"""Handlers and utilities for exposing app logs to users.
"""
import cgi
import datetime
import logging
import re
import urllib

import appengine_config
from google.appengine.api import logservice
from google.appengine.ext import ndb
from oauth_dropins.webutil.handlers import TemplateHandler
from oauth_dropins.webutil import util
import webapp2

from models import Response


class ResponsesHandler(TemplateHandler):
    """Renders recent Responses, with links to logs."""

    def template_file(self):
        return 'templates/responses.html'

    def template_vars(self):
        responses = Response.query().order(-Response.updated).fetch(20)

        for r in responses:
            r.source, r.target = [util.pretty_link(url)
                                  for url in r.key.id().split(' ')]

        return {
            'responses': responses,
        }


app = webapp2.WSGIApplication([
    ('/responses', ResponsesHandler),
], debug=appengine_config.DEBUG)
