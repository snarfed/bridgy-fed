# coding=utf-8
"""Renders mf2 proxy pages based on stored Responses."""
import datetime

import appengine_config

from granary import as2, atom, microformats2
from oauth_dropins.webutil.handlers import cache_response, ModernHandler
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_loads
import webapp2

from models import Response

CACHE_TIME = datetime.timedelta(minutes=15)


class RenderHandler(ModernHandler):
    """Fetches a stored Response and renders it as HTML."""

    @cache_response(CACHE_TIME)
    def get(self):
        source = util.get_required_param(self, 'source')
        target = util.get_required_param(self, 'target')

        id = '%s %s' % (source, target)
        resp = Response.get_by_id(id)
        if not resp:
            self.abort(404, 'No stored response for %s' % id)

        if resp.source_mf2:
            as1 = microformats2.json_to_object(json_loads(resp.source_mf2))
        elif resp.source_as2:
            as1 = as2.to_as1(json_loads(resp.source_as2))
        elif resp.source_atom:
            as1 = atom.atom_to_activity(resp.source_atom)
        else:
            self.abort(404, 'Stored response for %s has no data' % id)

        # add HTML meta redirect to source page. should trigger for end users in
        # browsers but not for webmention receivers (hopefully).
        html = microformats2.activities_to_html([as1])
        utf8 = '<meta charset="utf-8">'
        refresh = '<meta http-equiv="refresh" content="0;url=%s">' % source
        html = html.replace(utf8, utf8 + '\n' + refresh)

        self.response.write(html)


app = webapp2.WSGIApplication([
    ('/render', RenderHandler),
], debug=appengine_config.DEBUG)
