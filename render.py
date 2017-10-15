# coding=utf-8
"""Renders mf2 proxy pages based on stored Responses."""
import json

import appengine_config

from granary import as2, atom, microformats2
from oauth_dropins.webutil.handlers import ModernHandler
from oauth_dropins.webutil import util
import webapp2

from models import Response


class RenderHandler(ModernHandler):
    """Fetches a stored Response and renders it as HTML."""

    def get(self):
        source = util.get_required_param(self, 'source')
        target = util.get_required_param(self, 'target')

        id = '%s %s' % (source, target)
        resp = Response.get_by_id(id)
        if not resp:
            self.abort(404, 'No stored response for %s' % id)

        if resp.source_mf2:
            as1 = microformats2.json_to_object(json.loads(resp.source_mf2))
        elif resp.source_as2:
            as1 = as2.to_as1(json.loads(resp.source_as2))
        elif resp.source_atom:
            as1 = atom.atom_to_activity(resp.source_atom)
        else:
            self.abort(404, 'Stored response for %s has no data' % id)

        self.response.write(microformats2.activities_to_html([as1]))


app = webapp2.WSGIApplication([
    ('/render', RenderHandler),
], debug=appengine_config.DEBUG)
