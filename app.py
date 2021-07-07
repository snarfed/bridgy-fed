"""Main WSGI application. Just URL routes to the other modules."""
import importlib

from oauth_dropins.webutil import appengine_info, appengine_config, handlers
import webapp2


routes = []
for module in (
  'activitypub',
  'add_webmention',
  'logs',
  'redirect',
  'salmon',
  'superfeedr',
  'webfinger',
  'webmention',
):
  routes += importlib.import_module(module).ROUTES

application = handlers.ndb_context_middleware(
    webapp2.WSGIApplication(routes, debug=appengine_info.DEBUG),
    client=appengine_config.ndb_client)
