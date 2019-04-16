"""HTTP proxy that injects our webmention endpoint.
"""
import datetime
import logging
import urllib

import appengine_config

from oauth_dropins.webutil.handlers import memcache_response
import requests
import webapp2

import common

LINK_HEADER = '<%s>; rel="webmention"'

CACHE_TIME = datetime.timedelta(seconds=15)


class AddWebmentionHandler(webapp2.RequestHandler):
    """Proxies HTTP requests and adds Link header to our webmention endpoint."""

    @memcache_response(CACHE_TIME)
    def get(self, url):
        url = urllib.unquote(url)
        if not url.startswith('http://') and not url.startswith('https://'):
            common.error(self, 'URL must start with http:// or https://')

        try:
            resp = common.requests_get(url)
        except requests.exceptions.Timeout as e:
            common.error(self, unicode(e), status=504, exc_info=True)
        except requests.exceptions.RequestException as e:
            common.error(self, unicode(e), status=502, exc_info=True)

        self.response.status_int = resp.status_code
        self.response.write(resp.content)

        endpoint = LINK_HEADER % (str(self.request.get('endpoint')) or
                                  appengine_config.HOST_URL + '/webmention')
        self.response.headers.clear()
        self.response.headers.update(resp.headers)
        self.response.headers.add('Link', endpoint)


app = webapp2.WSGIApplication([
    ('/wm/(.+)', AddWebmentionHandler),
], debug=appengine_config.DEBUG)
