"""HTTP proxy that injects our webmention endpoint.
"""
import datetime
import urllib.parse

from oauth_dropins.webutil.handlers import cache_response
import requests
import webapp2

import common

LINK_HEADER = '<%s>; rel="webmention"'

CACHE_TIME = datetime.timedelta(seconds=15)


class AddWebmentionHandler(common.Handler):
    """Proxies HTTP requests and adds Link header to our webmention endpoint."""

    @cache_response(CACHE_TIME)
    def get(self, url):
        url = urllib.parse.unquote(url)
        if not url.startswith('http://') and not url.startswith('https://'):
            self.error('URL must start with http:// or https://')

        try:
            resp = common.requests_get(url)
        except requests.exceptions.Timeout as e:
            self.error(str(e), status=504, exc_info=True)
        except requests.exceptions.RequestException as e:
            self.error(str(e), status=502, exc_info=True)

        self.response.status_int = resp.status_code
        self.response.write(resp.content)

        endpoint = LINK_HEADER % (str(self.request.get('endpoint')) or
                                  self.request.host_url + '/webmention')
        self.response.headers.clear()
        self.response.headers.update(resp.headers)
        self.response.headers.add('Link', endpoint)


ROUTES = [
    ('/wm/(.+)', AddWebmentionHandler),
]
