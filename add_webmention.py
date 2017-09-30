"""HTTP proxy that injects our webmention endpoint.
"""
import logging

import appengine_config

import requests
import webapp2

import common

LINK_HEADER = '<%s>; rel="webmention"'


class AddWebmentionHandler(webapp2.RequestHandler):
    """Proxies HTTP requests and adds Link header to our webmention endpoint."""

    def get(self, url):
        if not url.startswith('http://') and not url.startswith('https://'):
            self.abort(400, 'URL must start with http:// or https://')

        try:
            resp = common.requests_get(url)
        except requests.exceptions.Timeout as e:
            logging.info('Returning 504 due to', exc_info=True)
            self.abort(504, unicode(e))
        except requests.exceptions.RequestException as e:
            logging.info('Returning 502 due to', exc_info=True)
            self.abort(502, unicode(e))

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
