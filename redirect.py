"""Simple endpoint that redirects to the embedded fully qualified URL.

May also instead fetch and convert to AS2, depending on conneg.

Used to wrap ActivityPub ids with the fed.brid.gy domain so that Mastodon
accepts them. Background:

https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747
"""
import datetime
import logging
import re
import urllib.parse

from granary import as2, microformats2
import mf2util
from oauth_dropins.webutil import util
from oauth_dropins.webutil.handlers import cache_response
from oauth_dropins.webutil.util import json_dumps
import ujson as json
import webapp2

import common
from models import MagicKey

CACHE_TIME = datetime.timedelta(seconds=15)


class RedirectHandler(common.Handler):
    """301 redirects to the embedded fully qualified URL.

    e.g. redirects /r/https://foo.com/bar?baz to https://foo.com/bar?baz
    """
    @cache_response(CACHE_TIME)
    def get(self):
        assert self.request.path_qs.startswith('/r/')
        to = self.request.path_qs[3:]

        # some browsers collapse repeated /s in the path down to a single slash.
        # if that happened to this URL, expand it back to two /s.
        to = re.sub(r'^(https?:/)([^/])', r'\1/\2', to)

        if not to.startswith('http://') and not to.startswith('https://'):
            self.error('Expected fully qualified URL; got %s' % to)

        # check that we've seen this domain before so we're not an open redirect
        domains = set((util.domain_from_link(to),
                       urllib.parse.urlparse(to).hostname))
        for domain in domains:
            if MagicKey.get_by_id(domain):
                logging.info(f'Found MagicKey for domain {domain}')
                break
        else:
            logging.info(f'No user found for any of {domains}; returning 404')
            self.abort(404)

        # poor man's conneg, only handle single Accept values, not multiple with
        # priorities.
        if self.request.headers.get('Accept') in (common.CONTENT_TYPE_AS2,
                                                  common.CONTENT_TYPE_AS2_LD):
            return self.convert_to_as2(to)

        # redirect
        logging.info('redirecting to %s', to)
        self.redirect(to, permanent=True)

    def convert_to_as2(self, url):
        """Fetch a URL as HTML, convert it to AS2, and return it.

        Currently mainly for Pixelfed.
        https://github.com/snarfed/bridgy-fed/issues/39
        """
        mf2 = util.fetch_mf2(url)
        entry = mf2util.find_first_entry(mf2, ['h-entry'])
        logging.info('Parsed mf2 for %s: %s', mf2['url'], json_dumps(entry, indent=2))

        obj = self.postprocess_as2(as2.from_as1(microformats2.json_to_object(entry)))
        logging.info('Returning: %s', json_dumps(obj, indent=2))

        self.response.headers.update({
            'Content-Type': common.CONTENT_TYPE_AS2,
            'Access-Control-Allow-Origin': '*',
        })
        self.response.write(json_dumps(obj, indent=2))


ROUTES = [
    (r'/r/.+', RedirectHandler),
]
