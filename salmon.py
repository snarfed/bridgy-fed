"""Handles requests for Salmon endpoints: actors, inbox, etc.

https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-salmon-00.html
https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-magicsig-01.html
"""
import logging

import appengine_config

from django_salmon import magicsigs, utils
from granary import atom
from oauth_dropins.webutil import util
import webapp2

import common

# from django_salmon.feeds
ATOM_NS = 'http://www.w3.org/2005/Atom'
ATOM_THREADING_NS = 'http://purl.org/syndication/thread/1.0'


class SlapHandler(webapp2.RequestHandler):
    """Accepts POSTs to /[ACCT]/salmon and converts to outbound webmentions."""

    # TODO: unify with activitypub
    def post(self, username, domain):
        logging.info('Got: %s', self.request.body)

        parsed = utils.parse_magic_envelope(self.request.body)
        data = utils.decode(parsed['data'])
        logging.info('Decoded: %s', data)

        # verify signature
        author = utils.parse_author_uri_from_atom(data)
        if ':' not in author:
            author = 'acct:%s' % author
        elif not author.startswith('acct:'):
            common.error(self, 'Author URI %s has unsupported scheme; expected acct:' % author)

        logging.info('Fetching Salmon key for %s' % author)
        if not magicsigs.verify(author, data, parsed['sig']):
            common.error(self, 'Could not verify magic signature.')
        logging.info('Verified magic signature.')

        # Verify that the timestamp is recent. Required by spec.
        # I get that this helps prevent spam, but in practice it's a bit silly,
        # and other major implementations don't (e.g. Mastodon), so forget it.
        #
        # updated = utils.parse_updated_from_atom(data)
        # if not utils.verify_timestamp(updated):
        #     common.error(self, 'Timestamp is more than 1h old.')

        # send webmentions to each target
        activity = atom.atom_to_activity(data)
        common.send_webmentions(self, activity, protocol='ostatus', source_atom=data)


app = webapp2.WSGIApplication([
    (r'/%s/salmon' % common.ACCT_RE, SlapHandler),
], debug=appengine_config.DEBUG)
