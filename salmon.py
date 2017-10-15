"""Handles requests for Salmon endpoints: actors, inbox, etc.

https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-salmon-00.html
https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-magicsig-01.html
"""
import json
import logging
from xml.etree import ElementTree

import appengine_config

from django_salmon import magicsigs, utils
from granary import atom
from oauth_dropins.webutil import util
import webapp2
from webmentiontools import send

import common
from models import Response

# from django_salmon.feeds
ATOM_NS = 'http://www.w3.org/2005/Atom'
ATOM_THREADING_NS = 'http://purl.org/syndication/thread/1.0'
SUPPORTED_VERBS = (
    'checkin',
    'create',
    'like',
    'share',
    'tag',
    'update',
)


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

        activity = atom.atom_to_activity(data)
        verb = activity.get('verb')
        if verb and verb not in SUPPORTED_VERBS:
            common.error(self, '%s activities are not supported yet.' % type)

        # extract source and targets
        source = activity.get('url') or activity.get('id')
        obj = activity.get('object')
        obj_url = util.get_url(obj)

        targets = util.get_list(activity, 'inReplyTo')
        if isinstance(obj, dict):
            if not source:
                source = obj_url or obj.get('id')
            targets.extend(util.get_list(obj, 'inReplyTo'))
        if verb in ('like', 'share'):
             targets.append(obj_url)

        targets = util.dedupe_urls(util.get_url(t) for t in targets)
        if not source:
            common.error(self, "Couldn't find post URL (link element)")
        if not targets:
            common.error(self, "Couldn't find target URL (thr:in-reply-to or TODO)")

        # Verify that the timestamp is recent. Required by spec.
        # I get that this helps prevent spam, but in practice it's a bit silly,
        # and other major implementations don't (e.g. Mastodon), so forget it.
        #
        # updated = utils.parse_updated_from_atom(data)
        # if not utils.verify_timestamp(updated):
        #     common.error(self, 'Timestamp is more than 1h old.')

        # send webmentions!
        errors = []
        for target in targets:
            response = Response(source=source, target=target, direction='in',
                                protocol='ostatus', source_atom=data)
            response.put()
            wm_source = (response.proxy_url() if verb in ('like', 'share')
                         else source)
            logging.info('Sending webmention from %s to %s', source, target)

            wm = send.WebmentionSend(wm_source, target)
            if wm.send(headers=common.HEADERS):
                logging.info('Success: %s', wm.response)
                response.status = 'complete'
            else:
                logging.warning('Failed: %s', wm.error)
                errors.append(wm.error)
                response.status = 'error'
            response.put()

        if errors:
            self.abort(errors[0].get('http_status') or 400,
                'Errors:\n' + '\n'.join(json.dumps(e, indent=2) for e in errors))


app = webapp2.WSGIApplication([
    (r'/%s/salmon' % common.ACCT_RE, SlapHandler),
], debug=appengine_config.DEBUG)
