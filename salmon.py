"""Handles requests for Salmon endpoints: actors, inbox, etc.

https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-salmon-00.html
https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-magicsig-01.html
"""
import json
import logging
from xml.etree import ElementTree

import appengine_config

from django_salmon import magicsigs, utils
import webapp2
from webmentiontools import send

import common

# from django_salmon.feeds
ATOM_NS = 'http://www.w3.org/2005/Atom'
ATOM_THREADING_NS = 'http://purl.org/syndication/thread/1.0'


class SlapHandler(webapp2.RequestHandler):
    """Accepts POSTs to /[DOMAIN]/salmon and converts to outbound webmentions."""

    # TODO: unify with activitypub
    def post(self, domain):
        logging.info('Got: %s', self.request.body)

        parsed = utils.parse_magic_envelope(self.request.body)
        data = utils.decode(parsed['data'])
        logging.info('Decoded: %s', data)

        # verify signature
        author = utils.parse_author_uri_from_atom(data)
        if ':' not in author:
            author = 'acct:%s' % author
        elif not author.startswith('acct:'):
            self.error('Author URI %s has unsupported scheme; expected acct:' % author)

        logging.info('Fetching Salmon key for %s' % author)
        if not magicsigs.verify(author, data, parsed['sig']):
            self.error('Could not verify magic signature.')
        logging.info('Verified magic signature.')

        # verify that the timestamp is recent (required by spec)
        updated = utils.parse_updated_from_atom(data)
        if not utils.verify_timestamp(updated):
            self.error('Timestamp is more than 1h old.')

        # find webmention source and target
        source = None
        targets = []
        for elem in ElementTree.fromstring(data):
            if elem.tag == utils.normalize('link', ATOM_NS):
                source = elem.attrib.get('href').strip()
            elif elem.tag == utils.normalize('in-reply-to', ATOM_THREADING_NS):
                target = elem.attrib.get('ref') or elem.text
                if target and target not in targets:
                    targets.append(target.strip())

        if not source:
            self.error("Couldn't find post URL (link element)")
        if not targets:
            self.error("Couldn't find target URL (thr:in-reply-to or TODO)")

        # send webmentions!
        errors = []
        for target in targets:
            logging.info('Sending webmention from %s to %s', source, target)
            wm = send.WebmentionSend(source, target)
            if wm.send(headers=common.HEADERS):
                logging.info('Success: %s', wm.response)
            else:
                logging.warning('Failed: %s', wm.error)
                errors.append(wm.error)

        if errors:
            self.abort(errors[0].get('http_status') or 400,
                'Errors:\n' + '\n'.join(json.dumps(e, indent=2) for e in errors))

    def error(self, msg):
        logging.info(msg)
        self.abort(400, msg)


app = webapp2.WSGIApplication([
    (r'/(?:acct)?@%s/salmon' % common.DOMAIN_RE, SlapHandler),
], debug=appengine_config.DEBUG)
