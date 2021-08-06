"""Handles requests for Salmon endpoints: actors, inbox, etc.

https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-salmon-00.html
https://github.com/salmon-protocol/salmon-protocol/blob/master/draft-panzer-magicsig-01.html
"""
import logging
import re
from xml.etree.ElementTree import ParseError

from django_salmon import magicsigs, utils
from flask import request
from granary import atom
from oauth_dropins.webutil import util
from oauth_dropins.webutil.flask_util import error

from app import app
import common

# from django_salmon.feeds
ATOM_NS = 'http://www.w3.org/2005/Atom'
ATOM_THREADING_NS = 'http://purl.org/syndication/thread/1.0'

SUPPORTED_VERBS = (
    'checkin',
    'create',
    'favorite',
    'like',
    'share',
    'tag',
    'update',
)


@app.post(f'/<regex("{common.ACCT_RE}|{common.DOMAIN_RE}"):acct>/salmon')
def slap(acct):
    """Accepts POSTs to /[ACCT]/salmon and converts to outbound webmentions."""
    # TODO: unify with activitypub
    body = request.get_data(as_text=True)
    logging.info(f'Got: {body}')

    try:
        parsed = utils.parse_magic_envelope(body)
    except ParseError as e:
        error('Could not parse POST body as XML', exc_info=True)
    data = parsed['data']
    logging.info(f'Decoded: {data}')

    # check that we support this activity type
    try:
        activity = atom.atom_to_activity(data)
    except ParseError as e:
        error('Could not parse envelope data as XML', exc_info=True)

    verb = activity.get('verb')
    if verb and verb not in SUPPORTED_VERBS:
        error(f'Sorry, {verb} activities are not supported yet.', status=501)

    # verify author and signature
    author = util.get_url(activity.get('actor'))
    if ':' not in author:
        author = f'acct:{author}'
    elif not author.startswith('acct:'):
        error(f'Author URI {author} has unsupported scheme; expected acct:')

    logging.info(f'Fetching Salmon key for {author}')
    if not magicsigs.verify(data, parsed['sig'], author_uri=author):
        error('Could not verify magic signature.')
    logging.info('Verified magic signature.')

    # Verify that the timestamp is recent. Required by spec.
    # I get that this helps prevent spam, but in practice it's a bit silly,
    # and other major implementations don't (e.g. Mastodon), so forget it.
    #
    # updated = utils.parse_updated_from_atom(data)
    # if not utils.verify_timestamp(updated):
    #     error('Timestamp is more than 1h old.')

    # send webmentions to each target
    activity = atom.atom_to_activity(data)
    common.send_webmentions(activity, protocol='ostatus', source_atom=data)
    return ''
