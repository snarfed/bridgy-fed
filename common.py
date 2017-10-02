# coding=utf-8
"""Misc common utilities.
"""
from __future__ import unicode_literals
import logging
import re

from granary import as2
from oauth_dropins.webutil import util
import requests
from webob import exc

DOMAIN_RE = r'([^/]+\.[^/]+)'
ACCT_RE = r'(?:acct:)?([^@]+)@' + DOMAIN_RE
HEADERS = {
    'User-Agent': 'Bridgy Fed (https://fed.brid.gy/)',
}
ATOM_CONTENT_TYPE = 'application/atom+xml'
MAGIC_ENVELOPE_CONTENT_TYPE = 'application/magic-envelope+xml'
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
USERNAME = 'me'
# USERNAME_EMOJI = '🌎'  # globe
LINK_HEADER_RE = re.compile(r""" *< *([^ >]+) *> *; *rel=['"]([^'"]+)['"] *""")
AS2_PUBLIC_AUDIENCE = 'https://www.w3.org/ns/activitystreams#Public'


def requests_get(url, **kwargs):
    return _requests_fn(util.requests_get, url, **kwargs)


def requests_post(url, **kwargs):
    return _requests_fn(util.requests_post, url, **kwargs)


def _requests_fn(fn, url, parse_json=False, log=False, **kwargs):
    """Wraps requests.* and adds raise_for_status() and User-Agent."""
    kwargs.setdefault('headers', {}).update(HEADERS)

    resp = fn(url, **kwargs)
    if log:
        logging.info('Got %s\n  headers:%s\n%s', resp.status_code, resp.headers,
                     resp.text)
    resp.raise_for_status()

    if parse_json:
        try:
            return resp.json()
        except ValueError:
            msg = "Couldn't parse response as JSON"
            logging.error(msg, exc_info=True)
            raise exc.HTTPBadRequest(msg)

    return resp


def error(handler, msg, status=400):
    logging.info(msg)
    handler.abort(status, msg)


def postprocess_as2(activity, key=None):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    Args:
      activity: dict, AS2 object or activity
      key: MagicKey, optional. populated into publicKey field if provided.
    """
    type = activity.get('type')
    if type == 'Person' and not activity.get('publicKey'):
        # underspecified, inferred from this issue and Mastodon's implementation:
        # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
        # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
        activity['publicKey'] = {
            'publicKeyPem': key.public_pem(),
        }
    if type == 'Person':
        activity.setdefault('preferredUsername', USERNAME)
    attr = activity.get('attributedTo')
    if attr:
        attr[0].setdefault('preferredUsername', USERNAME)

    in_reply_tos = activity.get('inReplyTo')
    if isinstance(in_reply_tos, list):
        if len(in_reply_tos) > 1:
            logging.warning("AS2 doesn't support multiple inReplyTo URLs! "
                            'Only using the first: %s' % in_reply_tos[0])
        activity['inReplyTo'] = in_reply_tos[0]

    if type in as2.TYPE_TO_VERB or type in ('Article', 'Note'):
        activity.setdefault('cc', []).extend(
            [AS2_PUBLIC_AUDIENCE] + util.get_list(activity, 'inReplyTo'))

    if type in ('Article', 'Note'):
        activity = {
            '@context': as2.CONTEXT,
            'type': 'Create',
            'object': activity,
        }

    # make sure the object has an id
    obj = activity.get('object')
    if obj and not obj.get('id'):
        obj['id'] = obj.get('url')

    return util.trim_nulls(activity)
