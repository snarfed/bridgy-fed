# coding=utf-8
"""Misc common utilities.
"""
from __future__ import unicode_literals
import json
import logging
import re

from granary import as2
from oauth_dropins.webutil import util
import requests
from webmentiontools import send
from webob import exc

from models import Response

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

SUPPORTED_VERBS = (
    'checkin',
    'create',
    'like',
    'share',
    'tag',
    'update',
)


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

    if resp.status_code // 100 in (4, 5):
        common.error('Received %s from %s:\n%s' % (resp.status_code, url, resp.text),
                     status=502)

    if parse_json:
        try:
            return resp.json()
        except ValueError as e:
            common.error("Couldn't parse response from %s as JSON: %s\n%s" %
                         (url, e, resp.text), exc_info=True, status=502)

    return resp


def error(handler, msg, status=None):
    if not status:
        status = 400
    logging.info('Returning %s: %s' % (status, msg), exc_info=True)
    handler.abort(status, msg)


def send_webmentions(handler, activity, **response_props):
    """Sends webmentions for an incoming Salmon slap or ActivityPub inbox delivery.
    Args:
      handler: RequestHandler
      activity: dict, AS1 activity
      response_props: passed through to the newly created Responses
    """
    verb = activity.get('verb')
    if verb and verb not in SUPPORTED_VERBS:
        error(handler, '%s activities are not supported yet.' % type)

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
        error(handler, "Couldn't find original post URL")
    if not targets:
        error(handler, "Couldn't find target URLs (inReplyTo or object)")

    # send webmentions and store Responses
    errors = []
    for target in targets:
        if not target:
            continue

        response = Response(source=source, target=target, direction='in',
                            **response_props)
        response.put()
        wm_source = response.proxy_url() if verb in ('like', 'share') else source
        logging.info('Sending webmention from %s to %s', wm_source, target)

        wm = send.WebmentionSend(wm_source, target)
        if wm.send(headers=HEADERS):
            logging.info('Success: %s', wm.response)
            response.status = 'complete'
        else:
            logging.warning('Failed: %s', wm.error)
            errors.append(wm.error)
            response.status = 'error'
        response.put()

    if errors:
        msg = 'Errors:\n' + '\n'.join(json.dumps(e, indent=2) for e in errors)
        error(handler, msg, status=errors[0].get('http_status'))


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
    if obj and isinstance(obj, dict) and not obj.get('id'):
        obj['id'] = obj.get('url')

    return util.trim_nulls(activity)
