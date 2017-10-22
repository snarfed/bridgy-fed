# coding=utf-8
"""Misc common utilities.
"""
from __future__ import unicode_literals
import copy
import json
import logging
import re
import urlparse

from bs4 import BeautifulSoup
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
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
USERNAME = 'me'
# USERNAME_EMOJI = '🌎'  # globe
LINK_HEADER_RE = re.compile(r""" *< *([^ >]+) *> *; *rel=['"]([^'"]+)['"] *""")
AS2_PUBLIC_AUDIENCE = 'https://www.w3.org/ns/activitystreams#Public'

# Content-Type values. All non-unicode strings because App Engine's wsgi.py
# requires header values to be str, not unicode.
#
# ActivityPub Content-Type details:
# https://www.w3.org/TR/activitypub/#retrieving-objects
CONTENT_TYPE_AS2_LD = b'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
CONTENT_TYPE_AS2 = b'application/activity+json'
CONTENT_TYPE_AS1 = b'application/stream+json'
CONTENT_TYPE_HTML = b'text/html'
CONTENT_TYPE_ATOM = b'application/atom+xml'
CONTENT_TYPE_MAGIC_ENVELOPE = b'application/magic-envelope+xml'

CONNEG_HEADERS_AS2 = {
    'Accept': '%s; q=0.9, %s; q=0.8' % (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD),
}
CONNEG_HEADERS_AS2_HTML = {
    'Accept': CONNEG_HEADERS_AS2['Accept'] + ', %s; q=0.7' % CONTENT_TYPE_HTML,
}

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


def _requests_fn(fn, url, parse_json=False, **kwargs):
    """Wraps requests.* and adds raise_for_status() and User-Agent."""
    kwargs.setdefault('headers', {}).update(HEADERS)

    resp = fn(url, **kwargs)

    logging.info('Got %s headers:%s', resp.status_code, resp.headers)
    type = content_type(resp)
    if (type and type != 'text/html' and
        (type.startswith('text/') or type.endswith('+json'))):
        logging.info(resp.text)

    if resp.status_code // 100 in (4, 5):
        raise exc.HTTPBadGateway('Received %s from %s:\n%s' %
                                 (resp.status_code, url, resp.text))

    if parse_json:
        try:
            return resp.json()
        except ValueError:
            msg = "Couldn't parse response as JSON"
            logging.info(msg, exc_info=True)
            raise exc.HTTPBadGateway(msg)

    return resp


def get_as2(url):
    """Tries to fetch the given URL as ActivityStreams 2.

    Uses HTTP content negotiation via the Content-Type header. If the url is
    HTML and it has a rel-alternate link with an AS2 content type, fetches and
    returns that URL.

    Args:
        url: string

    Returns:
        requests.Response

    Raises:
        requests.HTTPError, webob.exc.HTTPException

        If we raise webob HTTPException, it will have an additional response
        attribute with the last requests.Response we received.
    """
    def _error(resp):
        msg = "Couldn't fetch %s as ActivityStreams 2" % url
        logging.error(msg)
        err = exc.HTTPBadGateway(msg)
        err.response = resp
        raise err

    resp = requests_get(url, headers=CONNEG_HEADERS_AS2_HTML)
    if content_type(resp) in (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD):
        return resp

    parsed = BeautifulSoup(resp.content, from_encoding=resp.encoding)
    as2 = parsed.find('link', rel=('alternate', 'self'), type=(
        CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD))
    if not (as2 and as2['href']):
        _error(resp)

    resp = requests_get(urlparse.urljoin(resp.url, as2['href']),
                        headers=CONNEG_HEADERS_AS2)
    if content_type(resp) in (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD):
        return resp

    _error(resp)


def content_type(resp):
    """Returns a requests.Response's Content-Type, without charset suffix."""
    type = resp.headers.get('Content-Type')
    if type:
        return type.split(';')[0]


def error(handler, msg, status=None, exc_info=False):
    if not status:
        status = 400
    logging.info('Returning %s: %s' % (status, msg), exc_info=exc_info)
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
