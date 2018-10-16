# coding=utf-8
"""Misc common utilities.
"""
from __future__ import unicode_literals
import copy
import itertools
import json
import logging
import re
import urlparse

from bs4 import BeautifulSoup
from granary import as2
from oauth_dropins.webutil import handlers, util
import requests
from webmentiontools import send
from webob import exc

import appengine_config
from models import Response

DOMAIN_RE = r'([^/]+\.[^/]+)'
ACCT_RE = r'(?:acct:)?([^@]+)@' + DOMAIN_RE
HEADERS = {
    'User-Agent': 'Bridgy Fed (https://fed.brid.gy/)',
}
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
# USERNAME = 'me'
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
    'post',
    'share',
    'tag',
    'update',
)

canonicalize_domain = handlers.redirect('bridgy-federated.appspot.com', 'fed.brid.gy')


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
        (type.startswith('text/') or type.endswith('+json') or type.endswith('/json'))):
        logging.info(resp.text)

    if resp.status_code // 100 in (4, 5):
        msg = 'Received %s from %s:\n%s' % (resp.status_code, url, resp.text)
        logging.info(msg)
        raise exc.HTTPBadGateway(msg)

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

    parsed = beautifulsoup_parse(resp.content, from_encoding=resp.encoding)
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
        error(handler, '%s activities are not supported yet.' % verb)

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


def postprocess_as2(activity, target=None, key=None):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    Args:
      activity: dict, AS2 object or activity
      target: dict, AS2 object, optional. The target of activity's inReplyTo or
        Like/Announce/etc object, if any.
      key: MagicKey, optional. populated into publicKey field if provided.
    """
    type = activity.get('type')

    # actor objects
    if type == 'Person':
        postprocess_as2_actor(activity)
        if not activity.get('publicKey'):
            # underspecified, inferred from this issue and Mastodon's implementation:
            # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
            # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
            activity['publicKey'] = {
                'publicKeyPem': key.public_pem(),
            }
        return activity

    for actor in (util.get_list(activity, 'attributedTo') +
                  util.get_list(activity, 'actor')):
        postprocess_as2_actor(actor)

    # inReplyTo: singly valued, prefer id over url
    target_id = target.get('id') if target else None
    in_reply_to = activity.get('inReplyTo')
    if in_reply_to:
        if target_id:
            activity['inReplyTo'] = target_id
        elif isinstance(in_reply_to, list):
            if len(in_reply_to) > 1:
                logging.warning(
                    "AS2 doesn't support multiple inReplyTo URLs! "
                    'Only using the first: %s' % in_reply_tos[0])
            activity['inReplyTo'] = in_reply_to[0]

        # Mastodon evidently requires a Mention tag for replies to generate a
        # notification to the original post's author. not required for likes,
        # reposts, etc. details:
        # https://github.com/snarfed/bridgy-fed/issues/34
        to = target.get('actor') or target.get('attributedTo')
        if to:
            if isinstance(to, dict):
                to = to.get('url') or to.get('id')
            if to:
                activity.setdefault('tag', []).append({
                    'type': 'Mention',
                    'href': to,
                })


    # activity objects (for Like, Announce, etc): prefer id over url
    obj = activity.get('object', {})
    if obj:
        if isinstance(obj, dict) and not obj.get('id'):
            obj['id'] = target_id or obj.get('url')
        elif obj != target_id:
            activity['object'] = target_id

    # id is required for most things. default to url if it's not set.
    if not activity.get('id'):
        activity['id'] = activity.get('url')

    assert activity.get('id') or (isinstance(obj, dict) and obj.get('id'))

    activity['id'] = redirect_wrap(activity['id'])
    activity['url'] = redirect_wrap(activity['url'])

    # cc public and target's author(s) and recipients
    # https://www.w3.org/TR/activitystreams-vocabulary/#audienceTargeting
    # https://w3c.github.io/activitypub/#delivery
    if type in as2.TYPE_TO_VERB or type in ('Article', 'Note'):
        recips = [AS2_PUBLIC_AUDIENCE]
        if target:
            recips += itertools.chain(*(util.get_list(target, field) for field in
                                        ('actor', 'attributedTo', 'to', 'cc')))
        activity['cc'] = util.dedupe_urls(util.get_url(recip) for recip in recips)

    # wrap articles and notes in a Create activity
    if type in ('Article', 'Note'):
        activity = {
            '@context': as2.CONTEXT,
            'type': 'Create',
            'object': activity,
        }

    return util.trim_nulls(activity)


def postprocess_as2_actor(actor):
    """Prepare an AS2 actor object to be served or sent via ActivityPub.

    Args:
      actor: dict, AS2 actor object
    """
    url = actor.get('url')
    if url:
        domain = urlparse.urlparse(url).netloc
        actor.setdefault('preferredUsername', domain)
        actor['id'] = '%s/%s' % (appengine_config.HOST_URL, domain)
        actor['url'] = redirect_wrap(url)


def redirect_wrap(url):
    """Returns a URL on our domain that redirects to this URL.

    ...to satisfy Mastodon's non-standard domain matching requirement. :(

    https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
    https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747
    """
    prefix = urlparse.urljoin(appengine_config.HOST_URL, '/r/')
    if url.startswith(prefix):
        return url
    return prefix + url


def beautifulsoup_parse(html, **kwargs):
  """Parses an HTML string with BeautifulSoup. Centralizes our parsing config.

  *Copied from bridgy/util.py.*

  We currently use lxml, which BeautifulSoup claims is the fastest and best:
  http://www.crummy.com/software/BeautifulSoup/bs4/doc/#specifying-the-parser-to-use

  lxml is a native module, so we don't bundle and deploy it to App Engine.
  Instead, we use App Engine's version by declaring it in app.yaml.
  https://cloud.google.com/appengine/docs/standard/python/tools/built-in-libraries-27

  We pin App Engine's version in requirements.freeze.txt and tell BeautifulSoup
  to use lxml explicitly to ensure we use the same parser and version in prod
  and locally, since we've been bit by at least one meaningful difference
  between lxml and e.g. html5lib: lxml includes the contents of <noscript> tags,
  html5lib omits them. :(
  https://github.com/snarfed/bridgy/issues/798#issuecomment-370508015
  """
  return BeautifulSoup(html, 'lxml', **kwargs)
