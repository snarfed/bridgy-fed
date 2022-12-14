# coding=utf-8
"""Misc common utilities.
"""
from base64 import b64encode
import datetime
from hashlib import sha256
import itertools
import logging
import os
import re
import urllib.parse

from flask import request
from granary import as2, microformats2
from httpsig.requests_auth import HTTPSignatureAuth
import mf2util
from oauth_dropins.webutil import util, webmention
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

from models import Activity, User

logger = logging.getLogger(__name__)

DOMAIN_RE = r'([^/:]+\.[^/:]+)'
ACCT_RE = r'(?:acct:)?([^@]+)@' + DOMAIN_RE
TLD_BLOCKLIST = ('7z', 'asp', 'aspx', 'gif', 'html', 'ico', 'jpg', 'jpeg', 'js',
                 'json', 'php', 'png', 'rar', 'txt', 'yaml', 'yml', 'zip')
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
LINK_HEADER_RE = re.compile(r""" *< *([^ >]+) *> *; *rel=['"]([^'"]+)['"] *""")

# Content-Type values. All non-unicode strings because App Engine's wsgi.py
# requires header values to be str, not unicode.
#
# ActivityPub Content-Type details:
# https://www.w3.org/TR/activitypub/#retrieving-objects
CONTENT_TYPE_AS2_LD = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
CONTENT_TYPE_AS2 = 'application/activity+json'
CONTENT_TYPE_AS1 = 'application/stream+json'
CONTENT_TYPE_HTML = 'text/html; charset=utf-8'
CONTENT_TYPE_ATOM = 'application/atom+xml'
CONTENT_TYPE_MAGIC_ENVELOPE = 'application/magic-envelope+xml'

CONNEG_HEADERS_AS2 = {
    'Accept': '%s; q=0.9, %s; q=0.8' % (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD),
}
CONNEG_HEADERS_AS2_HTML = {
    'Accept': CONNEG_HEADERS_AS2['Accept'] + ', %s; q=0.7' % CONTENT_TYPE_HTML,
}

SUPPORTED_VERBS = (
    'checkin',
    'create',
    'follow',
    'like',
    'post',
    'share',
    'tag',
    'update',
)

PRIMARY_DOMAIN = 'fed.brid.gy'
OTHER_DOMAINS = (
    'bridgy-federated.appspot.com',
    'localhost',
)
DOMAINS = (PRIMARY_DOMAIN,) + OTHER_DOMAINS
# TODO: unify with Bridgy's
DOMAIN_BLOCKLIST = frozenset((
    'facebook.com',
    'fb.com',
    't.co',
    'twitter.com',
) + DOMAINS)

_DEFAULT_SIGNATURE_USER = None

# alias allows unit tests to mock the function
utcnow = datetime.datetime.utcnow


def default_signature_user():
    global _DEFAULT_SIGNATURE_USER
    if _DEFAULT_SIGNATURE_USER is None:
        _DEFAULT_SIGNATURE_USER = User.get_or_create('snarfed.org')
    return _DEFAULT_SIGNATURE_USER


def signed_get(url, **kwargs):
    return signed_request(util.requests_get, url, **kwargs)


def signed_post(url, **kwargs):
    return signed_request(util.requests_post, url, **kwargs)


def signed_request(fn, url, data=None, user=None, headers=None, **kwargs):
    """Wraps requests.* and adds HTTP Signature.

    Args:
      fn: :func:`util.requests_get` or  :func:`util.requests_get`
      url: str
      data: optional AS2 object
      user: optional :class:`User` to sign request with
      kwargs: passed through to requests

    Returns: :class:`requests.Response`
    """
    if headers is None:
        headers = {}

    # prepare HTTP Signature and headers
    if not user:
        user = default_signature_user()

    if data:
        logging.info(f'Sending AS2 object: {json_dumps(data, indent=2)}')
        data = kwargs['data'] = json_dumps(data).encode()

    headers.update({
        # required for HTTP Signature
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
        'Date': utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        # required by Mastodon
        # https://github.com/tootsuite/mastodon/pull/14556#issuecomment-674077648
        'Host': util.domain_from_link(url, minimize=False),
        'Content-Type': CONTENT_TYPE_AS2,
        # required for HTTP Signature and Mastodon
        'Digest': f'SHA-256={b64encode(sha256(data or b"").digest()).decode()}',
    })

    domain = user.key.id()
    logger.info(f"Signing with {domain}'s key")
    key_id = request.host_url + domain
    auth = HTTPSignatureAuth(secret=user.private_pem(), key_id=key_id,
                             algorithm='rsa-sha256', sign_header='signature',
                             headers=('Date', 'Host', 'Digest'))

    # make HTTP request
    kwargs.setdefault('gateway', True)
    resp = fn(url, auth=auth, headers=headers, **kwargs)

    logger.info(f'Got {resp.status_code} headers: {resp.headers}')
    type = content_type(resp)
    if (type and type != 'text/html' and
        (type.startswith('text/') or type.endswith('+json') or type.endswith('/json'))):
        logger.info(resp.text)

    return resp


def get_as2(url, user=None):
    """Tries to fetch the given URL as ActivityStreams 2.

    Uses HTTP content negotiation via the Content-Type header. If the url is
    HTML and it has a rel-alternate link with an AS2 content type, fetches and
    returns that URL.

    Includes an HTTP Signature with the request.
    https://w3c.github.io/activitypub/#authorization
    https://tools.ietf.org/html/draft-cavage-http-signatures-07
    https://github.com/mastodon/mastodon/pull/11269

    Mastodon requires this signature if AUTHORIZED_FETCH aka secure mode is on:
    https://docs.joinmastodon.org/admin/config/#authorized_fetch

    If user is not provided, defaults to using @snarfed.org@snarfed.org's key.

    Args:
        url: string
        user: :class:`User` used to sign request

    Returns:
        :class:`requests.Response`

    Raises:
        :class:`requests.HTTPError`, :class:`werkzeug.exceptions.HTTPException`

        If we raise a werkzeug HTTPException, it will have an additional
        requests_response attribute with the last requests.Response we received.
    """
    def _error(resp):
        msg = "Couldn't fetch %s as ActivityStreams 2" % url
        logger.warning(msg)
        err = BadGateway(msg)
        err.requests_response = resp
        raise err

    resp = signed_get(url, user=user, headers=CONNEG_HEADERS_AS2_HTML)
    if content_type(resp) in (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD):
        return resp

    parsed = util.parse_html(resp)
    as2 = parsed.find('link', rel=('alternate', 'self'), type=(
        CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD))
    if not (as2 and as2['href']):
        _error(resp)

    resp = signed_get(urllib.parse.urljoin(resp.url, as2['href']),
                      headers=CONNEG_HEADERS_AS2)
    if content_type(resp) in (CONTENT_TYPE_AS2, CONTENT_TYPE_AS2_LD):
        return resp

    _error(resp)


def content_type(resp):
    """Returns a :class:`requests.Response`'s Content-Type, without charset suffix."""
    type = resp.headers.get('Content-Type')
    if type:
        return type.split(';')[0]


def remove_blocklisted(urls):
    """Returns the subset of input URLs that aren't in our domain blocklist.

    Args:
      urls: sequence of str

    Returns: list of str
    """
    return [u for u in urls if not util.domain_or_parent_in(
              util.domain_from_link(u), DOMAIN_BLOCKLIST)]


def send_webmentions(activity_wrapped, proxy=None, **activity_props):
    """Sends webmentions for an incoming Salmon slap or ActivityPub inbox delivery.
    Args:
      activity_wrapped: dict, AS1 activity
      activity_props: passed through to the newly created Activity entities

    Returns: boolean, True if any webmentions were sent, False otherwise
    """
    activity = redirect_unwrap(activity_wrapped)

    verb = activity.get('verb')
    if verb and verb not in SUPPORTED_VERBS:
        error(f'{verb} activities are not supported yet.')

    # extract source and targets
    source = activity.get('url') or activity.get('id')
    obj = activity.get('object')
    obj_url = util.get_url(obj)

    targets = util.get_list(activity, 'inReplyTo')
    if isinstance(obj, dict):
        if not source or verb in ('create', 'post', 'update'):
            source = obj_url or obj.get('id')
        targets.extend(util.get_list(obj, 'inReplyTo'))

    if not source:
        error("Couldn't find original post URL")

    tags = util.get_list(activity_wrapped, 'tags')
    obj_wrapped = activity_wrapped.get('object')
    if isinstance(obj_wrapped, dict):
        tags.extend(util.get_list(obj_wrapped, 'tags'))
    for tag in tags:
        if tag.get('objectType') == 'mention':
            url = tag.get('url')
            if url and url.startswith(request.host_url):
                targets.append(redirect_unwrap(url))

    if verb in ('follow', 'like', 'share'):
        targets.append(obj_url)

    targets = util.dedupe_urls(util.get_url(t) for t in targets)
    targets = remove_blocklisted(t.lower() for t in targets)
    if not targets:
        logger.info("Couldn't find any IndieWeb target URLs in inReplyTo, object, or mention tags")
        return False

    logger.info(f'targets: {targets}')

    # send webmentions and store Activitys
    errors = []  # stores (code, body) tuples
    for target in targets:
        domain = util.domain_from_link(target, minimize=False)
        if (domain == util.domain_from_link(source, minimize=False)):
            logger.info(f'Skipping same-domain webmention from {source} to {target}')
            continue

        activity = Activity(source=source, target=target, direction='in',
                            domain=[domain], **activity_props)
        activity.put()
        wm_source = (activity.proxy_url()
                     if verb in ('follow', 'like', 'share') or proxy
                     else source)
        logger.info(f'Sending webmention from {wm_source} to {target}')

        try:
            endpoint = webmention.discover(target).endpoint
            if endpoint:
                webmention.send(endpoint, wm_source, target)
                activity.status = 'complete'
                logger.info('Success!')
            else:
                activity.status = 'ignored'
                logger.info('Ignoring.')
        except BaseException as e:
            errors.append(util.interpret_http_exception(e))
        activity.put()

    if errors:
        msg = 'Errors: ' + ', '.join(f'{code} {body}' for code, body in errors)
        error(msg, status=int(errors[0][0] or 502))

    return True


def postprocess_as2(activity, user=None, target=None):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    Args:
      activity: dict, AS2 object or activity
      user: :class:`User`, required. populated into actor.id and
        publicKey fields if needed.
      target: dict, AS2 object, optional. The target of activity's inReplyTo or
        Like/Announce/etc object, if any.
    """
    assert user
    type = activity.get('type')

    # actor objects
    if type == 'Person':
        postprocess_as2_actor(activity, user)
        if not activity.get('publicKey'):
            # underspecified, inferred from this issue and Mastodon's implementation:
            # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
            # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
            actor_url = request.host_url + activity.get('preferredUsername')
            activity.update({
                'publicKey': {
                    'id': actor_url,
                    'owner': actor_url,
                    'publicKeyPem': user.public_pem().decode(),
                },
                '@context': (util.get_list(activity, '@context') +
                             ['https://w3id.org/security/v1']),
            })
        return activity

    for actor in (util.get_list(activity, 'attributedTo') +
                  util.get_list(activity, 'actor')):
        postprocess_as2_actor(actor, user)

    # inReplyTo: singly valued, prefer id over url
    target_id = target.get('id') if target else None
    in_reply_to = activity.get('inReplyTo')
    if in_reply_to:
        if target_id:
            activity['inReplyTo'] = target_id
        elif isinstance(in_reply_to, list):
            if len(in_reply_to) > 1:
                logger.warning(
                    "AS2 doesn't support multiple inReplyTo URLs! "
                    'Only using the first: %s' % in_reply_to[0])
            activity['inReplyTo'] = in_reply_to[0]

        # Mastodon evidently requires a Mention tag for replies to generate a
        # notification to the original post's author. not required for likes,
        # reposts, etc. details:
        # https://github.com/snarfed/bridgy-fed/issues/34
        if target:
            for to in (util.get_list(target, 'attributedTo') +
                       util.get_list(target, 'actor')):
                if isinstance(to, dict):
                    to = util.get_first(to, 'url') or to.get('id')
                if to:
                    activity.setdefault('tag', []).append({
                        'type': 'Mention',
                        'href': to,
                    })

    # activity objects (for Like, Announce, etc): prefer id over url
    obj = activity.get('object')
    if obj:
        if isinstance(obj, dict) and not obj.get('id'):
            obj['id'] = target_id or util.get_first(obj, 'url')
        elif target_id and obj != target_id:
            activity['object'] = target_id

    # id is required for most things. default to url if it's not set.
    if not activity.get('id'):
        activity['id'] = util.get_first(activity, 'url')

    # TODO: find a better way to check this, sometimes or always?
    # removed for now since it fires on posts without u-id or u-url, eg
    # https://chrisbeckstrom.com/2018/12/27/32551/
    # assert activity.get('id') or (isinstance(obj, dict) and obj.get('id'))

    activity['id'] = redirect_wrap(activity.get('id'))
    activity['url'] = [redirect_wrap(u) for u in util.get_list(activity, 'url')]
    if len(activity['url']) == 1:
        activity['url'] = activity['url'][0]

    # copy image(s) into attachment(s). may be Mastodon-specific.
    # https://github.com/snarfed/bridgy-fed/issues/33#issuecomment-440965618
    obj_or_activity = obj if isinstance(obj, dict) else activity
    img = obj_or_activity.get('image')
    if img:
        obj_or_activity.setdefault('attachment', []).append(img)

    # cc target's author(s) and recipients
    # https://www.w3.org/TR/activitystreams-vocabulary/#audienceTargeting
    # https://w3c.github.io/activitypub/#delivery
    if target and (type in as2.TYPE_TO_VERB or type in ('Article', 'Note')):
        recips = itertools.chain(*(util.get_list(target, field) for field in
                                 ('actor', 'attributedTo', 'to', 'cc')))
        activity['cc'] = util.dedupe_urls(util.get_url(recip) or recip.get('id')
                                          for recip in recips)

    # to public, since Mastodon interprets to public as public, cc public as unlisted:
    # https://socialhub.activitypub.rocks/t/visibility-to-cc-mapping/284
    # https://wordsmith.social/falkreon/securing-activitypub
    to = activity.setdefault('to', [])
    if as2.PUBLIC_AUDIENCE not in to:
        to.append(as2.PUBLIC_AUDIENCE)

    # wrap articles and notes in a Create activity
    if type in ('Article', 'Note'):
        activity = {
            '@context': as2.CONTEXT,
            'type': 'Create',
            'id': f'{activity["id"]}#bridgy-fed-create',
            'actor': postprocess_as2_actor({}, user),
            'object': activity,
        }

    return util.trim_nulls(activity)


def postprocess_as2_actor(actor, user=None):
    """Prepare an AS2 actor object to be served or sent via ActivityPub.

    Modifies actor in place.

    Args:
      actor: dict, AS2 actor object
      user: :class:`User`

    Returns:
      actor dict
    """
    urls = util.get_list(actor, 'url') or [f'https://{user.key.id()}/']
    domain = util.domain_from_link(urls[0], minimize=False)
    urls[0] = redirect_wrap(urls[0])

    actor.setdefault('id', request.host_url + domain)
    actor.update({
        'url': urls if len(urls) > 1 else urls[0],
        # This has to be the domain for Mastodon interop/Webfinger discovery!
        # See related comment in actor() below.
        'preferredUsername': domain,
    })

    # required by pixelfed. https://github.com/snarfed/bridgy-fed/issues/39
    actor.setdefault('summary', '')
    return actor


def redirect_wrap(url):
    """Returns a URL on our domain that redirects to this URL.

    ...to satisfy Mastodon's non-standard domain matching requirement. :(

    Args:
      url: string

    https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
    https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747

    Returns: string, redirect url
    """
    if not url:
        return url

    prefix = urllib.parse.urljoin(request.host_url, '/r/')
    if url.startswith(prefix):
        return url

    return prefix + url


def redirect_unwrap(val):
    """Removes our redirect wrapping from a URL, if it's there.

    val may be a string, dict, or list. dicts and lists are unwrapped
    recursively.

    Strings that aren't wrapped URLs are left unchanged.

    Args:
      val: string or dict or list

    Returns: string, unwrapped url
    """
    if isinstance(val, dict):
        return {k: redirect_unwrap(v) for k, v in val.items()}

    elif isinstance(val, list):
        return [redirect_unwrap(v) for v in val]

    elif isinstance(val, str):
        prefix = urllib.parse.urljoin(request.host_url, '/r/')
        if val.startswith(prefix):
            unwrapped = val.removeprefix(prefix)
            if util.is_web(unwrapped):
                return util.follow_redirects(unwrapped).url
        elif val.startswith(request.host_url):
            path = val.removeprefix(request.host_url)
            if re.match(DOMAIN_RE, path):
                return util.follow_redirects(path).url

    return val


def actor(domain, user=None):
    """Fetches a home page, converts its representative h-card to AS2 actor.

    Creates a User for the given domain if one doesn't already exist.

    TODO: unify with webfinger.Actor

    Args:
      domain: str
      user: :class:`User`, optional

    Returns: dict, AS2 actor
    """
    tld = domain.split('.')[-1]
    if tld in TLD_BLOCKLIST:
        error('', status=404)

    url = f'https://{domain}/'
    try:
        mf2 = util.fetch_mf2(url, gateway=True)
    except ValueError as e:
        error(f"Couldn't fetch {url}: {e}")

    hcard = mf2util.representative_hcard(mf2, mf2['url'])
    logger.info(f'Representative h-card: {json_dumps(hcard, indent=2)}')
    if not hcard:
        error(f"Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on {mf2['url']}")

    if not user:
        user = User.get_or_create(domain)

    actor = postprocess_as2(
        as2.from_as1(microformats2.json_to_object(hcard)), user=user)
    actor.update({
        'id': f'{request.host_url}{domain}',
        # This has to be the domain for Mastodon etc interop! It seems like it
        # should be the custom username from the acct: u-url in their h-card,
        # but that breaks Mastodon's Webfinger discovery. Background:
        # https://github.com/snarfed/bridgy-fed/issues/302#issuecomment-1324305460
        # https://github.com/snarfed/bridgy-fed/issues/77
        'preferredUsername': domain,
        'inbox': f'{request.host_url}{domain}/inbox',
        'outbox': f'{request.host_url}{domain}/outbox',
        'following': f'{request.host_url}{domain}/following',
        'followers': f'{request.host_url}{domain}/followers',
        'endpoints': {
            'sharedInbox': f'{request.host_url}inbox',
        },
    })

    logger.info(f'Generated AS2 actor: {json_dumps(actor, indent=2)}')
    return actor
