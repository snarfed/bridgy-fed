# coding=utf-8
"""Misc common utilities.
"""
from base64 import b64encode
import copy
from datetime import timedelta, timezone
from hashlib import sha256
import itertools
import logging
import os
import re
import urllib.parse

from flask import request
from granary import as1, as2, microformats2
from httpsig.requests_auth import HTTPSignatureAuth
import mf2util
from oauth_dropins.webutil import util, webmention
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

from models import Follower, Object, Target, User

logger = logging.getLogger(__name__)

DOMAIN_RE = r'[^/:]+\.[^/:]+'
ACCT_RE = f'(?:acct:)?([^@]+)@({DOMAIN_RE})'
TLD_BLOCKLIST = ('7z', 'asp', 'aspx', 'gif', 'html', 'ico', 'jpg', 'jpeg', 'js',
                 'json', 'php', 'png', 'rar', 'txt', 'yaml', 'yml', 'zip')
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
LINK_HEADER_RE = re.compile(r""" *< *([^ >]+) *> *; *rel=['"]([^'"]+)['"] *""")

CONTENT_TYPE_LD_PLAIN = 'application/ld+json'
CONTENT_TYPE_HTML = 'text/html; charset=utf-8'

CONNEG_HEADERS_AS2_HTML = copy.deepcopy(as2.CONNEG_HEADERS)
CONNEG_HEADERS_AS2_HTML['Accept'] += f', {CONTENT_TYPE_HTML}; q=0.7'

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
    'bridgy-federated.uc.r.appspot.com',
)
LOCAL_DOMAINS = (
  'localhost',
  'localhost:8080',
  'my.dev.com:8080',
)
DOMAINS = (PRIMARY_DOMAIN,) + OTHER_DOMAINS + LOCAL_DOMAINS
# TODO: unify with Bridgy's
DOMAIN_BLOCKLIST = frozenset((
    # https://github.com/snarfed/bridgy-fed/issues/348
    'aaronparecki.com',
    'facebook.com',
    'fb.com',
    't.co',
    'twitter.com',
) + DOMAINS)

_DEFAULT_SIGNATURE_USER = None

CACHE_TIME = timedelta(seconds=60)
PAGE_SIZE = 20


def host_url(path_query=None):
  base = request.host_url
  if (util.domain_or_parent_in(request.host, OTHER_DOMAINS) or
      # when running locally against prod datastore
      (not DEBUG and request.host in LOCAL_DOMAINS)):
    base = f'https://{PRIMARY_DOMAIN}'

  return urllib.parse.urljoin(base, path_query)


def default_signature_user():
    global _DEFAULT_SIGNATURE_USER
    if _DEFAULT_SIGNATURE_USER is None:
        _DEFAULT_SIGNATURE_USER = User.get_or_create('snarfed.org')
    return _DEFAULT_SIGNATURE_USER


def pretty_link(url, text=None, user=None):
  """Wrapper around util.pretty_link() that converts Mastodon user URLs to @-@.

  Eg for URLs like https://mastodon.social/@foo and
  https://mastodon.social/users/foo, defaults text to @foo@mastodon.social if
  it's not provided.

  Args:
    url: str
    text: str
    user: :class:`User`, optional, user for the current request
  """
  if user and re.match(f'https?://{user.key.id()}/?$', url.strip('/')):
    return user.user_page_link()

  if text is None:
    match = re.match(r'https?://([^/]+)/(@|users/)([^/]+)$', url)
    if match:
      text = match.expand(r'@\3@\1')

  return util.pretty_link(url, text=text)


def signed_get(url, user, **kwargs):
    return signed_request(util.requests_get, url, user, **kwargs)


def signed_post(url, user, **kwargs):
    assert user
    return signed_request(util.requests_post, url, user, **kwargs)


def signed_request(fn, url, user, data=None, log_data=True, headers=None, **kwargs):
    """Wraps requests.* and adds HTTP Signature.

    Args:
      fn: :func:`util.requests_get` or  :func:`util.requests_get`
      url: str
      user: :class:`User` to sign request with
      data: optional AS2 object
      log_data: boolean, whether to log full data object
      kwargs: passed through to requests

    Returns: :class:`requests.Response`
    """
    if headers is None:
        headers = {}

    # prepare HTTP Signature and headers
    if not user:
        user = default_signature_user()

    if data:
        if log_data:
            logging.info(f'Sending AS2 object: {json_dumps(data, indent=2)}')
        data = json_dumps(data).encode()

    headers = copy.deepcopy(headers)
    headers.update({
        # required for HTTP Signature
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
        'Date': util.now().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        # required by Mastodon
        # https://github.com/tootsuite/mastodon/pull/14556#issuecomment-674077648
        'Host': util.domain_from_link(url, minimize=False),
        'Content-Type': as2.CONTENT_TYPE,
        # required for HTTP Signature and Mastodon
        'Digest': f'SHA-256={b64encode(sha256(data or b"").digest()).decode()}',
    })

    domain = user.key.id()
    logger.info(f"Signing with {domain}'s key")
    key_id = host_url(domain)
    # (request-target) is a special HTTP Signatures header that some fediverse
    # implementations require, eg Peertube.
    # https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
    # https://github.com/snarfed/bridgy-fed/issues/40
    auth = HTTPSignatureAuth(
      secret=user.private_pem(), key_id=key_id, algorithm='rsa-sha256',
      sign_header='signature',
      headers=('Date', 'Host', 'Digest', '(request-target)'))

    # make HTTP request
    kwargs.setdefault('gateway', True)
    resp = fn(url, data=data, auth=auth, headers=headers, allow_redirects=False,
              **kwargs)
    logger.info(f'Got {resp.status_code} headers: {resp.headers}')

    # handle GET redirects manually so that we generate a new HTTP signature
    if resp.is_redirect and fn == util.requests_get:
      return signed_request(fn, resp.headers['Location'], data=data, user=user,
                            headers=headers, log_data=log_data, **kwargs)

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
        msg = f"Couldn't fetch {url} as ActivityStreams 2"
        logger.warning(msg)
        err = BadGateway(msg)
        err.requests_response = resp
        raise err

    resp = signed_get(url, user=user, headers=CONNEG_HEADERS_AS2_HTML)
    if content_type(resp) in (as2.CONTENT_TYPE, CONTENT_TYPE_LD_PLAIN):
        return resp

    parsed = util.parse_html(resp)
    obj = parsed.find('link', rel=('alternate', 'self'), type=(
        as2.CONTENT_TYPE, as2.CONTENT_TYPE_LD))
    if not (obj and obj['href']):
        _error(resp)

    resp = signed_get(urllib.parse.urljoin(resp.url, obj['href']),
                      user=user, headers=as2.CONNEG_HEADERS)
    if content_type(resp) in (as2.CONTENT_TYPE, CONTENT_TYPE_LD_PLAIN):
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


def send_webmentions(activity_wrapped, proxy=None, **object_props):
    """Sends webmentions for an incoming ActivityPub inbox delivery.
    Args:
      activity_wrapped: dict, AS1 activity
      object_props: passed through to the newly created Object entities

    Returns: boolean, True if any webmentions were sent, False otherwise
    """
    activity = redirect_unwrap(activity_wrapped)

    verb = activity.get('verb')
    if verb and verb not in SUPPORTED_VERBS:
        error(f'{verb} activities are not supported yet.', status=501)

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
            if url and url.startswith(host_url()):
                targets.append(redirect_unwrap(url))

    if verb in ('follow', 'like', 'share'):
        targets.append(obj_url)

    targets = util.dedupe_urls(util.get_url(t) for t in targets)
    targets = remove_blocklisted(t.lower() for t in targets)
    if not targets:
        logger.info("Couldn't find any IndieWeb target URLs in inReplyTo, object, or mention tags")
        return False

    logger.info(f'targets: {targets}')

    # send webmentions and store Objects
    errors = []  # stores (code, body) tuples
    domains = []
    targets = [Target(uri=uri, protocol='activitypub') for uri in targets]

    obj = Object(id=source, labels=['notification'], undelivered=targets,
                 status='in progress', **object_props)
    if activity.get('objectType') == 'activity':
      obj.labels.append('activity')
    obj.put()

    for target in targets:
        domain = util.domain_from_link(target.uri, minimize=False)
        if domain == util.domain_from_link(source, minimize=False):
            logger.info(f'Skipping same-domain webmention from {source} to {target.uri}')
            continue

        if domain not in obj.domains:
          obj.domains.append(domain)
        wm_source = (obj.proxy_url()
                     if verb in ('follow', 'like', 'share') or proxy
                     else source)
        logger.info(f'Sending webmention from {wm_source} to {target.uri}')

        try:
            endpoint = webmention.discover(target.uri).endpoint
            if endpoint:
                webmention.send(endpoint, wm_source, target.uri)
                logger.info('Success!')
                obj.delivered.append(target)
            else:
                logger.info('No webmention endpoint')
        except BaseException as e:
          code, body = util.interpret_http_exception(e)
          if not code and not body:
            raise
          errors.append((code, body))
          obj.failed.append(target)

        obj.undelivered.remove(target)
        obj.put()

    obj.status = 'complete' if obj.delivered else 'failed' if obj.failed else 'ignored'
    obj.put()

    if errors:
        msg = 'Errors: ' + ', '.join(f'{code} {body}' for code, body in errors)
        error(msg, status=int(errors[0][0] or 502))

    return True


def postprocess_as2(activity, user=None, target=None, create=True):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    Args:
      activity: dict, AS2 object or activity
      user: :class:`User`, required. populated into actor.id and
        publicKey fields if needed.
      target: dict, AS2 object, optional. The target of activity's inReplyTo or
        Like/Announce/etc object, if any.
      create: boolean, whether to wrap `Note` and `Article` objects in a
        `Create` activity
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
            actor_url = host_url(activity.get('preferredUsername'))
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
                    f'Only using the first: {in_reply_to[0]}')
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
    img = util.get_list(obj_or_activity, 'image')
    if img:
        obj_or_activity.setdefault('attachment', []).extend(img)

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
    if create and type in ('Article', 'Note'):
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
    url = f'https://{user.key.id()}/' if user else None
    urls = util.get_list(actor, 'url')
    if not urls and url:
      urls = [url]

    domain = util.domain_from_link(urls[0], minimize=False)
    urls[0] = redirect_wrap(urls[0])

    actor.setdefault('id', host_url(domain))
    actor.update({
        'url': urls if len(urls) > 1 else urls[0],
        # This has to be the domain for Mastodon interop/Webfinger discovery!
        # See related comment in actor() below.
        'preferredUsername': domain,
    })

    # Override the label for their home page to be "Web site"
    for att in util.get_list(actor, 'attachment'):
      if att.get('type') == 'PropertyValue':
        val = att.get('value', '')
        link = util.parse_html(val).find('a')
        if url and (val == url or link.get('href') == url):
          att['name'] = 'Web site'

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

    prefix = host_url('/r/')
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
        prefix = host_url('/r/')
        if val.startswith(prefix):
            unwrapped = val.removeprefix(prefix)
            if util.is_web(unwrapped):
                return util.follow_redirects(unwrapped).url
        elif val.startswith(host_url()):
            path = val.removeprefix(host_url())
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

    Returns: (dict mf2 item, dict AS1 actor, dict AS2 actor, User)
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

    actor_as1 = microformats2.json_to_object(hcard, rel_urls=mf2.get('rel-urls'))
    actor_as2 = postprocess_as2(as2.from_as1(actor_as1), user=user)
    actor_as2.update({
        'id': host_url(domain),
        # This has to be the domain for Mastodon etc interop! It seems like it
        # should be the custom username from the acct: u-url in their h-card,
        # but that breaks Mastodon's Webfinger discovery. Background:
        # https://github.com/snarfed/bridgy-fed/issues/302#issuecomment-1324305460
        # https://github.com/snarfed/bridgy-fed/issues/77
        'preferredUsername': domain,
        'inbox': host_url(f'{domain}/inbox'),
        'outbox': host_url(f'{domain}/outbox'),
        'following': host_url(f'{domain}/following'),
        'followers': host_url(f'{domain}/followers'),
        'endpoints': {
            'sharedInbox': host_url('inbox'),
        },
    })

    logger.info(f'Generated AS2 actor: {json_dumps(actor_as2, indent=2)}')
    return hcard, actor_as1, actor_as2, user


def fetch_followers(domain, collection):
    """Fetches a page of Follower entities.

    Wraps :func:`common.fetch_page`. Paging uses the `before` and `after` query
    parameters, if available in the request.

    Args:
      domain: str, user to fetch entities for
      collection, str, 'followers' or 'following'

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of Follower entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    assert collection in ('followers', 'following'), collection

    domain_prop = Follower.dest if collection == 'followers' else Follower.src
    query = Follower.query(
        Follower.status == 'active',
        domain_prop == domain,
    ).order(-Follower.updated)
    return fetch_page(query, Follower)


def fetch_page(query, model_class):
    """Fetches a page of results from a datastore query.

    Uses the `before` and `after` query params (if provided; should be ISO8601
    timestamps) and the queried model class's `updated` property to identify the
    page to fetch.

    Populates a `log_url_path` property on each result entity that points to a
    its most recent logged request.

    Args:
      query: :class:`ndb.Query`
      model_class: ndb model class

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of query result entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    # if there's a paging param ('before' or 'after'), update query with it
    # TODO: unify this with Bridgy's user page
    def get_paging_param(param):
        val = request.values.get(param)
        if val:
            try:
                dt = util.parse_iso8601(val.replace(' ', '+'))
            except BaseException as e:
                error(f"Couldn't parse {param}, {val!r} as ISO8601: {e}")
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt

    before = get_paging_param('before')
    after = get_paging_param('after')
    if before and after:
        error("can't handle both before and after")
    elif after:
        query = query.filter(model_class.updated >= after).order(model_class.updated)
    elif before:
        query = query.filter(model_class.updated < before).order(-model_class.updated)
    else:
        query = query.order(-model_class.updated)

    query_iter = query.iter()
    results = sorted(itertools.islice(query_iter, 0, PAGE_SIZE),
                     key=lambda r: r.updated, reverse=True)

    # calculate new paging param(s)
    has_next = results and query_iter.probably_has_next()
    new_after = (
        before if before
        else results[0].updated if has_next and after
        else None)
    if new_after:
        new_after = new_after.isoformat()

    new_before = (
        after if after else
        results[-1].updated if has_next
        else None)
    if new_before:
        new_before = new_before.isoformat()

    return results, new_before, new_after
