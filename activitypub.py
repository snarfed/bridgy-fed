"""Handles requests for ActivityPub endpoints: actors, inbox, etc.
"""
from base64 import b64encode
from hashlib import sha256
import itertools
import logging
from urllib.parse import quote_plus

from flask import abort, g, request
from granary import as1, as2
from httpsig import HeaderVerifier
from httpsig.requests_auth import HTTPSignatureAuth
from httpsig.utils import parse_signature_header
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.util import fragmentless, json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

from app import app, cache
import common
from common import (
    CACHE_TIME,
    CONTENT_TYPE_HTML,
    error,
    host_url,
    redirect_unwrap,
    redirect_wrap,
    TLD_BLOCKLIST,
)
from models import Follower, Object, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)

CONNEG_HEADERS_AS2_HTML = {
    'Accept': f'{as2.CONNEG_HEADERS["Accept"]}, {CONTENT_TYPE_HTML}; q=0.7'
}

HTTP_SIG_HEADERS = ('Date', 'Host', 'Digest', '(request-target)')

_DEFAULT_SIGNATURE_USER = None

def default_signature_user():
    global _DEFAULT_SIGNATURE_USER
    if _DEFAULT_SIGNATURE_USER is None:
        _DEFAULT_SIGNATURE_USER = User.get_or_create('snarfed.org')
    return _DEFAULT_SIGNATURE_USER


class ActivityPub(Protocol):
    """ActivityPub protocol class."""
    LABEL = 'activitypub'

    @classmethod
    def send(cls, obj, url, log_data=True):
        """Delivers an activity to an inbox URL."""
        # this is set in WebmentionView.try_activitypub()
        target = getattr(obj, 'target_as2', None)

        activity = obj.as2 or postprocess_as2(as2.from_as1(obj.as1), target=target)
        activity['actor'] = g.user.actor_id()
        return signed_post(url, log_data=True, data=activity)
        # TODO: return bool or otherwise unify return value with others

    @classmethod
    def fetch(cls, id):
        """Tries to fetch an AS2 object.

        Uses HTTP content negotiation via the Content-Type header. If the url is
        HTML and it has a rel-alternate link with an AS2 content type, fetches and
        returns that URL.

        Includes an HTTP Signature with the request.
        https://w3c.github.io/activitypub/#authorization
        https://tools.ietf.org/html/draft-cavage-http-signatures-07
        https://github.com/mastodon/mastodon/pull/11269

        Mastodon requires this signature if AUTHORIZED_FETCH aka secure mode is on:
        https://docs.joinmastodon.org/admin/config/#authorized_fetch

        Signs the request with the current user's key. If not provided, defaults to
        using @snarfed.org@snarfed.org's key.

        Args:
          id: str, object's URL id

        Returns:
          obj: :class:`Object` with the fetched object

        Raises:
          :class:`requests.HTTPError`, :class:`werkzeug.exceptions.HTTPException`

          If we raise a werkzeug HTTPException, it will have an additional
          requests_response attribute with the last requests.Response we received.
        """
        resp = None

        def _error(extra_msg=None):
            msg = f"Couldn't fetch {id} as ActivityStreams 2"
            if extra_msg:
                msg += ': ' + extra_msg
            logger.warning(msg)
            err = BadGateway(msg)
            err.requests_response = resp
            raise err

        def _get(url, headers):
            """Returns None if we fetched and populated, resp otherwise."""
            nonlocal resp
            resp = signed_get(url, headers=headers, gateway=True)
            if not resp.content:
                _error('empty response')
            elif common.content_type(resp) == as2.CONTENT_TYPE:
                try:
                    as2_json = resp.json()
                except requests.JSONDecodeError:
                    _error("Couldn't decode as JSON")
                obj = Object.get_by_id(id)
                if obj:
                    orig_as1 = obj.as1
                    obj.clear()
                    obj.as2 = as2_json
                    obj.changed = as1.activity_changed(orig_as1, obj.as1)
                    obj.new = False
                else:
                    obj = Object(id=id, as2=as2_json)
                    obj.new = True
                return obj

        obj = _get(id, CONNEG_HEADERS_AS2_HTML)
        if obj:
            return obj

        # look in HTML to find AS2 link
        if common.content_type(resp) != 'text/html':
            _error('no AS2 available')
        parsed = util.parse_html(resp)
        link = parsed.find('link', rel=('alternate', 'self'), type=(
            as2.CONTENT_TYPE, as2.CONTENT_TYPE_LD))
        if not (link and link['href']):
            _error('no AS2 available')

        obj = _get(link['href'], as2.CONNEG_HEADERS)
        if obj:
            return obj

        _error()

    @classmethod
    def verify_signature(cls, activity):
        """Verifies the current request's HTTP Signature.

        Args:
          activity: dict, AS2 activity

        Logs details of the result. Raises :class:`werkzeug.HTTPError` if the
        signature is missing or invalid, otherwise does nothing and returns None.
        """
        sig = request.headers.get('Signature')
        if not sig:
            error('No HTTP Signature', status=401)

        logging.info('Verifying HTTP Signature')
        logger.info(f'Headers: {json_dumps(dict(request.headers), indent=2)}')

        # parse_signature_header lower-cases all keys
        keyId = fragmentless(parse_signature_header(sig).get('keyid'))
        if not keyId:
            error('HTTP Signature missing keyId', status=401)

        digest = request.headers.get('Digest') or ''
        if not digest:
            error('Missing Digest header, required for HTTP Signature', status=401)

        expected = b64encode(sha256(request.data).digest()).decode()
        if digest.removeprefix('SHA-256=') != expected:
            error('Invalid Digest header, required for HTTP Signature', status=401)

        try:
            key_actor = cls.load(keyId)
        except BadGateway:
            obj_id = as1.get_object(activity).get('id')
            if (activity.get('type') == 'Delete' and obj_id and
                keyId == fragmentless(obj_id)):
                logging.info('Object/actor being deleted is also keyId')
                key_actor = Object(id=keyId, source_protocol='activitypub', deleted=True)
                key_actor.put()
            else:
                raise

        if key_actor.deleted:
            abort(202, f'Ignoring, signer {keyId} is already deleted')

        key = key_actor.as2.get("publicKey", {}).get('publicKeyPem')
        logger.info(f'Verifying signature for {request.path} with key {key}')
        try:
            verified = HeaderVerifier(request.headers, key,
                                      required_headers=['Digest'],
                                      method=request.method,
                                      path=request.path,
                                      sign_header='signature').verify()
        except BaseException as e:
            error(f'HTTP Signature verification failed: {e}', status=401)

        if verified:
            logger.info('HTTP Signature verified!')
        else:
            error('HTTP Signature verification failed', status=401)


def signed_get(url, **kwargs):
    return signed_request(util.requests_get, url, **kwargs)


def signed_post(url, **kwargs):
    assert g.user
    return signed_request(util.requests_post, url, **kwargs)


def signed_request(fn, url, data=None, log_data=True, headers=None, **kwargs):
    """Wraps requests.* and adds HTTP Signature.

    If the current session has a user (ie in g.user), signs with that user's
    key. Otherwise, uses the default user snarfed.org.

    Args:
      fn: :func:`util.requests_get` or  :func:`util.requests_get`
      url: str
      data: optional AS2 object
      log_data: boolean, whether to log full data object
      kwargs: passed through to requests

    Returns: :class:`requests.Response`
    """
    if headers is None:
        headers = {}

    # prepare HTTP Signature and headers
    user = g.user or default_signature_user()

    if data:
        if log_data:
            logger.info(f'Sending AS2 object: {json_dumps(data, indent=2)}')
        data = json_dumps(data).encode()

    headers = {
        **headers,
        # required for HTTP Signature
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
        'Date': util.now().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        # required by Mastodon
        # https://github.com/tootsuite/mastodon/pull/14556#issuecomment-674077648
        'Host': util.domain_from_link(url, minimize=False),
        'Content-Type': as2.CONTENT_TYPE,
        # required for HTTP Signature and Mastodon
        'Digest': f'SHA-256={b64encode(sha256(data or b"").digest()).decode()}',
    }

    logger.info(f"Signing with {user}'s key")
    # (request-target) is a special HTTP Signatures header that some fediverse
    # implementations require, eg Peertube.
    # https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
    # https://github.com/snarfed/bridgy-fed/issues/40
    auth = HTTPSignatureAuth(secret=user.private_pem(), key_id=user.actor_id(),
                             algorithm='rsa-sha256', sign_header='signature',
                             headers=HTTP_SIG_HEADERS)

    # make HTTP request
    kwargs.setdefault('gateway', True)
    resp = fn(url, data=data, auth=auth, headers=headers, allow_redirects=False,
              **kwargs)
    logger.info(f'Got {resp.status_code} headers: {resp.headers}')

    # handle GET redirects manually so that we generate a new HTTP signature
    if resp.is_redirect and fn == util.requests_get:
      return signed_request(fn, resp.headers['Location'], data=data,
                            headers=headers, log_data=log_data, **kwargs)

    type = common.content_type(resp)
    if (type and type != 'text/html' and
        (type.startswith('text/') or type.endswith('+json') or type.endswith('/json'))):
        logger.info(resp.text)

    return resp


def postprocess_as2(activity, target=None):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    g.user is required. Populates it into the actor.id and publicKey fields.

    Args:
      activity: dict, AS2 object or activity
      target: dict, AS2 object, optional. The target of activity's inReplyTo or
        Like/Announce/etc object, if any.
    """
    if not activity or isinstance(activity, str):
        return activity

    assert g.user
    type = activity.get('type')

    # actor objects
    if type == 'Person':
        postprocess_as2_actor(activity)
        if not activity.get('publicKey'):
            # underspecified, inferred from this issue and Mastodon's implementation:
            # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
            # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
            actor_url = host_url(activity.get('preferredUsername'))
            activity.update({
                'publicKey': {
                    'id': actor_url,
                    'owner': actor_url,
                    'publicKeyPem': g.user.public_pem().decode(),
                },
                '@context': (util.get_list(activity, '@context') +
                             ['https://w3id.org/security/v1']),
            })
        return activity

    for field in 'actor', 'attributedTo':
        activity[field] = [postprocess_as2_actor(actor)
                           for actor in util.get_list(activity, field)]
        if len(activity[field]) == 1:
            activity[field] = activity[field][0]

    # inReplyTo: singly valued, prefer id over url
    # TODO: ignore target, do for all inReplyTo
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
    obj = as1.get_object(activity)
    id = obj.get('id')
    if not id:
        obj['id'] = util.get_first(obj, 'url') or target_id
    elif target_id and id != target_id:
        activity['object'] = target_id
    elif g.user.is_homepage(id):
        obj['id'] = g.user.actor_id()

    # for Accepts
    if g.user.is_homepage(obj.get('object')):
        obj['object'] = g.user.actor_id()

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
    obj_or_activity = obj if obj.keys() > set(['id']) else activity
    imgs = util.get_list(obj_or_activity, 'image')
    atts = obj_or_activity.setdefault('attachment', [])
    if imgs:
        atts.extend(img for img in imgs if img not in atts)

    # cc target's author(s) and recipients
    # https://www.w3.org/TR/activitystreams-vocabulary/#audienceTargeting
    # https://w3c.github.io/activitypub/#delivery
    if target and type in as2.TYPE_TO_VERB:
        recips = itertools.chain(*(util.get_list(target, field) for field in
                                 ('actor', 'attributedTo', 'to', 'cc')))
        obj_or_activity['cc'] = sorted(util.dedupe_urls(
            util.get_url(recip) or recip.get('id') for recip in recips))

    # to public, since Mastodon interprets to public as public, cc public as unlisted:
    # https://socialhub.activitypub.rocks/t/visibility-to-cc-mapping/284
    # https://wordsmith.social/falkreon/securing-activitypub
    to = activity.setdefault('to', [])
    if as2.PUBLIC_AUDIENCE not in to:
        to.append(as2.PUBLIC_AUDIENCE)

    # hashtags. Mastodon requires:
    # * type: Hashtag
    # * name starts with #
    # * href is set to a valid, fully qualified URL
    #
    # If content has an <a> tag with a fully qualified URL and the hashtag name
    # (with leading #) as its text, Mastodon will rewrite its href to the local
    # instance's search for that hashtag. If content doesn't have a link for a
    # given hashtag, Mastodon won't add one, but that hashtag will still be
    # indexed in search.
    #
    # https://docs.joinmastodon.org/spec/activitypub/#properties-used
    # https://github.com/snarfed/bridgy-fed/issues/45
    for tag in util.get_list(activity, 'tag') + util.get_list(obj, 'tag'):
        name = tag.get('name')
        if name and tag.get('type', 'Tag') == 'Tag':
            tag['type'] = 'Hashtag'
            tag.setdefault('href', common.host_url(
                f'hashtag/{quote_plus(name.removeprefix("#"))}'))
            if not name.startswith('#'):
                tag['name'] = f'#{name}'

    activity['object'] = postprocess_as2(activity.get('object'), target=target)

    return util.trim_nulls(activity)


def postprocess_as2_actor(actor):
    """Prepare an AS2 actor object to be served or sent via ActivityPub.

    Modifies actor in place.

    Args:
      actor: dict, AS2 actor object

    Returns:
      actor dict
    """
    if not actor or isinstance(actor, str):
        return g.user.actor_id() if g.user.is_homepage(actor) else actor

    url = g.user.homepage if g.user else None
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


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>')
@flask_util.cached(cache, CACHE_TIME)
def actor(domain):
    """Serves a user's AS2 actor from the datastore."""
    tld = domain.split('.')[-1]
    if tld in TLD_BLOCKLIST:
        error('', status=404)

    g.user = User.get_by_id(domain)
    if not g.user:
        return f'User {domain} not found', 404
    elif not g.user.actor_as2:
        return f'User {domain} not fully set up', 404

    # TODO: unify with common.actor()
    actor = postprocess_as2(g.user.actor_as2)
    actor.update({
        'id': g.user.actor_id(),
        # This has to be the domain for Mastodon etc interop! It seems like it
        # should be the custom username from the acct: u-url in their h-card,
        # but that breaks Mastodon's Webfinger discovery. Background:
        # https://docs.joinmastodon.org/spec/activitypub/#properties-used-1
        # https://docs.joinmastodon.org/spec/webfinger/#mastodons-requirements-for-webfinger
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

    logger.info(f'Returning: {json_dumps(actor, indent=2)}')
    return actor, {
        'Content-Type': as2.CONTENT_TYPE,
        'Access-Control-Allow-Origin': '*',
    }


@app.post('/inbox')
@app.post(f'/<regex("{common.DOMAIN_RE}"):domain>/inbox')
def inbox(domain=None):
    """Handles ActivityPub inbox delivery."""
    # parse and validate AS2 activity
    try:
        activity = request.json
        assert activity and isinstance(activity, dict)
    except (TypeError, ValueError, AssertionError):
        body = request.get_data(as_text=True)
        error(f"Couldn't parse body as non-empty JSON mapping: {body}", exc_info=True)

    type = activity.get('type')
    actor_id = as1.get_object(activity, 'actor').get('id')
    logger.info(f'Got {type} from {actor_id}: {json_dumps(activity, indent=2)}')

    # load user
    if domain:
        g.user = User.get_by_id(domain)
        if not g.user:
            error(f'User {domain} not found', status=404)

    ActivityPub.verify_signature(activity)

    # check that this activity is public. only do this for creates, not likes,
    # follows, or other activity types, since Mastodon doesn't currently mark
    # those as explicitly public. Use as2's is_public instead of as1's because
    # as1's interprets unlisted as true.
    if type == 'Create' and not as2.is_public(activity):
        logger.info('Dropping non-public activity')
        return 'OK'

    if type == 'Follow':
        # rendered mf2 HTML proxy pages (in render.py) fall back to redirecting
        # to the follow's AS2 id field, but Mastodon's Accept ids are URLs that
        # don't load in browsers, eg:
        # https://jawns.club/ac33c547-ca6b-4351-80d5-d11a6879a7b0
        #
        # so, set a synthetic URL based on the follower's profile.
        # https://github.com/snarfed/bridgy-fed/issues/336
        follower_url = redirect_unwrap(util.get_url(activity, 'actor'))
        followee_url = redirect_unwrap(util.get_url(activity, 'object'))
        activity.setdefault('url', f'{follower_url}#followed-{followee_url}')

    return ActivityPub.receive(activity.get('id'), as2=redirect_unwrap(activity))


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/<any(followers,following):collection>')
@flask_util.cached(cache, CACHE_TIME)
def follower_collection(domain, collection):
    """ActivityPub Followers and Following collections.

    https://www.w3.org/TR/activitypub/#followers
    https://www.w3.org/TR/activitypub/#collections
    https://www.w3.org/TR/activitystreams-core/#paging
    """
    if not User.get_by_id(domain):
        return f'User {domain} not found', 404

    # page
    followers, new_before, new_after = Follower.fetch_page(domain, collection)
    items = []
    for f in followers:
        f_as2 = f.to_as2()
        if f_as2:
            items.append(f_as2)

    page = {
        'type': 'CollectionPage',
        'partOf': request.base_url,
        'items': items,
    }
    if new_before:
        page['next'] = f'{request.base_url}?before={new_before}'
    if new_after:
        page['prev'] = f'{request.base_url}?after={new_after}'

    if 'before' in request.args or 'after' in request.args:
        page.update({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': request.url,
        })
        logger.info(f'Returning {json_dumps(page, indent=2)}')
        return page, {'Content-Type': as2.CONTENT_TYPE}

    # collection
    domain_prop = Follower.dest if collection == 'followers' else Follower.src
    count = Follower.query(
        Follower.status == 'active',
        domain_prop == domain,
    ).count()

    collection = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.base_url,
        'type': 'Collection',
        'summary': f"{domain}'s {collection}",
        'totalItems': count,
        'first': page,
    }
    logger.info(f'Returning {json_dumps(collection, indent=2)}')
    return collection, {'Content-Type': as2.CONTENT_TYPE}


@app.get(f'/<regex("{common.DOMAIN_RE}"):domain>/outbox')
def outbox(domain):
    url = common.host_url(f"{domain}/outbox")
    return {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': url,
            'summary': f"{domain}'s outbox",
            'type': 'OrderedCollection',
            'totalItems': 0,
            'first': {
                'type': 'CollectionPage',
                'partOf': url,
                'items': [],
            },
        }, {'Content-Type': as2.CONTENT_TYPE}
