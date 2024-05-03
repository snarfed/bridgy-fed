"""ActivityPub protocol implementation."""
from base64 import b64encode
from hashlib import sha256
import itertools
import logging
import re
from urllib.parse import quote_plus, urljoin, urlparse

from flask import abort, g, redirect, request
from google.cloud import ndb
from google.cloud.ndb.query import FilterNode, OR, Query
from granary import as1, as2
from httpsig import HeaderVerifier
from httpsig.requests_auth import HTTPSignatureAuth
from httpsig.utils import parse_signature_header
from oauth_dropins.webutil import appengine_info, flask_util, util
from oauth_dropins.webutil.util import fragmentless, json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

from flask_app import app, cache
import common
from common import (
    add,
    CACHE_TIME,
    CONTENT_TYPE_HTML,
    DOMAINS,
    DOMAIN_RE,
    error,
    host_url,
    LOCAL_DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    redirect_wrap,
    subdomain_wrap,
    unwrap,
)
from models import fetch_objects, Follower, Object, PROTOCOLS, User
from protocol import Protocol
import webfinger

logger = logging.getLogger(__name__)

CONNEG_HEADERS_AS2_HTML = {
    'Accept': f'{as2.CONNEG_HEADERS["Accept"]}, {CONTENT_TYPE_HTML}; q=0.5'
}

HTTP_SIG_HEADERS = ('Date', 'Host', 'Digest', '(request-target)')

SECURITY_CONTEXT = 'https://w3id.org/security/v1'

# https://seb.jambor.dev/posts/understanding-activitypub-part-4-threads/#the-instance-actor
_INSTANCE_ACTOR = None

# populated in User.status
WEB_OPT_OUT_DOMAINS = None

FEDI_URL_RE = re.compile(r'https://[^/]+/(@|users/)([^/@]+)(@[^/@]+)?(/(?:statuses/)?[0-9]+)?')

# can't use translate_user_id because Web.owns_id checks valid_domain, which
# doesn't allow our protocol subdomains
BOT_ACTOR_IDS = tuple(f'https://{domain}/{domain}' for domain in PROTOCOL_DOMAINS)


def instance_actor():
    global _INSTANCE_ACTOR
    if _INSTANCE_ACTOR is None:
        import web
        _INSTANCE_ACTOR = web.Web.get_or_create(PRIMARY_DOMAIN)
    return _INSTANCE_ACTOR


class ActivityPub(User, Protocol):
    """ActivityPub protocol class.

    Key id is AP/AS2 actor id URL. (*Not* fediverse/WebFinger @-@ handle!)
    """
    ABBREV = 'ap'
    PHRASE = 'the fediverse'
    LOGO_HTML = '<img src="/static/fediverse_logo.svg">'
    CONTENT_TYPE = as2.CONTENT_TYPE_LD_PROFILE
    HAS_FOLLOW_ACCEPTS = True
    DEFAULT_ENABLED_PROTOCOLS = ('web',)

    def _pre_put_hook(self):
        """Validate id, require URL, don't allow Bridgy Fed domains.

        TODO: normalize scheme and domain to lower case. Add that to
        :class:`oauth_dropins.webutil.util.UrlCanonicalizer`\?
        """
        super()._pre_put_hook()
        id = self.key.id()
        assert id
        assert util.is_web(id), f'{id} is not a URL'
        domain = util.domain_from_link(id)
        assert domain, 'missing domain'
        assert not self.is_blocklisted(domain), f'{id} is a blocked domain'

    def web_url(self):
        """Returns this user's web URL aka web_url, eg ``https://foo.com/``."""
        if self.obj and self.obj.as1:
            url = as1.get_url(self.obj.as1)
            if url:
                return url

        return self.key.id()

    @ndb.ComputedProperty
    def handle(self):
        """Returns this user's ActivityPub address, eg ``@user@foo.com``."""
        if self.obj and self.obj.as1:
            addr = as2.address(self.convert(self.obj, from_user=self))
            if addr:
                return addr

        return as2.address(self.key.id())

    @ndb.ComputedProperty
    def status(self):
        """Override :meth:`Model.status` and include Web opted out domains."""
        global WEB_OPT_OUT_DOMAINS
        if WEB_OPT_OUT_DOMAINS is None:
            WEB_OPT_OUT_DOMAINS = {
                key.id() for key in Query(
                    'MagicKey',
                    filters=FilterNode('manual_opt_out', '=', True)
                ).fetch(keys_only=True)
            }
            logger.info(f'Loaded {len(WEB_OPT_OUT_DOMAINS)} manually opted out Web users')

        status = super().status
        if status:
            return status

        return util.domain_or_parent_in(util.domain_from_link(self.key.id()),
                                        WEB_OPT_OUT_DOMAINS)


    @classmethod
    def owns_id(cls, id):
        """Returns None if ``id`` is an http(s) URL, False otherwise.

        All AP ids are http(s) URLs, but not all http(s) URLs are AP ids.

        https://www.w3.org/TR/activitypub/#obj-id

        I used to include a heuristic here that no actor is the root path on its
        host, which was nice because it let us assume that home pages are Web
        users without making any network requests...but then I inevitably ran
        into AP actors that _are_ the root path, eg microblog.pub sites like
        https://bw3.dev/ .

        https://docs.microblog.pub/user_guide.html#activitypub
        """
        if util.is_web(id) and not cls.is_blocklisted(id):
            return None

        return False

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        """Returns True if handle is a WebFinger ``@-@`` handle, False otherwise.

        Example: ``@user@instance.com``. The leading ``@`` is optional.

        https://datatracker.ietf.org/doc/html/rfc7033#section-3.1
        https://datatracker.ietf.org/doc/html/rfc7033#section-4.5
        """
        parts = handle.lstrip('@').split('@')
        if len(parts) != 2:
            return False

        user, domain = parts
        return user and domain and not cls.is_blocklisted(
            domain, allow_internal=allow_internal)

    @classmethod
    def handle_to_id(cls, handle):
        """Looks in the datastore first, then queries WebFinger."""
        assert cls.owns_handle(handle)

        if not handle.startswith('@'):
            handle = '@' + handle

        user = ActivityPub.query(OR(ActivityPub.handle == handle,
                                    ActivityPub.readable_id == handle),
                                 ).get()
        if user:
            return user.key.id()

        return webfinger.fetch_actor_url(handle)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns ``obj``'s or its author's/actor's inbox, if available."""
        if not obj.as1:
            return None

        if obj.type not in as1.ACTOR_TYPES:
            for field in 'actor', 'author', 'attributedTo':
                inner_obj = as1.get_object(obj.as1, field)
                inner_id = inner_obj.get('id') or as1.get_url(inner_obj)
                if (not inner_id
                        or inner_id == obj.as1.get('id')
                        or (obj.key and inner_id == obj.key.id())):
                    continue

                # TODO: need a "soft" kwarg for load to suppress errors?
                actor = cls.load(inner_id)
                if actor and actor.as1:
                    target = cls.target_for(actor)
                    if target:
                        logger.info(f'Target for {obj.key} via {inner_id} is {target}')
                        return target

            logger.info(f'{obj.key} type {obj.type} is not an actor and has no author or actor with inbox')

        actor = ActivityPub.convert(obj)

        if shared:
            shared_inbox = actor.get('endpoints', {}).get('sharedInbox')
            if shared_inbox:
                return shared_inbox

        return actor.get('publicInbox') or actor.get('inbox')

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj=None):
        """Delivers an activity to an inbox URL.

        If ``obj.recipient_obj`` is set, it's interpreted as the receiving actor
        who we're delivering to and its id is populated into ``cc``.
        """
        if to_cls.is_blocklisted(url):
            logger.info(f'Skipping sending to blocklisted {url}')
            return False

        orig_obj = to_cls.convert(orig_obj, from_user=from_user)
        activity = to_cls.convert(obj, from_user=from_user, orig_obj=orig_obj)

        return signed_post(url, data=activity, from_user=from_user).ok

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Tries to fetch an AS2 object.

        Assumes ``obj.id`` is a URL. Any fragment at the end is stripped before
        loading. This is currently underspecified and somewhat inconsistent
        across AP implementations:

        * https://socialhub.activitypub.rocks/t/problems-posting-to-mastodon-inbox/801/11
        * https://socialhub.activitypub.rocks/t/problems-posting-to-mastodon-inbox/801/23
        * https://socialhub.activitypub.rocks/t/s2s-create-activity/1647/5
        * https://github.com/mastodon/mastodon/issues/13879 (open!)
        * https://github.com/w3c/activitypub/issues/224

        Uses HTTP content negotiation via the ``Content-Type`` header. If the
        url is HTML and it has a ``rel-alternate`` link with an AS2 content
        type, fetches and returns that URL.

        Includes an HTTP Signature with the request.

        * https://w3c.github.io/activitypub/#authorization
        * https://tools.ietf.org/html/draft-cavage-http-signatures-07
        * https://github.com/mastodon/mastodon/pull/11269

        Mastodon requires this signature if ``AUTHORIZED_FETCH`` aka secure mode
        is on: https://docs.joinmastodon.org/admin/config/#authorized_fetch

        Signs the request with the current user's key. If not provided, defaults to
        using @snarfed.org@snarfed.org's key.

        See :meth:`protocol.Protocol.fetch` for more details.

        Args:
          obj (models.Object): with the id to fetch. Fills data into the as2
            property.
          kwargs: ignored

        Returns:
          bool: True if the object was fetched and populated successfully,
          False otherwise

        Raises:
          requests.HTTPError:
          werkzeug.exceptions.HTTPException: will have an additional
            ``requests_response`` attribute with the last
            :class:`requests.Response` we received.
        """
        url = obj.key.id()
        if not util.is_web(url):
            logger.info(f'{url} is not a URL')
            return False

        resp = None

        def _error(extra_msg=None):
            msg = f"Couldn't fetch {url} as ActivityStreams 2"
            if extra_msg:
                msg += ': ' + extra_msg
            logger.warning(msg)
            # protocol.for_id depends on us raising this when an AP network
            # fetch fails. if we change that, update for_id too!
            err = BadGateway(msg)
            err.requests_response = resp
            raise err

        def _get(url, headers):
            """Returns None if we fetched and populated, resp otherwise."""
            nonlocal resp

            try:
                resp = signed_get(url, headers=headers, gateway=True)
            except BadGateway as e:
                # ugh, this is ugly, should be something structured
                if '406 Client Error' in str(e):
                    return
                raise

            if not resp.content:
                _error('empty response')
            elif common.content_type(resp) in as2.CONTENT_TYPES:
                try:
                    return resp.json()
                except requests.JSONDecodeError:
                    _error("Couldn't decode as JSON")

        obj.as2 = _get(url, CONNEG_HEADERS_AS2_HTML)

        if obj.as2:
            return True
        elif not resp:
            return False

        # look in HTML to find AS2 link
        if common.content_type(resp) != 'text/html':
            logger.info('no AS2 available')
            return False

        parsed = util.parse_html(resp)
        link = parsed.find('link', rel=('alternate', 'self'), type=(
            as2.CONTENT_TYPE, as2.CONTENT_TYPE_LD))
        if not (link and link['href']):
            logger.info('no AS2 available')
            return False

        obj.as2 = _get(link['href'], as2.CONNEG_HEADERS)
        if obj.as2:
            return True

        return False

    @classmethod
    def convert(cls, obj, orig_obj=None, from_user=None):
        """Convert a :class:`models.Object` to AS2.

        Args:
          obj (models.Object)
          orig_obj (dict): AS2 object, optional. The target of activity's
            ``inReplyTo`` or ``Like``/``Announce``/etc object, if any. Passed
            through to :func:`postprocess_as2`.
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          dict: AS2 JSON
        """
        if not obj or not obj.as1:
            return {}

        from_proto = PROTOCOLS.get(obj.source_protocol)
        user_id = from_user.key.id() if from_user and from_user.key else None
        # TODO: uncomment
        # if from_proto and not from_user.is_enabled(cls):
        #     error(f'{cls.LABEL} <=> {from_proto.LABEL} not enabled')

        if obj.as2:
            return {
                # add back @context since we strip it when we store Objects
                '@context': [as2.CONTEXT, SECURITY_CONTEXT],
                **obj.as2,
            }

        translated = cls.translate_ids(obj.as1)

        # compact actors to just string id for compatibility, since many other
        # AP implementations choke on objects.
        # https://github.com/snarfed/bridgy-fed/issues/658
        #
        # TODO: expand this to general purpose compact() function and use
        # elsewhere, eg in models.resolve_id
        for o in translated, as1.get_object(translated):
            for field in 'actor', 'attributedTo', 'author':
                actors = as1.get_objects(o, field)
                ids = [a['id'] for a in actors if a.get('id')]
                o[field] = ids[0] if len(ids) == 1 else ids

        converted = as2.from_as1(translated)

        if obj.source_protocol in ('ap', 'activitypub'):
            return converted

        # special cases where obj or obj['object'] or obj['object']['object']
        # are an actor
        if from_user:
            if as1.object_type(obj.as1) in as1.ACTOR_TYPES:
                return postprocess_as2_actor(converted, user=from_user)

            inner_obj = as1.get_object(obj.as1)
            if as1.object_type(inner_obj) in as1.ACTOR_TYPES:
                converted['object'] = postprocess_as2_actor(converted['object'],
                                                            user=from_user)

            # eg Accept of a Follow
            if from_user.is_web_url(as1.get_object(inner_obj).get('id')):
                converted['object']['object'] = from_user.id_as(ActivityPub)

        # convert!
        return postprocess_as2(converted, orig_obj=orig_obj)

    @classmethod
    def verify_signature(cls, activity):
        """Verifies the current request's HTTP Signature.

        Raises :class:`werkzeug.exceptions.HTTPError` if the signature is
        missing or invalid, otherwise does nothing and returns the id of the
        actor whose key signed the request.

        Logs details of the result.

        Args:
          activity (dict): AS2 activity

        Returns:
          str: signing AP actor id
        """
        headers = dict(request.headers)  # copy so we can modify below
        sig = headers.get('Signature')
        if not sig:
            if appengine_info.DEBUG:
                logger.info('No HTTP Signature, allowing due to DEBUG=true')
                return
            error('No HTTP Signature', status=401)

        logger.info('Verifying HTTP Signature')
        # logger.info(f'Headers: {json_dumps(headers, indent=2)}')

        # parse_signature_header lower-cases all keys
        sig_fields = parse_signature_header(sig)
        keyId = fragmentless(sig_fields.get('keyid'))
        if not keyId:
            error('HTTP Signature missing keyId', status=401)

        # TODO: right now, assume hs2019 is rsa-sha256. the real answer is...
        # ...complicated and unclear. 🤷
        # https://github.com/snarfed/bridgy-fed/issues/430#issuecomment-1510462267
        # https://arewehs2019yet.vpzom.click/
        # https://socialhub.activitypub.rocks/t/state-of-http-signatures/754/23
        # https://socialhub.activitypub.rocks/t/http-signatures-libraray/2087/2
        # https://github.com/mastodon/mastodon/pull/14556
        if sig_fields.get('algorithm') == 'hs2019':
            headers['Signature'] = headers['Signature'].replace(
                'algorithm="hs2019"', 'algorithm=rsa-sha256')

        digest = headers.get('Digest') or ''
        if not digest:
            error('Missing Digest header, required for HTTP Signature', status=401)

        expected = b64encode(sha256(request.data).digest()).decode()
        if digest.removeprefix('SHA-256=').removeprefix('sha-256=') != expected:
            error('Invalid Digest header, required for HTTP Signature', status=401)

        try:
            key_actor = cls.load(keyId)
        except BadGateway:
            obj_id = as1.get_object(activity).get('id')
            if (activity.get('type') == 'Delete' and obj_id
                    and keyId == fragmentless(obj_id)):
                logger.info('Object/actor being deleted is also keyId')
                key_actor = Object.get_or_create(
                    id=keyId, source_protocol='activitypub', deleted=True)
                key_actor.put()
            else:
                raise

        if key_actor and key_actor.deleted:
            abort(202, f'Ignoring, signer {keyId} is already deleted')
        elif not key_actor or not key_actor.as1:
            error(f"Couldn't load {keyId} to verify signature", status=401)

        # don't ActivityPub.convert since we don't want to postprocess_as2
        key = as2.from_as1(key_actor.as1).get('publicKey', {}).get('publicKeyPem')
        if not key:
            error(f'No public key for {keyId}', status=401)

        # can't use request.full_path because it includes a trailing ? even if
        # it wasn't in the request. https://github.com/pallets/flask/issues/2867
        path_query = request.url.removeprefix(request.host_url.rstrip('/'))
        logger.info(f'Verifying signature for {path_query} with key {key}')
        try:
            verified = HeaderVerifier(headers, key,
                                      required_headers=['Digest'],
                                      method=request.method,
                                      path=path_query,
                                      sign_header='signature',
                                      ).verify()
        except BaseException as e:
            error(f'HTTP Signature verification failed: {e}', status=401)

        if verified:
            logger.info('HTTP Signature verified!')
        else:
            error('HTTP Signature verification failed', status=401)

        return keyId


def signed_get(url, from_user=None, **kwargs):
    return signed_request(util.requests_get, url, from_user=from_user, **kwargs)


def signed_post(url, from_user, **kwargs):
    assert from_user
    return signed_request(util.requests_post, url, from_user=from_user, **kwargs)


def signed_request(fn, url, data=None, headers=None, from_user=None, **kwargs):
    """Wraps ``requests.*`` and adds HTTP Signature.

    Args:
      fn (callable): :func:`util.requests_get` or  :func:`util.requests_post`
      url (str):
      data (dict): optional AS2 object
      from_user (models.User): user to sign request as; optional. If not
        provided, uses the default user ``@snarfed.org@snarfed.org``.
      kwargs: passed through to requests

    Returns:
      requests.Response:
    """
    if headers is None:
        headers = {}

    # prepare HTTP Signature and headers
    if not from_user or isinstance(from_user, ActivityPub):
        # ActivityPub users are remote, so we don't have their keys
        from_user = instance_actor()

    if data:
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
        'Content-Type': as2.CONTENT_TYPE_LD_PROFILE,
        # required for HTTP Signature and Mastodon
        'Digest': f'SHA-256={b64encode(sha256(data or b"").digest()).decode()}',
    }

    logger.info(f"Signing with {from_user.key}'s key")
    # (request-target) is a special HTTP Signatures header that some fediverse
    # implementations require, eg Peertube.
    # https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
    # https://www.w3.org/wiki/SocialCG/ActivityPub/Authentication_Authorization#Signing_requests_using_HTTP_Signatures
    # https://docs.joinmastodon.org/spec/security/#http
    key_id = f'{from_user.id_as(ActivityPub)}#key'
    auth = HTTPSignatureAuth(secret=from_user.private_pem(), key_id=key_id,
                             algorithm='rsa-sha256', sign_header='signature',
                             headers=HTTP_SIG_HEADERS)

    # make HTTP request
    kwargs.setdefault('gateway', True)
    resp = fn(url, data=data, auth=auth, headers=headers, allow_redirects=False,
              **kwargs)
    logger.info(f'Got {resp.status_code} headers: {resp.headers}')

    # handle GET redirects manually so that we generate a new HTTP signature
    if resp.is_redirect and fn == util.requests_get:
        new_url = urljoin(url, resp.headers['Location'])
        return signed_request(fn, new_url, data=data, headers=headers,
                              **kwargs)

    type = common.content_type(resp)
    if (type and type != 'text/html' and
        (type.startswith('text/') or type.endswith('+json')
         or type.endswith('/json'))):
        logger.info(resp.text)

    return resp


def postprocess_as2(activity, orig_obj=None, wrap=True):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    Args:
      activity (dict): AS2 object or activity
      orig_obj (dict): AS2 object, optional. The target of activity's
        ``inReplyTo`` or ``Like``/``Announce``/etc object, if any.
      wrap (bool): whether to wrap ``id``, ``url``, ``object``, ``actor``, and
       ``attributedTo``
    """
    if not activity or isinstance(activity, str):
        return redirect_wrap(activity) if wrap else activity
    elif activity.keys() == {'id'}:
        return redirect_wrap(activity['id']) if wrap else activity['id']

    type = activity.get('type')

    # inReplyTo: singly valued, prefer id over url
    # TODO: ignore orig_obj, do for all inReplyTo
    orig_id = orig_obj.get('id') if orig_obj else None
    in_reply_to = activity.get('inReplyTo')
    if in_reply_to:
        if orig_id:
            activity['inReplyTo'] = orig_id
        elif isinstance(in_reply_to, list):
            if len(in_reply_to) > 1:
                # this isn't actually true, AS2 inReplyTo can be multiply
                # valued. Why do we truncate it to one value? interop somewhere?
                # it's not marked Functional:
                # https://www.w3.org/TR/activitystreams-vocabulary/#dfn-inreplyto
                logger.warning(
                    "AS2 doesn't support multiple inReplyTo URLs! "
                    f'Only using the first: {in_reply_to[0]}')
            activity['inReplyTo'] = in_reply_to[0]

        # Mastodon evidently requires a Mention tag for replies to generate a
        # notification to the original post's author. not required for likes,
        # reposts, etc. details:
        # https://github.com/snarfed/bridgy-fed/issues/34
        if orig_obj:
            for to in (util.get_list(orig_obj, 'attributedTo') +
                       util.get_list(orig_obj, 'author') +
                       util.get_list(orig_obj, 'actor')):
                if isinstance(to, dict):
                    to = util.get_first(to, 'url') or to.get('id')
                if to:
                    add(activity.setdefault('tag', []), {
                        'type': 'Mention',
                        'href': to,
                    })

    # activity objects (for Like, Announce, etc): prefer id over url
    obj = as1.get_object(activity)
    id = obj.get('id')
    if orig_id and type in as2.TYPES_WITH_OBJECT:
        # inline most objects as bare string ids, not composite objects, for interop
        activity['object'] = orig_id
    elif not id:
        obj['id'] = util.get_first(obj, 'url')

    # id is required for most things. default to url if it's not set.
    if not activity.get('id'):
        activity['id'] = util.get_first(activity, 'url')

    if wrap:
        activity['id'] = redirect_wrap(activity.get('id'))
        activity['url'] = [redirect_wrap(u) for u in util.get_list(activity, 'url')]
        if len(activity['url']) == 1:
            activity['url'] = activity['url'][0]

    # TODO: find a better way to check this, sometimes or always?
    # removed for now since it fires on posts without u-id or u-url, eg
    # https://chrisbeckstrom.com/2018/12/27/32551/
    # assert activity.get('id') or (isinstance(obj, dict) and obj.get('id'))

    # drop Link attachments since fediverse instances generate their own link previews
    # https://github.com/snarfed/bridgy-fed/issues/958
    obj_or_activity = obj if obj.keys() > set(['id']) else activity
    obj_or_activity['attachment'] = [
        a for a in as1.get_objects(obj_or_activity, 'attachment')
        if a.get('type') != 'Link']

    # copy image(s) into attachment(s). may be Mastodon-specific.
    # https://github.com/snarfed/bridgy-fed/issues/33#issuecomment-440965618
    imgs = util.get_list(obj_or_activity, 'image')
    if imgs:
        atts = obj_or_activity['attachment']
        atts.extend(img for img in imgs if img not in atts)

    # cc target's author(s), recipients, mentions
    # https://www.w3.org/TR/activitystreams-vocabulary/#audienceTargeting
    # https://w3c.github.io/activitypub/#delivery
    # https://docs.joinmastodon.org/spec/activitypub/#Mention
    obj_or_activity.setdefault('cc', [])

    tags = util.get_list(activity, 'tag') + util.get_list(obj, 'tag')
    for tag in tags:
        href = tag.get('href')
        if (href and tag.get('type') == 'Mention'
                and not ActivityPub.is_blocklisted(href)):
            add(obj_or_activity['cc'], href)

    if orig_obj and type in as2.TYPE_TO_VERB:
        for field in 'actor', 'attributedTo', 'to', 'cc':
            for recip in as1.get_objects(orig_obj, field):
                add(obj_or_activity['cc'], util.get_url(recip) or recip.get('id'))

    # to public, since Mastodon interprets to public as public, cc public as unlisted:
    # https://socialhub.activitypub.rocks/t/visibility-to-cc-mapping/284
    # https://wordsmith.social/falkreon/securing-activitypub
    to = activity.setdefault('to', [])
    add(to, as2.PUBLIC_AUDIENCE)

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
    for tag in tags:
        name = tag.get('name')
        if name and tag.get('type', 'Tag') == 'Tag':
            tag['type'] = 'Hashtag'
            tag.setdefault('href', common.host_url(
                f'hashtag/{quote_plus(name.removeprefix("#"))}'))
            if not name.startswith('#'):
                tag['name'] = f'#{name}'

    # language, in contentMap
    # https://github.com/snarfed/bridgy-fed/issues/681
    if content := obj_or_activity.get('content'):
        obj_or_activity.setdefault('contentMap', {'en': content})

    activity['object'] = [
        postprocess_as2(o, orig_obj=orig_obj,
                        wrap=wrap and type in ('Create', 'Update', 'Delete'))
        for o in as1.get_objects(activity)]
    if len(activity['object']) == 1:
        activity['object'] = activity['object'][0]

    return util.trim_nulls(activity)


def postprocess_as2_actor(actor, user):
    """Prepare an AS2 actor object to be served or sent via ActivityPub.

    Modifies actor in place.

    Args:
      actor (dict): AS2 actor object
      user (models.User): current user

    Returns:
      actor dict
    """
    if not actor:
        return actor

    assert isinstance(actor, dict)
    assert user

    url = user.web_url()
    urls = [u for u in util.get_list(actor, 'url') if u and not u.startswith('acct:')]
    if not urls and url:
        urls = [url]
    if urls:
        urls[0] = redirect_wrap(urls[0])

    id = actor.get('id')
    user_id = user.key.id()
    if not id or user.is_web_url(id) or unwrap(id) in (user_id, f'www.{user_id}'):
        id = actor['id'] = user.id_as(ActivityPub)

    actor['url'] = urls[0] if len(urls) == 1 else urls
    # required by ActivityPub
    # https://www.w3.org/TR/activitypub/#actor-objects
    actor.setdefault('inbox', id + '/inbox')
    actor.setdefault('outbox', id + '/outbox')

    # For web, this has to be domain for Mastodon etc interop! It seems like it
    # should be the custom username from the acct: u-url in their h-card, but
    # that breaks Mastodon's Webfinger discovery.
    # Background:
    # https://docs.joinmastodon.org/spec/activitypub/#properties-used-1
    # https://docs.joinmastodon.org/spec/webfinger/#mastodons-requirements-for-webfinger
    # https://github.com/snarfed/bridgy-fed/issues/302#issuecomment-1324305460
    # https://github.com/snarfed/bridgy-fed/issues/77
    if user.LABEL == 'web':
        actor['preferredUsername'] = user.key.id()
    else:
        handle = user.handle_as(ActivityPub)
        if handle:
            actor['preferredUsername'] = handle.strip('@').split('@')[0]

    # Override the label for their home page to be "Web site"
    for att in util.get_list(actor, 'attachment'):
        if att.get('type') == 'PropertyValue':
            val = att.get('value', '')
            link = util.parse_html(val).find('a')
            if url and url.rstrip('/') in [val.rstrip('/'),
                                           link.get('href').rstrip('/')]:
                att['name'] = 'Web site'

    # required by pixelfed. https://github.com/snarfed/bridgy-fed/issues/39
    actor.setdefault('summary', '')

    if not actor.get('publicKey') and not isinstance(user, ActivityPub):
        # underspecified, inferred from this issue and Mastodon's implementation:
        # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
        # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
        actor.update({
            'publicKey': {
                'id': f'{id}#key',
                'owner': id,
                'publicKeyPem': user.public_pem().decode(),
            },
            '@context': (util.get_list(actor, '@context') + [SECURITY_CONTEXT]),
        })

    if (user.key.id() not in DOMAINS
        and (not user.direct
             # Web users only
             or (user.LABEL == 'web'
                 and not getattr(user, 'last_webmention_in', 'unset')
                 and not getattr(user, 'has_redirects', None)))):
        actor['type'] = 'Application'
        disclaimer = f'[<a href="https://{PRIMARY_DOMAIN}{user.user_page_path()}">bridged</a> from <a href="{user.web_url()}">{user.handle_or_id()}</a> by <a href="https://{PRIMARY_DOMAIN}/">Bridgy Fed</a>]'
        if not actor['summary'].endswith(disclaimer):
            if actor['summary']:
                actor['summary'] += '<br><br>'
            actor['summary'] += disclaimer

    return actor

# source protocol in subdomain.
# WARNING: the user page handler in pages.py overrides this for fediverse
# addresses with leading @ character. be careful when changing this route!
@app.get(f'/ap/<handle_or_id>')
# source protocol in path; primarily for backcompat
@app.get(f'/ap/web/<handle_or_id>')
# special case Web users without /ap/web/ prefix, for backward compatibility
@app.get(f'/<regex("{DOMAIN_RE}"):handle_or_id>')
@flask_util.cached(cache, CACHE_TIME)
def actor(handle_or_id):
    """Serves a user's AS2 actor from the datastore."""
    if handle_or_id == PRIMARY_DOMAIN or handle_or_id in PROTOCOL_DOMAINS:
        from web import Web
        cls = Web
    else:
        cls = Protocol.for_request(fed='web')

    if not cls:
        error(f"Couldn't determine protocol", status=404)
    elif cls.LABEL == 'web' and request.path.startswith('/ap/'):
        # we started out with web users' AP ids as fed.brid.gy/[domain], so we
        # need to preserve those for backward compatibility
        return redirect(subdomain_wrap(None, f'/{handle_or_id}'), code=301)

    if cls.owns_id(handle_or_id) is False:
        if cls.owns_handle(handle_or_id) is False:
            error(f"{handle_or_id} doesn't look like a {cls.LABEL} id or handle",
                  status=404)
        id = cls.handle_to_id(handle_or_id)
        if not id:
            error(f"Couldn't resolve {handle_or_id} as a {cls.LABEL} handle",
                  status=404)
    else:
        id = handle_or_id

    assert id
    user = cls.get_or_create(id)
    if not user or not user.is_enabled(ActivityPub):
        error(f'{cls.LABEL} user {id} not found', status=404)

    id = user.id_as(ActivityPub)
    # check that we're serving from the right subdomain
    if request.host != urlparse(id).netloc:
        return redirect(id)

    if not user.obj or not user.obj.as1:
        user.obj = cls.load(user.profile_id(), gateway=True)
        if user.obj:
            user.obj.put()

    actor = ActivityPub.convert(user.obj, from_user=user) or {
        '@context': [as2.CONTEXT],
        'type': 'Person',
    }
    actor = postprocess_as2_actor(actor, user=user)
    actor.update({
        'id': id,
        'inbox': id + '/inbox',
        'outbox': id + '/outbox',
        'following': id + '/following',
        'followers': id + '/followers',
        'endpoints': {
            'sharedInbox': subdomain_wrap(cls, '/ap/sharedInbox'),
        },
        # add this if we ever change the Web actor ids to be /web/[id]
        # 'alsoKnownAs': [host_url(id)],
    })

    logger.info(f'Returning: {json_dumps(actor, indent=2)}')
    return actor, {
        'Content-Type': as2.CONTENT_TYPE_LD_PROFILE,
        'Access-Control-Allow-Origin': '*',
    }


# note that this shared inbox path overlaps with the /ap/<handle_or_id> actor
# route above, but doesn't collide because this is POST and that one is GET.
@app.post('/ap/sharedInbox')
# source protocol in subdomain
@app.post(f'/ap/<id>/inbox')
# source protocol in path; primarily for backcompat
@app.post(f'/ap/<protocol>/<id>/inbox')
# special case Web users without /ap/web/ prefix, for backward compatibility
@app.post('/inbox')
@app.post(f'/<regex("{DOMAIN_RE}"):id>/inbox')
def inbox(protocol=None, id=None):
    """Handles ActivityPub inbox delivery."""
    # parse and validate AS2 activity
    try:
        activity = request.json
        assert activity and isinstance(activity, dict)
    except (TypeError, ValueError, AssertionError):
        body = request.get_data(as_text=True)
        error(f"Couldn't parse body as non-empty JSON mapping: {body}", exc_info=True)

    type = activity.get('type')
    actor = as1.get_object(activity, 'actor')
    actor_id = actor.get('id')
    logger.info(f'Got {type} from {actor_id}: {json_dumps(activity, indent=2)}')

    if ActivityPub.is_blocklisted(actor_id):
        error(f'Actor {actor_id} is blocklisted')

    authed_as = ActivityPub.verify_signature(activity)

    # check that this activity is public. only do this for creates, not likes,
    # follows, or other activity types, since Mastodon doesn't currently mark
    # those as explicitly public. Use as2's is_public instead of as1's because
    # as1's interprets unlisted as true.
    # TODO: move this to Protocol
    object = as1.get_object(activity)
    to_cc = set(as1.get_ids(object, 'to') + as1.get_ids(activity, 'cc') +
                as1.get_ids(object, 'to') + as1.get_ids(object, 'cc'))
    if (type == 'Create' and not as2.is_public(activity, unlisted=False)
            # DM to one of our protocol bot users
            and not (len(to_cc) == 1 and to_cc.pop() in BOT_ACTOR_IDS)):
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
        follower_url = unwrap(util.get_url(activity, 'actor'))
        followee_url = unwrap(util.get_url(activity, 'object'))
        activity.setdefault('url', f'{follower_url}#followed-{followee_url}')

    obj = Object(id=activity.get('id'), as2=unwrap(activity))
    return ActivityPub.receive(obj, authed_as=authed_as)


# protocol in subdomain
@app.get(f'/ap/<id>/<any(followers,following):collection>')
# source protocol in path; primarily for backcompat
@app.get(f'/ap/web/<regex("{DOMAIN_RE}"):id>/<any(followers,following):collection>')
# special case Web users without /ap/web/ prefix, for backward compatibility
@app.route(f'/<regex("{DOMAIN_RE}"):id>/<any(followers,following):collection>',
           methods=['GET', 'HEAD'])
@flask_util.cached(cache, CACHE_TIME)
def follower_collection(id, collection):
    """ActivityPub Followers and Following collections.

    * https://www.w3.org/TR/activitypub/#followers
    * https://www.w3.org/TR/activitypub/#collections
    * https://www.w3.org/TR/activitystreams-core/#paging

    TODO: unify page generation with outbox()
    """
    if (request.path.startswith('/ap/')
            and request.host in (PRIMARY_DOMAIN,) + LOCAL_DOMAINS):
        # UI request. unfortunate that the URL paths overlap like this!
        import pages
        return pages.followers_or_following('ap', id, collection)

    protocol = Protocol.for_request(fed='web')
    assert protocol
    user = protocol.get_by_id(id)
    if not user:
        return f'{protocol} user {id} not found', 404

    if request.method == 'HEAD':
        return '', {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    # page
    followers, new_before, new_after = Follower.fetch_page(collection, user=user)
    page = {
        'type': 'CollectionPage',
        'partOf': request.base_url,
        'items': util.trim_nulls([ActivityPub.convert(f.user.obj, from_user=f.user)
                                  for f in followers]),
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
        return page, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    # collection
    num_followers, num_following = user.count_followers()
    collection = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.base_url,
        'type': 'Collection',
        'summary': f"{id}'s {collection}",
        'totalItems': num_followers if collection == 'followers' else num_following,
        'first': page,
    }
    logger.info(f'Returning {json_dumps(collection, indent=2)}')
    return collection, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}


# protocol in subdomain
@app.get(f'/ap/<id>/outbox')
# source protocol in path; primarily for backcompat
@app.get(f'/ap/web/<regex("{DOMAIN_RE}"):id>/outbox')
# special case Web users without /ap/web/ prefix, for backward compatibility
@app.route(f'/<regex("{DOMAIN_RE}"):id>/outbox', methods=['GET', 'HEAD'])
@flask_util.cached(cache, CACHE_TIME)
def outbox(id):
    """Serves a user's AP outbox.

    TODO: unify page generation with follower_collection()
    """
    protocol = Protocol.for_request(fed='web')
    if not protocol:
        error(f"Couldn't determine protocol", status=404)

    user = protocol.get_by_id(id)
    if not user:
        error(f'User {id} not found', status=404)

    if request.method == 'HEAD':
        return '', {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    query = Object.query(Object.users == user.key)
    objects, new_before, new_after = fetch_objects(query, by=Object.updated,
                                                   user=user)

    # page
    page = {
        'type': 'CollectionPage',
        'partOf': request.base_url,
        'items': util.trim_nulls([ActivityPub.convert(obj, from_user=user)
                                  for obj in objects]),
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
        return page, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    # collection
    return {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.url,
        'type': 'OrderedCollection',
        'summary': f"{id}'s outbox",
        'totalItems': query.count(),
        'first': page,
    }, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}
