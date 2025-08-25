"""ActivityPub protocol implementation."""
from base64 import b64encode
import copy
import datetime
from hashlib import sha256
import itertools
import logging
import os
import re
from urllib.parse import quote_plus, urljoin, urlparse
from unittest.mock import MagicMock

from flask import abort, g, redirect, request
from google.cloud import ndb
from google.cloud.ndb.query import FilterNode, OR, Query
from granary import as1, as2
from httpsig import HeaderVerifier
from httpsig.requests_auth import HTTPSignatureAuth
from httpsig.utils import parse_signature_header
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
import oauth_dropins.threads
from oauth_dropins.webutil import appengine_info, flask_util, util
from oauth_dropins.webutil.flask_util import FlashErrors, MovedPermanently
from oauth_dropins.webutil.util import add, fragmentless, json_dumps, json_loads
import requests
from requests import TooManyRedirects
from requests.models import DEFAULT_REDIRECT_LIMIT
from werkzeug.exceptions import BadGateway

from flask_app import app
import common
from common import (
    CACHE_CONTROL,
    CACHE_CONTROL_VARY_ACCEPT,
    CONTENT_TYPE_HTML,
    create_task,
    DOMAINS,
    DOMAIN_RE,
    error,
    FlashErrors,
    host_url,
    LOCAL_DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    redirect_wrap,
    report_error,
    subdomain_wrap,
    unwrap,
)
import ids
import memcache
from models import fetch_objects, Follower, Object, PROTOCOLS, User
from protocol import activity_id_memcache_key, DELETE_TASK_DELAY, Protocol
from ui import UIProtocol
import webfinger

logger = logging.getLogger(__name__)

CONNEG_HEADERS_AS2_HTML = {
    'Accept': f'{as2.CONNEG_HEADERS["Accept"]}, {CONTENT_TYPE_HTML}; q=0.5'
}

HTTP_SIG_HEADERS = ('Date', 'Host', 'Digest', '(request-target)')

SECURITY_CONTEXT = 'https://w3id.org/security/v1'

# https://www.w3.org/ns/activitystreams#did-core
# https://docs.joinmastodon.org/spec/activitypub/#properties-used-1
AKA_CONTEXT = {'alsoKnownAs': {'@id': 'as:alsoKnownAs', '@type': '@id'}}

# https://seb.jambor.dev/posts/understanding-activitypub-part-4-threads/#the-instance-actor
_INSTANCE_ACTOR = None

OLD_ACCOUNT_EXEMPT_DOMAINS = (
    'channel.org',
    'mo-me.social',
    'newsmast.community',
    'pixelfed.social',
)

# we can't yet authorize activities from these domains:
# * a.gup.pe groups sign with the group's actor but use the external author as
#   actor and attributedTo, and don't include an LD Sig
#   https://github.com/snarfed/bridgy-fed/issues/566#issuecomment-2130714037
NO_AUTH_DOMAINS = (
    'a.gup.pe',
)

FEDI_URL_RE = re.compile(r'https://[^/]+/(@|users/)([^/@]+)(@[^/@]+)?(/(?:statuses/)?[0-9]+)?')


def instance_actor():
    global _INSTANCE_ACTOR

    if _INSTANCE_ACTOR is None:
        import web
        _INSTANCE_ACTOR = web.Web.get_or_create(PRIMARY_DOMAIN)
        assert _INSTANCE_ACTOR

    return _INSTANCE_ACTOR


class ActivityPub(User, Protocol):
    """ActivityPub protocol class.

    Key id is AP/AS2 actor id URL. (*Not* fediverse/WebFinger @-@ handle!)
    """
    ABBREV = 'ap'
    ''
    PHRASE = 'the fediverse'
    ''
    LOGO_EMOJI = '⁂'
    ''
    LOGO_HTML = '<img src="/static/fediverse_logo.svg">'
    ''
    CONTENT_TYPE = as2.CONTENT_TYPE_LD_PROFILE
    ''
    REQUIRES_NAME = False
    ''
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    ''
    SUPPORTED_AS1_TYPES = (
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + tuple(as1.VERBS_WITH_OBJECT)
        + ('audio', 'bookmark', 'image', 'move', 'video')
    )
    ''
    SUPPORTED_AS2_TYPES = tuple(
        as2.OBJECT_TYPE_TO_TYPE.get(t) or as2.VERB_TO_TYPE.get(t)
        for t in SUPPORTED_AS1_TYPES)
    ''
    SUPPORTS_DMS = True
    ''
    SEND_REPLIES_TO_ORIG_POSTS_MENTIONS = True
    'https://github.com/snarfed/bridgy-fed/issues/1608 , https://github.com/snarfed/bridgy-fed/issues/1218'
    HTML_PROFILES = True
    ''

    webfinger_addr = ndb.StringProperty()
    """Populated by :meth:`reload_profile`."""

    @property
    def REQUIRES_AVATAR(self):
        ''
        return not util.domain_or_parent_in(self.key.id(), ids.ATPROTO_HANDLE_DOMAINS)

    @property
    def REQUIRES_OLD_ACCOUNT(self):
        ''
        return not util.domain_or_parent_in(
            self.key.id(), OLD_ACCOUNT_EXEMPT_DOMAINS + ids.ATPROTO_HANDLE_DOMAINS)

    def _pre_put_hook(self):
        r"""Validate id, require URL, don't allow Bridgy Fed domains.

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
        if self.webfinger_addr:
            assert self.webfinger_addr.startswith('@')
            return self.webfinger_addr

        if self.obj and self.obj.as1:
            addr = as2.address(self._convert(self.obj, from_user=self))
            if addr:
                return addr

        return as2.address(self.key.id())

    @ndb.ComputedProperty
    def status(self):
        if self.obj and self.obj.as2 and as2.is_server_actor(self.obj.as2):
            return None

        return super().status

    def reload_profile(self, **kwargs):
        """Reloads this user's AP actor, then resolves their webfinger subject.

        1. load AP actor
        2. fetch Webfinger with preferredUsername
        3. re-fetch Webfinger with subject from first Webfinger

        https://www.w3.org/community/reports/socialcg/CG-FINAL-apwf-20240608/#reverse-discovery
        https://correct.webfinger-canary.fietkau.software/#developers
        """
        super().reload_profile(**kwargs)

        self.webfinger_addr = None
        if self.handle:
            if profile := webfinger.fetch(self.handle):
                if subject := profile.get('subject'):
                    addr = subject.removeprefix('acct:')
                    if profile := webfinger.fetch(addr):
                        if subject == profile.get('subject'):
                            logger.info(f'resolved webfinger subject to {subject}')
                            if not addr.startswith('@'):
                                addr = '@' + addr
                            self.webfinger_addr = addr
                            self.put()

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
        if (handle and handle[0] == '@'
                and cls.is_user_at_domain(handle[1:], allow_internal=allow_internal)):
            return True

        return False

    @classmethod
    def handle_to_id(cls, handle):
        """Looks in the datastore first, then queries WebFinger."""
        assert cls.owns_handle(handle)

        if not handle.startswith('@'):
            handle = '@' + handle

        user = ActivityPub.query(ActivityPub.handle == handle).get()
        if user:
            return user.key.id()

        return webfinger.fetch_actor_url(handle)

    def user_page_path(self, rest=None, **kwargs):
        """Always prefer handle, since id is a full URL."""
        kwargs['prefer_id'] = False
        return super().user_page_path(rest=rest, **kwargs)

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

                actor = cls.load(inner_id, raise_=False)
                if actor and actor.as1:
                    target = cls.target_for(actor, shared=shared)
                    if target:
                        logger.info(f'Target for {obj.key} via {inner_id} is {target}')
                        return target

            logger.info(f'{obj.key} type {obj.type} is not an actor and has no author or actor with inbox')

        if not (actor := cls._convert(obj)):
            return None

        if shared:
            shared_inbox = (actor.get('endpoints') or {}).get('sharedInbox')
            if shared_inbox:
                return shared_inbox

        return actor.get('publicInbox') or actor.get('inbox')

    @classmethod
    def send(to_cls, obj, inbox_url, from_user=None, orig_obj_id=None):
        """Delivers an activity to an inbox URL.

        If ``obj.recipient_obj`` is set, it's interpreted as the receiving actor
        who we're delivering to and its id is populated into ``cc``.
        """
        if not from_user:
            logger.info('Skipping sending, no from_user!')
            return False
        elif to_cls.is_blocklisted(inbox_url):
            logger.info(f'Skipping sending to blocklisted {inbox_url}')
            return False

        orig_obj = None
        if orig_obj_id:
            orig_obj = to_cls.convert(Object.get_by_id(orig_obj_id),
                                      from_user=from_user)
        activity = to_cls.convert(obj, from_user=from_user, orig_obj=orig_obj)

        return signed_post(inbox_url, data=activity, from_user=from_user).ok

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

        resp, obj.as2 = cls._get(url, headers=CONNEG_HEADERS_AS2_HTML)
        if obj.as2:
            return True
        elif not resp:
            return False

        # look in HTML to find AS2 link
        if common.content_type(resp) != 'text/html':
            logger.debug('no AS2 available')
            return False

        parsed = util.parse_html(resp)
        link = parsed.find('link', rel=('alternate', 'self'), type=(
            as2.CONTENT_TYPE, as2.CONTENT_TYPE_LD))
        if not (link and link['href']):
            logger.debug('no AS2 available')
            return False

        _, obj.as2 = cls._get(link['href'])
        if not obj.as2:
            return False

        return True

    @classmethod
    def _get(cls, url, headers=as2.CONNEG_HEADERS):
        """Fetches a URL as AS2.

        Args:
          url (str)
          headers (dict)

        Returns:
          (requests.Response, dict JSON response body or None) tuple:
        """
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

        resp = None
        try:
            resp = signed_get(url, headers=headers, gateway=True)
        except BadGateway as e:
            # ugh, this is ugly, should be something structured
            if '406 Client Error' in str(e):
                return resp, None
            raise

        if not resp.content:
            _error('empty response')
        elif common.content_type(resp) in as2.CONTENT_TYPES:
            try:
                obj = resp.json()
            except requests.JSONDecodeError:
                _error("Couldn't decode as JSON")
            if not isinstance(obj, dict):
                logger.warning(f'Got non-object: {obj}')
                return resp, None

            cls._hydrate(obj)
            return resp, obj

        return resp, None

    @classmethod
    def _hydrate(cls, obj):
        """Hydrates compacted values in ``obj``, in place.

        Very minimal and incomplete! Right now only handles the ``featured``
        collection in actors.

        Args:
          obj (dict)
        """
        if util.get_first(obj, 'type') in as2.ACTOR_TYPES:
            if feat := as1.get_object(obj, 'featured'):
                if set(feat.keys()) == {'id'}:
                    # fetch collection
                    _, obj['featured'] = cls._get(feat['id'])

    @classmethod
    def _convert(cls, obj, orig_obj=None, from_user=None):
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

        # TODO: uncomment
        # from_proto = PROTOCOLS.get(obj.source_protocol)
        # if from_proto and not from_user.is_enabled(cls):
        #     error(f'{cls.LABEL} <=> {from_proto.LABEL} not enabled')

        if obj.as2:
            return {
                # add back @context since we strip it when we store Objects
                '@context': as2.CONTEXT + [SECURITY_CONTEXT],
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
        converted = postprocess_as2(converted, orig_obj=orig_obj)

        # FEP-fffd proxy link
        # https://codeberg.org/fediverse/fep/src/branch/main/fep/fffd/fep-fffd.md
        # https://github.com/snarfed/bridgy-fed/issues/543
        if (obj.source_protocol not in (None, 'activitypub')
                and obj.type not in as1.CRUD_VERBS and obj.key and obj.key.id()
                and not cls.is_blocklisted(obj.key.id())):
            canonical = {
                'type': 'Link',
                'rel': 'canonical',
                'href': obj.key.id(),
            }
            converted['url'] = util.get_list(converted, 'url')
            util.add(converted['url'], canonical)

        return converted

    @classmethod
    def migrate_out(cls, user, to_user_id):
        """Migrates a bridged account out to be a native account.

        * https://www.manton.org/2022/12/02/moving-from-mastodon.html
        * https://docs.joinmastodon.org/user/moving/#migration
        * https://www.w3.org/TR/activitystreams-vocabulary/#dfn-move

        Args:
          user (models.User)
          to_user_id (str)

        Raises:
          ValueError: eg if ``ActivityPub`` doesn't own ``to_user_id``
        """
        user_ap_id = user.id_as(cls)
        logger.info(f"Migrating {user.key.id()} 's bridged AP actor {user_ap_id} to {to_user_id}")

        cls.check_can_migrate_out(user, to_user_id)

        # send a Move activity to all followers' inboxes
        id = f'{user_ap_id}#move-{to_user_id}'
        move = Object(id=id, as2={
            'type': 'Move',
            'id': id,
            'actor': user_ap_id,
            'object': user_ap_id,
            'target': to_user_id,
            'to': [as2.PUBLIC_AUDIENCE],
        })
        move.put()
        logger.info(f'Delivering to AP followers: {move.as2}')
        ret = user.deliver(move, from_user=user, to_proto=cls)

        # set the bridged actor's alsoKnownAs, movedTo
        user.obj.our_as1 = copy.deepcopy(user.obj.as1)
        user.obj.our_as1['movedTo'] = to_user_id
        util.add(user.obj.our_as1.setdefault('alsoKnownAs', []), to_user_id)
        user.obj.put()

        return ret

    @classmethod
    def check_can_migrate_out(cls, user, to_user_id):
        """Raises an exception if a user can't yet migrate to a native AP account.

        For example, if ``to_user_id`` isn't an ActivityPub actor id, or if it
        doesn't have ``user``'s bridged AP id in its ``alsoKnownAs``.

        Args:
          user (models.User)
          to_user_id (str)

        Raises:
          ValueError: if ``user`` can't migrate to ActivityPub or ``to_user_id`` yet
        """
        super().check_can_migrate_out(user, to_user_id)

        # check that the destination actor has an alias to the bridged actor
        if not (to_actor := cls.load(to_user_id, remote=True)):
            raise ValueError("Couldn't fetch {to_user_id}")

        aka = util.get_list(to_actor.as2, 'alsoKnownAs')
        user_ap_id = user.id_as(cls)
        if user_ap_id not in aka:
            msg = f"{to_user_id} 's alsoKnownAs doesn't contain {user_ap_id}: {aka}"
            logger.warning(msg)
            raise ValueError(msg)

    @classmethod
    def verify_signature(cls, activity):
        """Verifies the current request's HTTP Signature.

        Raises :class:`werkzeug.exceptions.HTTPError` if the signature is
        missing or invalid, otherwise does nothing and returns the id of the
        actor whose key signed the request.

        Logs details of the result.

        https://swicg.github.io/activitypub-http-signature/

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

        logger.debug('Verifying HTTP Signature')
        logger.debug(f'Headers: {json_dumps(headers, indent=2)}')

        # parse_signature_header lower-cases all keys
        sig_fields = parse_signature_header(sig)
        key_id = fragmentless(sig_fields.get('keyid'))
        if not key_id:
            error('sig missing keyId', status=401)

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
            error('Missing Digest', status=401)

        expected = b64encode(sha256(request.data).digest()).decode()
        if digest.removeprefix('SHA-256=').removeprefix('sha-256=') != expected:
            error('Invalid Digest', status=401)

        try:
            key_actor = cls._load_key(key_id)
        except BadGateway:
            obj_id = as1.get_object(activity).get('id')
            if (activity.get('type') == 'Delete' and obj_id
                    and key_id == fragmentless(obj_id)):
                logger.debug('Object/actor being deleted is also keyId')
                key_actor = Object.get_or_create(
                    id=key_id, authed_as=key_id, source_protocol='activitypub',
                    deleted=True)
            else:
                raise

        if key_actor and key_actor.deleted:
            abort(202, f'Ignoring, signer {key_id} is already deleted')
        elif not key_actor or not key_actor.as1:
            error(f"Couldn't load {key_id} to verify signature", status=401)

        # don't ActivityPub.convert since we don't want to postprocess_as2
        key = as2.from_as1(key_actor.as1).get('publicKey', {}).get('publicKeyPem')
        if not key:
            error(f'No public key for {key_id}', status=401)

        # can't use request.full_path because it includes a trailing ? even if
        # it wasn't in the request. https://github.com/pallets/flask/issues/2867
        path_query = request.url.removeprefix(request.host_url.rstrip('/'))
        logger.debug(f'Verifying signature for {path_query} with key {sig_fields["keyid"]}')
        try:
            verified = HeaderVerifier(headers, key,
                                      required_headers=['Digest'],
                                      method=request.method,
                                      path=path_query,
                                      sign_header='signature',
                                      ).verify()
        except BaseException as e:
            error(f'sig verification failed: {e}', status=401)

        if verified:
            logger.debug('sig ok')
        else:
            error('sig failed', status=401)

        return key_actor.key.id()

    @classmethod
    def _load_key(cls, key_id, follow_owner=True):
        """Loads the ActivityPub actor for a given ``keyId``.

        https://swicg.github.io/activitypub-http-signature/#how-to-obtain-a-signature-s-public-key
        Args:
          key_id (str): ``keyId`` from an HTTP Signature
          follow_owner (bool): whether to follow ``owner``/``controller`` fields

        Returns:
          Object or None:

        Raises:
          requests.HTTPError:
        """
        assert '#' not in key_id
        # TODO: we don't currently handle when this raises InvalidURL, see error
        # below, but I can't reproduce it, when I mock request.get to return
        # InvalidURL in test_inbox_verify_sig_fetch_key_fails, we return 400
        # instead of crashing :/
        # https://console.cloud.google.com/errors/detail/COLzgISI47vpMg?project=bridgy-federated
        actor = cls.load(key_id)
        if not actor:
            return None

        if follow_owner and actor.as1:
            actor_as2 = as2.from_as1(actor.as1)
            key = actor_as2.get('publicKey', {})
            owner = key.get('controller') or key.get('owner')
            if not owner and actor.type not in as1.ACTOR_TYPES:
                owner = actor_as2.get('controller') or actor_as2.get('owner')

            if owner:
                owner = fragmentless(owner)
                if owner != key_id:
                    logger.debug(f'keyId {key_id} has controller/owner {owner}, fetching that')
                    return cls._load_key(owner, follow_owner=False)

        return actor


def signed_get(url, from_user=None, **kwargs):
    return signed_request(util.requests_get, url, from_user=from_user, **kwargs)


def signed_post(url, from_user, **kwargs):
    assert from_user
    return signed_request(util.requests_post, url, from_user=from_user, **kwargs)


def signed_request(fn, url, data=None, headers=None, from_user=None,
                   _redirect_count=None, **kwargs):
    """Wraps ``requests.*`` and adds HTTP Signature.

    https://swicg.github.io/activitypub-http-signature/

    Args:
      fn (callable): :func:`util.requests_get` or  :func:`util.requests_post`
      url (str):
      data (dict): optional AS2 object
      from_user (models.User): user to sign request as; optional. If not
        provided, uses the default user ``@fed.brid.gy@fed.brid.gy``.
      _redirect_count: internal, used to count redirects followed so far
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
        logger.debug(f'Sending AS2 object: {json_dumps(data, indent=2)}')
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

    logger.debug(f"Signing with {from_user.key.id()} 's key")

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

    if fn == util.requests_get:
        assert not isinstance(resp, MagicMock), \
            f'unit test missing a mock HTTP response for {url}'

    # handle GET redirects manually so that we generate a new HTTP signature
    if resp.is_redirect and fn == util.requests_get:
        new_url = urljoin(url, resp.headers['Location'])
        if _redirect_count is None:
            _redirect_count = 0
        elif _redirect_count > DEFAULT_REDIRECT_LIMIT:
            raise TooManyRedirects(response=resp)

        return signed_request(fn, new_url, data=data, from_user=from_user,
                              headers=headers, _redirect_count=_redirect_count + 1,
                              **kwargs)

    type = common.content_type(resp)
    if (type and type != 'text/html' and
        (type.startswith('text/') or type.endswith('+json')
         or type.endswith('/json'))):
        logger.debug(resp.text)

    return resp


def postprocess_as2(activity, orig_obj=None, wrap=True):
    """Prepare an AS2 object to be served or sent via ActivityPub.

    TODO: get rid of orig_obj! https://github.com/snarfed/bridgy-fed/issues/1257

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
    in_reply_to = util.get_list(activity, 'inReplyTo')
    if in_reply_to:
        if orig_id:  # TODO: and orig_id in in_reply_to ...or get rid of orig_obj
            activity['inReplyTo'] = orig_id
        elif len(in_reply_to) > 1:
            # AS2 inReplyTo can be multiply valued, it's not marked Functional:
            # https://www.w3.org/TR/activitystreaams-vocabulary/#dfn-inreplyto
            # ...but most fediverse projects don't support that:
            # https://funfedi.dev/support_tables/generated/in_reply_to/
            logger.warning(
                "AS2 doesn't support multiple inReplyTo URLs! "
                f'Only using the first: {in_reply_to[0]}')
            activity['inReplyTo'] = in_reply_to[0]

        # Mastodon evidently requires a Mention tag for replies to generate a
        # notification to the original post's author. also include the original
        # post's own Mention tags to notify other people involved in the thread.
        # not required for likes, reposts, etc.
        # https://github.com/snarfed/bridgy-fed/issues/34
        # https://github.com/snarfed/bridgy-fed/issues/1608
        if orig_obj and ActivityPub.owns_id(orig_id) is not False:
            orig_mentions = [t.get('href') for t in as1.get_objects(orig_obj, 'tag')
                             if t.get('type') == 'Mention']
            for to in (util.get_list(orig_obj, 'attributedTo') +
                       util.get_list(orig_obj, 'author') +
                       util.get_list(orig_obj, 'actor') +
                       orig_mentions):
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
    if orig_id and type in as2.TYPES_WITH_OBJECT and type != 'Undo':
        # inline most objects as bare string ids, not composite objects, for interop
        activity['object'] = orig_id
    elif not id:
        obj['id'] = util.get_first(obj, 'url')

    # id is required for most things. default to url if it's not set.
    if not activity.get('id'):
        activity['id'] = util.get_first(activity, 'url')

    if wrap:
        # some fediverse servers (eg Misskey) require activity id and actor id
        # to be on the same domain
        # https://github.com/snarfed/bridgy-fed/issues/1093#issuecomment-2299247639
        redirect_domain = util.domain_from_link(as1.get_id(activity, 'actor'))
        if redirect_domain not in DOMAINS:
            redirect_domain = None
        activity['id'] = redirect_wrap(activity.get('id'), domain=redirect_domain)
        activity['url'] = [redirect_wrap(u) for u in util.get_list(activity, 'url')]
        if len(activity['url']) == 1:
            activity['url'] = activity['url'][0]

    # TODO: find a better way to check this, sometimes or always?
    # removed for now since it fires on posts without u-id or u-url, eg
    # https://chrisbeckstrom.com/2018/12/27/32551/
    # assert activity.get('id') or (isinstance(obj, dict) and obj.get('id'))

    obj_or_activity = obj if obj.keys() > set(['id']) else activity

    # move Link attachments to links in text since fediverse instances generate
    # their own link previews.
    # https://github.com/snarfed/bridgy-fed/issues/958
    atts = util.pop_list(obj_or_activity, 'attachment')
    obj_or_activity['attachment'] = [a for a in atts if a.get('type') != 'Link']
    link_atts = [a for a in atts if a.get('type') == 'Link']

    content = obj_or_activity.get('content', '')
    for link in link_atts:
        for url in util.get_list(link, 'href'):
            if content:
                content += '<br><br>'
            content += util.pretty_link(url, text=link.get('name'))

    if content:
        as2.set_content(obj_or_activity, content)

    # copy image(s) into attachment(s). may be Mastodon-specific.
    # https://github.com/snarfed/bridgy-fed/issues/33#issuecomment-440965618
    imgs = util.get_list(obj_or_activity, 'image')
    if imgs:
        atts = obj_or_activity['attachment']
        for img in imgs:
            if isinstance(img, str):
                img = {'url': img}
            add(atts, img)

    # determine whether this is a DM *before* we modify the cc field, below
    #
    # WARNING: activity and obj here are AS2, but we're using as1.is_dm. right now
    # the logic is effectively the same for our purposes, but watch out here if that
    # ever changes.
    if not as1.is_dm(activity):
        # to public, since Mastodon interprets to public as public, cc public as
        # unlisted:
        # https://socialhub.activitypub.rocks/t/visibility-to-cc-mapping/284
        # https://wordsmith.social/falkreon/securing-activitypub
        add(activity.setdefault('to', []), as2.PUBLIC_AUDIENCE)
        if obj and type in as2.CRUD_VERBS:
            add(obj.setdefault('to', []), as2.PUBLIC_AUDIENCE)

    # cc target's author(s), recipients, mentions
    # https://www.w3.org/TR/activitystreams-vocabulary/#audienceTargeting
    # https://w3c.github.io/activitypub/#delivery
    # https://docs.joinmastodon.org/spec/activitypub/#Mention
    cc = obj_or_activity.setdefault('cc', [])

    tags = util.get_list(activity, 'tag') + util.get_list(obj, 'tag')
    for tag in tags:
        href = tag.get('href')
        if (tag.get('type') == 'Mention'
                and href
                and href not in util.get_list(obj_or_activity, 'to')
                and not ActivityPub.is_blocklisted(href)):
            add(cc, href)

    if orig_obj and type in as2.TYPE_TO_VERB:
        for field in 'actor', 'attributedTo', 'to', 'cc':
            for recip in as1.get_objects(orig_obj, field):
                add(cc, util.get_url(recip) or recip.get('id'))

    # for some activities, Pleroma (and Akkoma?) seem to crash if the activity's
    # to and cc aren't exactly the same as the object's. (I think?)
    # https://indieweb.social/@diego@lounge.collabfc.com/112977955332152430
    # https://git.pleroma.social/pleroma/pleroma/-/issues/3206#note_108296
    # https://github.com/snarfed/bridgy-fed/issues/12#issuecomment-2302776658
    if type in ('Create', 'Update'):
        activity['to'] = util.get_list(obj, 'to')
        activity['cc'] = util.get_list(obj, 'cc')

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
            url_path = f'/hashtag/{quote_plus(name.removeprefix("#"))}'
            tag.setdefault('href', urljoin(activity['id'], url_path))
            if not name.startswith('#'):
                tag['name'] = f'#{name}'

    as2.link_tags(obj_or_activity)

    activity['object'] = [
        postprocess_as2(o, orig_obj=orig_obj,
                        wrap=wrap and type in ('Create', 'Update', 'Delete'))
        for o in as1.get_objects(activity)]
    if len(activity['object']) == 1:
        activity['object'] = activity['object'][0]

    if content := obj_or_activity.get('content'):
        # language, in contentMap
        # https://github.com/snarfed/bridgy-fed/issues/681
        obj_or_activity.setdefault('contentMap', {'en': content})

        # wrap in <p>. some fediverse servers (eg Mastodon) have a white-space:
        # pre-wrap style that applies to p inside content. this preserves
        # meaningful whitespace in plain text content.
        # https://github.com/snarfed/bridgy-fed/issues/990
        if not content.startswith('<p>'):
            as2.set_content(obj_or_activity, f'<p>{content}</p>')

    activity.pop('content_is_html', None)
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
    if not id or user.is_web_url(id) or unwrap(id) in (
            user_id, user.profile_id(), f'www.{user_id}'):
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
            if url and link and url.rstrip('/') in [val.rstrip('/'),
                                                    link.get('href').rstrip('/')]:
                att['name'] = 'Web site'

    # required by pixelfed
    #
    # https://github.com/snarfed/bridgy-fed/issues/1893
    actor.setdefault('manuallyApprovesFollowers', False)
    # https://github.com/snarfed/bridgy-fed/issues/39
    actor.setdefault('summary', '')

    if not actor.get('publicKey') and not isinstance(user, ActivityPub):
        # underspecified, inferred from this issue and Mastodon's implementation:
        # https://github.com/w3c/activitypub/issues/203#issuecomment-297553229
        # https://github.com/tootsuite/mastodon/blob/bc2c263504e584e154384ecc2d804aeb1afb1ba3/app/services/activitypub/process_account_service.rb#L77
        actor['publicKey'] = {
            'id': f'{id}#key',
            'owner': id,
            'publicKeyPem': user.public_pem().decode(),
        }
        actor['@context'] = util.get_list(actor, '@context')
        add(actor['@context'], SECURITY_CONTEXT)

    # TODO: bring back once we figure out how to get Mastodon to support this and
    # Pleroma and Akkoma not to DDoS us
    # https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    #
    # featured collection, pinned posts
    if featured := actor.get('featured'):
        featured.setdefault('id', id + '/featured')

    return actor


def _load_user(handle_or_id, create=False):
    if handle_or_id == PRIMARY_DOMAIN or handle_or_id in PROTOCOL_DOMAINS:
        from web import Web
        proto = Web
    else:
        proto = Protocol.for_request(fed='web')

    if not proto:
        error(f"Couldn't determine protocol", status=404)

    if proto.owns_id(handle_or_id) is False:
        if proto.owns_handle(handle_or_id) is False:
            error(f"{handle_or_id} doesn't look like a {proto.LABEL} id or handle",
                  status=404)
        id = proto.handle_to_id(handle_or_id)
        if not id:
            error(f"Couldn't resolve {handle_or_id} as a {proto.LABEL} handle",
                  status=404)
    else:
        id = handle_or_id

    assert id
    try:
        user = proto.get_or_create(id) if create else proto.get_by_id(id)
    except ValueError as e:
        logging.warning(e)
        user = None

    if not user or not user.is_enabled(ActivityPub):
        error(f'{proto.LABEL} user {id} not found', status=404)

    return user


# source protocol in subdomain.
# WARNING: the user page handler in pages.py overrides this for fediverse
# addresses with leading @ character. be careful when changing this route!
@app.get(f'/ap/<handle_or_id>')
# special case Web users on fed.brid.gy subdomain without /ap/web/ prefix, for
# backward compatibility
@app.get(f'/<regex("{DOMAIN_RE}"):handle_or_id>')
@flask_util.headers(CACHE_CONTROL_VARY_ACCEPT)
def actor(handle_or_id):
    """Serves a user's AS2 actor from the datastore."""
    user = _load_user(handle_or_id, create=True)
    proto = user

    as2_type = common.as2_request_type()
    if not as2_type:
        return redirect(user.web_url(), code=302)

    if proto.LABEL == 'web' and request.path.startswith('/ap/'):
        # we started out with web users' AP ids as fed.brid.gy/[domain], so we
        # need to preserve those for backward compatibility
        raise MovedPermanently(location=subdomain_wrap(None, f'/{handle_or_id}'))

    id = user.id_as(ActivityPub)
    # check that we're serving from the right subdomain
    if request.host != urlparse(id).netloc:
        raise MovedPermanently(location=id)

    actor = ActivityPub.convert(user.obj, from_user=user) or {
        '@context': as2.CONTEXT,
        'type': 'Person',
    }
    actor = postprocess_as2_actor(actor, user=user)

    actor['@context'] = util.get_list(actor, '@context')
    add(actor['@context'], AKA_CONTEXT)
    actor.setdefault('alsoKnownAs', [user.id_uri()])

    actor.update({
        'id': id,
        'inbox': id + '/inbox',
        'outbox': id + '/outbox',
        'following': id + '/following',
        'followers': id + '/followers',
        'endpoints': {
            'sharedInbox': urljoin(id, '/ap/sharedInbox'),
        },
    })

    logger.debug(f'Returning: {json_dumps(actor, indent=2)}')
    return actor, {
        'Content-Type': as2_type,
        'Access-Control-Allow-Origin': '*',
    }


# note that this shared inbox path overlaps with the /ap/<handle_or_id> actor
# route above, but doesn't collide because this is POST and that one is GET.
@app.post('/ap/sharedInbox')
# source protocol in subdomain
@app.post(f'/ap/<id>/inbox')
# source protocol in path; primarily for backcompat
@app.post(f'/ap/<protocol>/<id>/inbox')
# special case Web users on fed subdomain without /ap/web/ prefix
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

    # do we support this object type?
    # (this logic is duplicated in Protocol.check_supported)
    obj = as1.get_object(activity)
    inner_type = obj.get('type')
    if type := activity.get('type'):
        if (type not in ActivityPub.SUPPORTED_AS2_TYPES or
            (type in as2.CRUD_VERBS
             and inner_type
             and inner_type not in ActivityPub.SUPPORTED_AS2_TYPES)):
            error(f"Bridgy Fed for ActivityPub doesn't support {type} {inner_type} yet: {json_dumps(activity, indent=2)}", status=204)

    # check actor, authz actor's domain against activity and object ids
    # https://github.com/snarfed/bridgy-fed/security/advisories/GHSA-37r7-jqmr-3472
    actor = (as1.get_object(activity, 'actor')
             or as1.get_object(activity, 'attributedTo'))
    actor_id = actor.get('id')

    if ActivityPub.is_blocklisted(actor_id):
        error(f'Actor {actor_id} is blocklisted')

    actor_domain = util.domain_from_link(actor_id)
    # temporary, see emails w/Michael et al, and
    # https://github.com/snarfed/bridgy-fed/issues/1686
    if actor_domain == 'newsmast.community' and type == 'Undo':
        return ':(', 204

    id = activity.get('id')
    obj_id = obj.get('id')
    if id and actor_domain != util.domain_from_link(id):
        report_error(f'Auth: actor and activity on different domains: {json_dumps(activity, indent=2)}',
                     user=f'actor {actor_id} activity {id}')
        return f'actor {actor_id} and activity {id} on different domains', 403
    elif (type in as2.CRUD_VERBS and obj_id
          and actor_domain != util.domain_from_link(obj_id)):
        report_error(f'Auth: actor and object on different domains {json_dumps(activity, indent=2)}',
                     user=f'actor {actor_id} object {obj_id}')
        return f'actor {actor_id} and object {obj_id} on different domains', 403

    # are we already processing or done with this activity?
    if id:
        domain = util.domain_from_link(id)
        if memcache.memcache.get(activity_id_memcache_key(id)):
            logger.info(f'Already seen {id}')
            return '', 204

    # check signature, auth
    authed_as = ActivityPub.verify_signature(activity)

    if util.domain_or_parent_in(authed_as, NO_AUTH_DOMAINS):
        error(f"Ignoring, sorry, we don't know how to authorize {util.domain_from_link(authed_as)} activities yet. https://github.com/snarfed/bridgy-fed/issues/566", status=204)

    # if we need the LD Sig to authorize this activity, bail out, we don't do
    # those yet
    if authed_as != actor_id and activity.get('signature'):
        error(f"Ignoring LD Signature, sorry, we can't verify those yet. https://github.com/snarfed/bridgy-fed/issues/566", status=202)

    logger.info(f'Got {type} {id} from {actor_id}')

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

    if not id:
        id = f'{actor_id}#{type}-{obj_id or ""}-{util.now().isoformat()}'

    # automatically bridge server aka instance actors
    # https://codeberg.org/fediverse/fep/src/branch/main/fep/d556/fep-d556.md
    if as2.is_server_actor(actor):
        all_protocols = [proto.LABEL for proto in set(PROTOCOLS.values())
                         if proto not in (ActivityPub, UIProtocol, None)]
        user = ActivityPub.get_or_create(actor_id, propagate=True,
                                         enabled_protocols=all_protocols)
        if user and not user.existing:
            logger.info(f'Automatically enabled AP server actor {actor_id}')

    delay = None
    if type == 'Delete' or (type == 'Undo' and inner_type != 'Follow'):
        delay = DELETE_TASK_DELAY

    return create_task(queue='receive', id=id, as2=activity,
                       source_protocol=ActivityPub.LABEL, authed_as=authed_as,
                       received_at=util.now().isoformat(), delay=delay)


# protocol in subdomain
@app.get(f'/ap/<id>/<any(followers,following):collection>')
# special case Web users on fed.brid.gy subdomain without /ap/web/ prefix, for
# backward compatibility
@app.route(f'/<regex("{DOMAIN_RE}"):id>/<any(followers,following):collection>',
           methods=['GET', 'HEAD'])
@flask_util.headers(CACHE_CONTROL)
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

    user = _load_user(id)

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
        logger.debug(f'Returning {json_dumps(page, indent=2)}')
        return page, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    ret = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.base_url,
        'type': 'Collection',
        'summary': f"{id}'s {collection}",
        'first': page,
    }

    # count total if it's small, <= 1k. we should eventually precompute this
    # so that we can always return it cheaply.
    prop = Follower.to if collection == 'followers' else Follower.from_
    count = Follower.query(prop == user.key, Follower.status == 'active')\
                    .count(limit=1001)
    if count != 1001:
        ret['totalItems'] = count

    logger.debug(f'Returning {json_dumps(collection, indent=2)}')
    return ret, {
        'Content-Type': as2.CONTENT_TYPE_LD_PROFILE,
    }


# protocol in subdomain
@app.get(f'/ap/<id>/outbox')
# special case Web users on fed.brid.gy subdomain without /ap/web/ prefix, for
# backward compatibility
@app.route(f'/<regex("{DOMAIN_RE}"):id>/outbox', methods=['GET', 'HEAD'])
@flask_util.headers(CACHE_CONTROL)
def outbox(id):
    """Serves a user's AP outbox.

    TODO: unify page generation with follower_collection()
    """
    user = _load_user(id)

    if request.method == 'HEAD':
        return '', {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    # TODO: bring this back once we filter it by author status, etc
    # query = Object.query(Object.users == user.key)
    # objects, new_before, new_after = fetch_objects(query, by=Object.updated,
    #                                                user=user)

    # page = {
    #     'type': 'CollectionPage',
    #     'partOf': request.base_url,
    #     'items': util.trim_nulls([ActivityPub.convert(obj, from_user=user)
    #                               for obj in objects]),
    # }
    # if new_before:
    #     page['next'] = f'{request.base_url}?before={new_before}'
    # if new_after:
    #     page['prev'] = f'{request.base_url}?after={new_after}'

    # if 'before' in request.args or 'after' in request.args:
    #     page.update({
    #         '@context': 'https://www.w3.org/ns/activitystreams',
    #         'id': request.url,
    #     })
    #     logger.debug(f'Returning {json_dumps(page, indent=2)}')
    #     return page, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}

    ret = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'id': request.url,
        'type': 'OrderedCollection',
        'summary': f"{id}'s outbox",
        'totalItems': 0,
        # 'first': page,
        'first': {
            'type': 'CollectionPage',
            'partOf': request.base_url,
            'items': [],
        },
    }

    # # count total if it's small, <= 1k. we should eventually precompute this
    # # so that we can always return it cheaply.
    # count = query.count(limit=1001)
    # if count != 1001:
    #     ret['totalItems'] = count

    return ret, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}


# protocol in subdomain
@app.get('/ap/<id>/featured')
def featured(id):
    """Serves a user's AP featured collection for pinned posts.

    https://docs.joinmastodon.org/spec/activitypub/#featured

    We inline the featured collection in users' actors, but Mastodon (and
    Pleroma/Akkoma?) require it to be fetchable separately too. :(

    Also, it's critical that the collection items here are expanded objects!
    Originally they were compacted string ids, but that triggered a massive flood of
    requests from Pleroma and Akkoma:
    https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    """
    # TODO: bring back once we figure out how to get Mastodon to support this and
    # Pleroma and Akkoma not to DDoS us
    # https://github.com/snarfed/bridgy-fed/issues/1374#issuecomment-2891993190
    return '', 404

    user = _load_user(id)

    items = []
    if user.obj and user.obj.as1:
        for obj in as1.get_objects(user.obj.as1.get('featured', {}), 'items'):
            if set(obj.keys()) == {'id'}:
                if obj := user.load(obj['id']):
                    if obj.as1:
                        items.append(ActivityPub.convert(obj))
            elif obj:
                items.append(ActivityPub.convert(Object(our_as1=obj)))

    return {
        '@context': as2.CONTEXT,
        'type': 'OrderedCollection',
        'id': request.base_url,
        'totalItems': len(items),
        'orderedItems': items,
    }, {'Content-Type': as2.CONTENT_TYPE_LD_PROFILE}


@app.get('/.well-known/nodeinfo')
@flask_util.canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def nodeinfo_jrd():
    """
    https://nodeinfo.diaspora.software/protocol.html
    """
    return {
        'links': [{
            'rel': 'http://nodeinfo.diaspora.software/ns/schema/2.1',
            'href': common.host_url('nodeinfo.json'),
        }, {
            "rel": "https://www.w3.org/ns/activitystreams#Application",
            "href": instance_actor().id_as(ActivityPub),
        }],
    }, {
        'Content-Type': 'application/jrd+json',
    }


@app.get('/nodeinfo.json')
@flask_util.canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@memcache.memoize(expire=datetime.timedelta(hours=1))
@flask_util.headers(CACHE_CONTROL)
def nodeinfo():
    """
    https://nodeinfo.diaspora.software/schema.html
    """
    from atproto import ATProto
    from nostr import Nostr
    from web import Web

    atp = ATProto.query(ATProto.enabled_protocols != None).count()
    ap = ActivityPub.query(ActivityPub.enabled_protocols != None).count()
    nostr = Nostr.query(Nostr.enabled_protocols != None).count()
    web = Web.query(Web.status == None).count()
    total = atp + ap + nostr + web

    logger.info(f'Users: ap: {ap}')
    logger.info(f'Users: atproto: {atp}')
    logger.info(f'Users: web: {web}')
    logger.info(f'Users: total: {total}')

    return {
        'version': '2.1',
        'software': {
            'name': 'bridgy-fed',
            'version': os.getenv('GAE_VERSION'),
            'repository': 'https://github.com/snarfed/bridgy-fed',
            'homepage': 'https://fed.brid.gy/',
        },
        'protocols': [
            'activitypub',
            'atprotocol',
            'webmention',
        ],
        'services': {
            'outbound': [],
            'inbound': [],
        },
        'usage': {
            'users': {
                'total': total,
                # 'activeMonth':
                # 'activeHalfyear':
            },
            # these are too heavy
            # 'localPosts': Object.query(Object.source_protocol.IN(('web', 'webmention')),
            #                            Object.type.IN(['note', 'article']),
            #                            ).count(),
            # 'localComments': Object.query(Object.source_protocol.IN(('web', 'webmention')),
            #                               Object.type == 'comment',
            #                               ).count(),
        },
        'openRegistrations': True,
        'metadata': {
            'users': {
                'activitypub': ap,
                'atprotocol': atp,
                'webmention': web,
            },
        },
    }, {
        # https://nodeinfo.diaspora.software/protocol.html
        'Content-Type': 'application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"',
    }


@app.get('/api/v1/instance')
@flask_util.canonicalize_request_domain(common.PROTOCOL_DOMAINS, common.PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def instance_info():
    """
    https://docs.joinmastodon.org/methods/instance/#v1
    """
    return {
        'uri': 'fed.brid.gy',
        'title': 'Bridgy Fed',
        'version': os.getenv('GAE_VERSION'),
        'short_description': 'Bridging the new social internet',
        'description': 'Bridging the new social internet',
        'email': 'feedback@brid.gy',
        'thumbnail': 'https://fed.brid.gy/static/bridgy_logo_with_alpha.png',
        'registrations': True,
        'approval_required': False,
        'invites_enabled': False,
        'contact_account': {
            'username': 'snarfed.org',
            'acct': 'snarfed.org',
            'display_name': 'Ryan',
            'url': 'https://snarfed.org/',
        },
    }


#
# OAuth
#
class MastodonStart(FlashErrors, oauth_dropins.mastodon.Start):
  def app_name(self):
      return 'Bridgy Fed'

  def app_url(self):
      return 'https://fed.brid.gy/'

class MastodonCallback(FlashErrors, oauth_dropins.mastodon.Callback):
    pass

class PixelfedStart(FlashErrors, oauth_dropins.pixelfed.Start):
  def app_name(self):
      return 'Bridgy Fed'

  def app_url(self):
      return 'https://fed.brid.gy/'

class PixelfedCallback(FlashErrors, oauth_dropins.pixelfed.Callback):
    pass

class ThreadsStart(FlashErrors, oauth_dropins.threads.Start):
    pass

class ThreadsCallback(FlashErrors, oauth_dropins.threads.Callback):
    pass


app.add_url_rule('/oauth/mastodon/start', view_func=MastodonStart.as_view(
                     '/oauth/mastodon/start', '/oauth/mastodon/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/mastodon/finish', view_func=MastodonCallback.as_view(
                     '/oauth/mastodon/finish', '/settings'))

app.add_url_rule('/oauth/pixelfed/start', view_func=PixelfedStart.as_view(
                     '/oauth/pixelfed/start', '/oauth/pixelfed/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/pixelfed/finish', view_func=PixelfedCallback.as_view(
                     '/oauth/pixelfed/finish', '/settings'))

app.add_url_rule('/oauth/threads/start', view_func=ThreadsStart.as_view(
                     '/oauth/threads/start', '/oauth/threads/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/threads/finish', view_func=ThreadsCallback.as_view(
                     '/oauth/threads/finish', '/settings'))
