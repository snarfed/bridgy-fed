"""ATProto protocol implementation.

https://atproto.com/
"""
import itertools
import logging
import os
import re

from arroba import did
from arroba.datastore_storage import AtpRemoteBlob, AtpRepo, DatastoreStorage
from arroba.repo import Repo, Write
import arroba.server
from arroba.storage import Action, CommitData
from arroba.util import at_uri, next_tid, parse_at_uri, service_jwt
import dag_json
from flask import abort, request
from google.cloud import dns
from google.cloud import ndb
from granary import as1, bluesky
from lexrpc import Client
import requests
from requests import RequestException
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from common import (
    add,
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    DOMAINS,
    error,
    USER_AGENT,
)
import flask_app
from models import Object, PROTOCOLS, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)

arroba.server.storage = DatastoreStorage(ndb_client=ndb_client)

appview = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                 headers={'User-Agent': USER_AGENT})
LEXICONS = appview.defs

# https://atproto.com/guides/applications#record-types
COLLECTION_TO_TYPE = {
  'app.bsky.actor.profile': 'profile',
  'app.bsky.feed.like': 'like',
  'app.bsky.feed.post': 'post',
  'app.bsky.feed.repost': 'repost',
  'app.bsky.graph.follow': 'follow',
}

DNS_GCP_PROJECT = 'brid-gy'
DNS_ZONE = 'brid-gy'
DNS_TTL = 10800  # seconds
logger.info(f'Using GCP DNS project {DNS_GCP_PROJECT} zone {DNS_ZONE}')
dns_client = dns.Client(project=DNS_GCP_PROJECT)


def did_to_handle(did):
    """Resolves a DID to a handle _if_ we have the DID doc stored locally.

    Args:
      did (str)

    Returns:
      str: handle, or None
    """
    if did_obj := ATProto.load(did, did_doc=True):
        if aka := util.get_first(did_obj.raw, 'alsoKnownAs', ''):
            handle, _, _ = parse_at_uri(aka)
            if handle:
                return handle


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'atproto'
    # TODO: add second bsky label? inject into PROTOCOLS?
    PHRASE = 'Bluesky'
    LOGO_HTML = '<img src="/static/atproto_logo.png">'
    PDS_URL = f'https://{ABBREV}{common.SUPERDOMAIN}/'
    CONTENT_TYPE = 'application/json'

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web."""
        super()._pre_put_hook()
        id = self.key.id()
        assert id

        if id.startswith('did:plc:'):
            assert id.removeprefix('did:plc:')
        elif id.startswith('did:web:'):
            domain = id.removeprefix('did:web:')
            assert (re.match(common.DOMAIN_RE, domain)
                    and not Protocol.is_blocklisted(domain)), domain
        else:
            assert False, f'{id} is not valid did:plc or did:web'

    @ndb.ComputedProperty
    def handle(self):
        """Returns handle if the DID document includes one, otherwise None."""
        return did_to_handle(self.key.id())

    def web_url(self):
        return bluesky.Bluesky.user_url(self.handle_or_id())

    @classmethod
    def owns_id(cls, id):
        return (id.startswith('at://')
                or id.startswith('did:plc:')
                or id.startswith('did:web:')
                or id.startswith('https://bsky.app/'))

    @classmethod
    def owns_handle(cls, handle):
        if not re.match(DOMAIN_RE, handle):
            return False

    @classmethod
    def handle_to_id(cls, handle):
        assert cls.owns_handle(handle) is not False

        # TODO: shortcut our own handles? eg snarfed.org.web.brid.gy

        user = ATProto.query(ATProto.handle == handle).get()
        if user:
            return user.key.id()

        return did.resolve_handle(handle, get_fn=util.requests_get)

    @staticmethod
    def profile_at_uri(id):
        assert id.startswith('did:')
        return f'at://{id}/app.bsky.actor.profile/self'

    def profile_id(self):
        return self.profile_at_uri(self.key.id())

    @classmethod
    def bridged_web_url_for(cls, user):
        """Returns a bridged user's profile URL on bsky.app.

        For example, returns ``https://bsky.app/profile/alice.com.web.brid.gy``
        for Web user ``alice.com``.

        Args:
          user (models.User)

        Returns:
          str, or None if there isn't a canonical URL
        """
        if not isinstance(user, ATProto):
            if did := user.get_copy(ATProto):
                return bluesky.Bluesky.user_url(did_to_handle(did) or did)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns our PDS URL as the target for the given object.

        ATProto delivery is indirect. We write all records to the user's local
        repo that we host, then BGSes and other subscribers receive them via the
        subscribeRepos event streams. So, we use a single target, our base URL
        (eg ``https://atproto.brid.gy/``) as the PDS URL, for all activities.
        """
        if cls.owns_id(obj.key.id()) is not False:
            return cls.PDS_URL

    @classmethod
    def pds_for(cls, obj):
        """Returns the PDS URL for the given object, or None.

        Args:
          obj (Object)

        Returns:
          str:
        """
        id = obj.key.id()
        # logger.debug(f'Finding ATProto PDS for {id}')

        if id.startswith('did:'):
            if obj.raw:
                for service in obj.raw.get('service', []):
                    if service.get('id') in ('#atproto_pds', f'{id}#atproto_pds'):
                        return service.get('serviceEndpoint')

            logger.info(f"{id}'s DID doc has no ATProto PDS")
            return None

        if id.startswith('https://bsky.app/'):
            return cls.pds_for(Object(id=bluesky.web_url_to_at_uri(id)))

        if id.startswith('at://'):
            repo, collection, rkey = parse_at_uri(id)

            if not repo.startswith('did:'):
                # repo is a handle; resolve it
                repo_did = cls.handle_to_id(repo)
                if repo_did:
                    return cls.pds_for(Object(id=id.replace(
                        f'at://{repo}', f'at://{repo_did}')))
                else:
                    return None

            did_obj = ATProto.load(repo, did_doc=True)
            if did_obj:
                return cls.pds_for(did_obj)
            # TODO: what should we do if the DID doesn't exist? should we return
            # None here? or do we need this path to return BF's URL so that we
            # then create the DID for non-ATP users on demand?

        # don't use Object.as1 if bsky is set, since that conversion calls
        # pds_for, which would infinite loop
        if not obj.bsky and obj.as1:
            if owner := as1.get_owner(obj.as1):
                if user_key := Protocol.key_for(owner):
                    if user := user_key.get():
                        if owner_did := user.get_copy(ATProto):
                            return cls.pds_for(Object(id=f'at://{owner_did}'))

        return None

    def is_blocklisted(url):
        # don't block common.DOMAINS since we want ourselves, ie our own PDS, to
        # be a valid domain to send to
        return util.domain_or_parent_in(util.domain_from_link(url), DOMAIN_BLOCKLIST)

    @classmethod
    @ndb.transactional()
    def create_for(cls, user):
        """Creates an ATProto repo and profile for a non-ATProto user.

        Args:
          user (models.User)
        """
        assert not isinstance(user, ATProto)

        if user.get_copy(ATProto):
            return

        # create new DID, repo
        pds_url = common.host_url() if DEBUG else cls.PDS_URL
        logger.info(f'Creating new did:plc for {user.key} {pds_url}')
        did_plc = did.create_plc(user.handle_as('atproto'),
                                 pds_url=pds_url,
                                 post_fn=util.requests_post)

        Object.get_or_create(did_plc.did, raw=did_plc.doc)
        # TODO: move this to ATProto.get_or_create?
        add(user.copies, Target(uri=did_plc.did, protocol='atproto'))
        handle = user.handle_as('atproto')

        # create _atproto DNS record for handle resolution
        # https://atproto.com/specs/handle#handle-resolution
        name = f'_atproto.{handle}.'
        val = f'"did={did_plc.did}"'
        logger.info(f'adding GCP DNS TXT record for {name} {val}')
        if DEBUG:
            logger.info('  skipped since DEBUG is true')
        else:
            zone = dns_client.zone(DNS_ZONE)
            r = zone.resource_record_set(name=name, record_type='TXT', ttl=DNS_TTL,
                                         rrdatas=[val])
            changes = zone.changes()
            changes.add_record_set(r)
            changes.create()
            logger.info('  done!')

        # fetch and store profile
        if not user.obj:
            user.obj = user.load(user.profile_id())

        initial_writes = None
        if user.obj and user.obj.as1:
            # create user profile
            profile = cls.convert(user.obj, fetch_blobs=True, from_user=user)
            profile.setdefault('labels', {'$type': 'com.atproto.label.defs#selfLabels'})
            profile['labels'].setdefault('values', []).append({
                'val' : f'bridged-from-bridgy-fed-{user.LABEL}',
            })

            profile_json = json_dumps(dag_json.encode(profile).decode(), indent=2)
            logger.info(f'Storing ATProto app.bsky.actor.profile self: {profile_json}')
            initial_writes = [Write(
                action=Action.CREATE, collection='app.bsky.actor.profile',
                rkey='self', record=profile)]
            uri = at_uri(did_plc.did, 'app.bsky.actor.profile', 'self')
            user.obj.add('copies', Target(uri=uri, protocol='atproto'))
            user.obj.put()

        repo = Repo.create(
            arroba.server.storage, did_plc.did, handle=handle,
            callback=lambda _: common.create_task(queue='atproto-commit'),
            initial_writes=initial_writes,
            signing_key=did_plc.signing_key,
            rotation_key=did_plc.rotation_key)

        user.put()

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj=None):
        """Creates a record if we own its repo.

        Creates the repo first if it doesn't exist.

        If the repo's DID doc doesn't say we're its PDS, does nothing and
        returns False.

        Doesn't deliver anywhere externally! BGS(es) will receive this record
        through ``subscribeRepos`` and then deliver it to AppView(s), which will
        notify recipients as necessary.
        """
        if util.domain_from_link(url) not in DOMAINS:
            logger.info(f'Target PDS {url} is not us')
            return False

        verb = obj.as1.get('verb')
        if verb in ('accept', 'undo'):
            logger.info(f'Skipping sending {verb}, not supported in ATProto')
            return False

        # determine "base" object, if any
        type = as1.object_type(obj.as1)
        base_obj = obj
        if type in ('post', 'update', 'delete'):
            obj_as1 = as1.get_object(obj.as1)
            type = as1.object_type(obj_as1)
            # TODO: should we not load for deletes?
            base_obj = PROTOCOLS[obj.source_protocol].load(obj_as1['id'])
            if not base_obj:
                base_obj = obj

        # convert to Bluesky record; short circuits on error
        try:
            record = to_cls.convert(base_obj, fetch_blobs=True, from_user=from_user)
        except ValueError as e:
            logger.info(f'Skipping due to {e}')
            return False

        # find user
        from_cls = PROTOCOLS[obj.source_protocol]
        from_key = from_cls.actor_key(obj)
        if not from_key:
            logger.info(f"Couldn't find {obj.source_protocol} user for {obj.key}")
            return False

        # load user
        user = from_cls.get_or_create(from_key.id(), propagate=True)
        did = user.get_copy(ATProto)
        assert did
        logger.info(f'{user.key} is {did}')
        did_doc = to_cls.load(did, did_doc=True)
        pds = to_cls.pds_for(did_doc)
        if not pds or util.domain_from_link(pds) not in DOMAINS:
            logger.warning(f'{from_key} {did} PDS {pds} is not us')
            return False

        # load repo
        repo = arroba.server.storage.load_repo(did)
        assert repo
        repo.callback = lambda _: common.create_task(queue='atproto-commit')

        # write commit
        type = record['$type']
        lex_type = LEXICONS[type]['type']
        assert lex_type == 'record', f"Can't store {type} object of type {lex_type}"

        ndb.transactional()
        def write():
            match verb:
                case 'update':
                    action = Action.UPDATE
                case 'delete':
                    action = Action.DELETE
                case _:
                    action = Action.CREATE
                    rkey = next_tid()

            if verb in ('update', 'delete'):
                # load existing record, check that it's the same one
                copy = base_obj.get_copy(to_cls)
                assert copy
                copy_did, coll, rkey = parse_at_uri(copy)
                assert copy_did == did
                assert coll == type

            logger.info(f'Storing ATProto {action} {type} {rkey}: {dag_json.encode(record).decode()}')
            repo.apply_writes([Write(action=action, collection=type, rkey=rkey,
                                     record=record)])

            at_uri = f'at://{did}/{type}/{rkey}'
            base_obj.add('copies', Target(uri=at_uri, protocol=to_cls.LABEL))
            base_obj.put()

        write()
        return True

    @classmethod
    def load(cls, id, did_doc=False, **kwargs):
        """Thin wrapper that converts DIDs and bsky.app URLs to at:// URIs.

        Args:
          did_doc (bool): if True, loads and returns a DID document object
            instead of an ``app.bsky.actor.profile/self``.
        """
        if id.startswith('did:') and not did_doc:
            id = cls.profile_at_uri(id)

        elif id.startswith('https://bsky.app/'):
            try:
                id = bluesky.web_url_to_at_uri(id)
            except ValueError as e:
                logger.warning(f"Couldn't convert {id} to at:// URI: {e}")
                return None

        return super().load(id, **kwargs)

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Tries to fetch a ATProto object.

        Args:
          obj (models.Object): with the id to fetch. Fills data into the ``as2``
            property.
          kwargs: ignored

        Returns:
          bool: True if the object was fetched and populated successfully,
          False otherwise

        Raises:
          TODO
        """
        id = obj.key.id()
        if not cls.owns_id(id):
            logger.info(f"ATProto can't fetch {id}")
            return False

        assert not id.startswith('https://bsky.app/')  # handled in load

        # did:plc, did:web
        if id.startswith('did:'):
            try:
                obj.raw = did.resolve(id, get_fn=util.requests_get)
                return True
            except (ValueError, requests.RequestException) as e:
                util.interpret_http_exception(e)
                return False

        # at:// URI. if it has a handle, resolve and replace with DID.
        # examples:
        # at://did:plc:s2koow7r6t7tozgd4slc3dsg/app.bsky.feed.post/3jqcpv7bv2c2q
        # https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        repo, collection, rkey = parse_at_uri(id)
        if not repo.startswith('did:'):
            handle = repo
            repo = cls.handle_to_id(repo)
            if not repo:
                return False
            assert repo.startswith('did:')
            obj.key = ndb.Key(Object, id.replace(f'at://{handle}', f'at://{repo}'))

        try:
            ret = appview.com.atproto.repo.getRecord(
                repo=repo, collection=collection, rkey=rkey)
        except RequestException as e:
            util.interpret_http_exception(e)
            return False

        # TODO: verify sig?
        obj.bsky = {
            **ret['value'],
            'cid': ret.get('cid'),
        }
        return True

    @classmethod
    def convert(cls, obj, fetch_blobs=False, from_user=None):
        """Converts a :class:`models.Object` to ``app.bsky.*`` lexicon JSON.

        Args:
          obj (models.Object)
          fetch_blobs (bool): whether to fetch images and other blobs, store
            them in :class:`arroba.datastore_storage.AtpRemoteBlob`\s if they
            don't already exist, and fill them into the returned object.
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          dict: JSON object
        """
        from_proto = PROTOCOLS.get(obj.source_protocol)
        user_id = from_user.key.id() if from_user and from_user.key else None
        # TODO: uncomment
        # if from_proto and not common.is_enabled(cls, from_proto, handle_or_id=user_id):
        #     error(f'{cls.LABEL} <=> {from_proto.LABEL} not enabled')

        if obj.bsky:
            return obj.bsky

        if not obj.as1:
            return {}

        blobs = {}  # maps str URL to dict blob object
        if fetch_blobs:
            for o in obj.as1, as1.get_object(obj.as1):
                for url in util.get_urls(o, 'image'):
                    if url not in blobs:
                        blob = AtpRemoteBlob.get_or_create(
                            url=url, get_fn=util.requests_get)
                        blobs[url] = blob.as_object()

        ret = bluesky.from_as1(cls.translate_ids(obj.as1), blobs=blobs)
            # TODO: uncomment this and pass through client eventually? would be
            # nice to start reusing granary's resolving handles and CIDs, but we
            # do much of that ourselves here in BF beforehand, so granary ends
            # up duplicating those network requests
            # client=appview)

        # fill in CIDs from Objects
        def populate_cid(strong_ref):
            if uri := strong_ref.get('uri'):
                # TODO: fail if this load fails? since we don't populate CID
                if ref_obj := ATProto.load(uri):
                    if not ref_obj.bsky.get('cid'):
                        ref_obj = ATProto.load(uri, remote=True)
                    strong_ref.update({
                        'cid': ref_obj.bsky.get('cid'),
                        'uri': ref_obj.key.id(),
                    })

        match ret.get('$type'):
            case 'app.bsky.feed.like' | 'app.bsky.feed.repost':
                populate_cid(ret['subject'])
            case 'app.bsky.feed.post' if ret.get('reply'):
                populate_cid(ret['reply']['root'])
                populate_cid(ret['reply']['parent'])

        return ret


# URL route is registered in hub.py
def poll_notifications():
    """Fetches and enqueueus new activities from the AppView for our users.

    Uses the ``listNotifications`` endpoint, which is intended for end users. 🤷

    https://github.com/bluesky-social/atproto/discussions/1538

    TODO: unify with poll_posts
    """
    repos = {r.key.id(): r for r in AtpRepo.query()}
    logger.info(f'Got {len(repos)} repos')
    if not repos:
        return

    users = itertools.chain(*(cls.query(cls.copies.uri.IN(list(repos)))
                              for cls in set(PROTOCOLS.values())
                              if cls and cls != ATProto))

    # this client needs to be request-local because we set its service token
    # below per user that we're polling
    client = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                    headers={'User-Agent': USER_AGENT})

    for user in users:
        # TODO: remove for launch
        if not DEBUG and user.key.id() not in ['indieweb.org', 'snarfed.org']:
            logger.info(f'Skipping {user.key.id()}')
            continue

        logger.debug(f'Fetching notifs for {user.key.id()}')

        # TODO: store and use cursor
        # seenAt would be easier, but they don't support it yet
        # https://github.com/bluesky-social/atproto/issues/1636
        did = user.get_copy(ATProto)
        repo = repos[did]
        client.session['accessJwt'] = service_jwt(os.environ['APPVIEW_HOST'],
                                                  repo_did=did,
                                                  privkey=repo.signing_key)
        resp = client.app.bsky.notification.listNotifications()
        for notif in resp['notifications']:
            actor_did = notif['author']['did']
            logger.debug(f'Got {notif["reason"]} from {notif["author"]["handle"]} {notif["uri"]} {notif["cid"]} : {json_dumps(notif, indent=2)}')

            # TODO: verify sig. skipping this for now because we're getting
            # these from the AppView, which is trusted, specifically we expect
            # the BGS and/or the AppView already checked sigs.
            obj = Object.get_or_create(id=notif['uri'], bsky=notif['record'],
                                       source_protocol=ATProto.ABBREV,
                                       actor=actor_did)
            if not obj.status:
                obj.status = 'new'
            obj.add('notify', user.key)
            obj.put()

            common.create_task(queue='receive', obj=obj.key.urlsafe(),
                               authed_as=actor_did)

    return 'OK'


# URL route is registered in hub.py
def poll_posts():
    """Fetches and enqueueus new posts from the AppView for our users.

    Uses the ``getTimeline`` endpoint, which is intended for end users. 🤷

    TODO: unify with poll_notifications
    """
    repos = {r.key.id(): r for r in AtpRepo.query()}
    logger.info(f'Got {len(repos)} repos')
    if not repos:
        return

    users = itertools.chain(*(cls.query(cls.copies.uri.IN(list(repos)))
                              for cls in set(PROTOCOLS.values())
                              if cls and cls != ATProto))

    # this client needs to be request-local because we set its service token
    # below per user that we're polling
    client = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                    headers={'User-Agent': USER_AGENT})

    for user in users:
        # TODO: remove for launch
        if not DEBUG and user.key.id() not in ['indieweb.org', 'snarfed.org']:
            logger.info(f'Skipping {user.key.id()}')
            continue

        logger.debug(f'Fetching posts for {user.key.id()}')

        # TODO: store and use cursor
        # seenAt would be easier, but they don't support it yet
        # https://github.com/bluesky-social/atproto/issues/1636
        did = user.get_copy(ATProto)
        repo = repos[did]
        client.session['accessJwt'] = service_jwt(os.environ['APPVIEW_HOST'],
                                                  repo_did=did,
                                                  privkey=repo.signing_key)
        resp = client.app.bsky.feed.getTimeline()
        for item in resp['feed']:
            # TODO: handle reposts once we have a URI for them
            # https://github.com/bluesky-social/atproto/issues/1811
            if item.get('reason'):
                continue

            post = item['post']
            logger.debug(f'Got {post["uri"]}: {json_dumps(item, indent=2)}')

            # TODO: verify sig. skipping this for now because we're getting
            # these from the AppView, which is trusted, specifically we expect
            # the BGS and/or the AppView already checked sigs.
            author_did = post['author']['did']
            obj = Object.get_or_create(id=post['uri'], bsky=post['record'],
                                       source_protocol=ATProto.ABBREV,
                                       actor=author_did)
            if not obj.status:
                obj.status = 'new'
            obj.add('feed', user.key)
            obj.put()

            common.create_task(queue='receive', obj=obj.key.urlsafe(),
                               authed_as=author_did)

    return 'OK'
