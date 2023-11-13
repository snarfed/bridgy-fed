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

arroba.server.storage = DatastoreStorage()

LEXICONS = Client('https://unused').defs

DNS_GCP_PROJECT = 'brid-gy'
DNS_ZONE = 'brid-gy'
DNS_TTL = 10800  # seconds
logger.info(f'Using GCP DNS project {DNS_GCP_PROJECT} zone {DNS_ZONE}')
dns_client = dns.Client(project=DNS_GCP_PROJECT)


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'atproto'
    LOGO_HTML = '<img src="/static/atproto_logo.png">'
    PDS_URL = f'https://{ABBREV}{common.SUPERDOMAIN}/'
    CONTENT_TYPE = 'application/json'

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web.

        Also check that the ``atproto_did`` property isn't set.
        """
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

        assert not self.atproto_did, \
            f"{self.key} shouldn't have atproto_did {self.atproto_did}"

    @ndb.ComputedProperty
    def handle(self):
        """Returns handle if the DID document includes one, otherwise None."""
        did_obj = ATProto.load(self.key.id())
        if did_obj:
            handle, _, _ = parse_at_uri(
                util.get_first(did_obj.raw, 'alsoKnownAs', ''))
            if handle:
                return handle

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

        user = ATProto.query(ATProto.handle == handle).get()
        if user:
            return user.key.id()

        return did.resolve_handle(handle, get_fn=util.requests_get)

    def profile_id(self):
        return f'at://{self.key.id()}/app.bsky.actor.profile/self'

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
                repo_did = did.resolve_handle(repo, get_fn=util.requests_get)
                if repo_did:
                    return cls.pds_for(Object(id=id.replace(
                        f'at://{repo}', f'at://{repo_did}')))
                else:
                    return None

            did_obj = ATProto.load(repo)
            if did_obj:
                return cls.pds_for(did_obj)
            # TODO: what should we do if the DID doesn't exist? should we return
            # None here? or do we need this path to return BF's URL so that we
            # then create the DID for non-ATP users on demand?

        if obj.as1:
            owner = as1.get_owner(obj.as1)
            if owner:
                user_key = Protocol.key_for(owner)
                if user_key:
                    user = user_key.get()
                    if user and user.atproto_did:
                        return cls.pds_for(Object(id=f'at://{user.atproto_did}'))

        return None

    def is_blocklisted(url):
        # don't block common.DOMAINS since we want ourselves, ie our own PDS, to
        # be a valid domain to send to
        return util.domain_or_parent_in(util.domain_from_link(url), DOMAIN_BLOCKLIST)

    @classmethod
    @ndb.transactional()
    def create_for(cls, user):
        """Creates an ATProto user, repo, and profile for a non-ATProto user.

        Args:
          user (models.User)
        """
        assert not isinstance(user, ATProto)

        if user.atproto_did:
            return

        # create new DID, repo
        logger.info(f'Creating new did:plc for {user.key}')
        did_plc = did.create_plc(user.handle_as('atproto'),
                                 pds_url=cls.PDS_URL,
                                 post_fn=util.requests_post)

        Object.get_or_create(did_plc.did, raw=did_plc.doc)
        user.atproto_did = did_plc.did
        # TODO: move this to ATProto.get_or_create?
        add(user.copies, Target(uri=did_plc.did, protocol='atproto'))
        handle = user.handle_as('atproto')

        # create _atproto DNS record for handle resolution
        # https://atproto.com/specs/handle#handle-resolution
        name = f'_atproto.{handle}.'
        val = f'"did={did_plc.did}"'
        logger.info(f'adding GCP DNS TXT record for {name} {val}')
        if not DEBUG:
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
            profile = cls.convert(user.obj, fetch_blobs=True)
            profile_json = json_dumps(dag_json.encode(profile).decode(), indent=2)
            logger.info(f'Storing ATProto app.bsky.actor.profile self: {profile_json}')
            initial_writes = [Write(
                action=Action.CREATE, collection='app.bsky.actor.profile',
                rkey='self', record=profile)]
            uri = at_uri(user.atproto_did, 'app.bsky.actor.profile', 'self')
            user.obj.add('copies', Target(uri=uri, protocol='atproto'))
            user.obj.put()

        repo = Repo.create(
            arroba.server.storage, user.atproto_did, handle=handle,
            callback=lambda _: common.create_task(queue='atproto-commit'),
            initial_writes=initial_writes,
            signing_key=did_plc.signing_key,
            rotation_key=did_plc.rotation_key)

        user.put()

    @classmethod
    def send(to_cls, obj, url, orig_obj=None):
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

        type = as1.object_type(obj.as1)
        base_obj = obj
        if type in ('accept', 'undo'):
            logger.info(f'Skipping unsupported type {type}, not writing to repo')
            return False
        elif type in ('post', 'update', 'delete'):
            obj_as1 = as1.get_object(obj.as1)
            type = as1.object_type(obj_as1)
            base_obj = PROTOCOLS[obj.source_protocol].load(obj_as1['id'])
            if not base_obj:
                base_obj = obj

        assert type in ('note', 'article')

        from_cls = PROTOCOLS[obj.source_protocol]
        from_key = from_cls.actor_key(obj)
        if not from_key:
            logger.info(f"Couldn't find {obj.source_protocol} user for {obj.key}")
            return False

        # load user
        user = from_cls.get_or_create(from_key.id(), propagate=True)
        assert user.atproto_did
        logger.info(f'{user.key} is {user.atproto_did}')
        did_doc = to_cls.load(user.atproto_did)
        pds = to_cls.pds_for(did_doc)
        if not pds or util.domain_from_link(pds) not in DOMAINS:
            logger.warning(f'{from_key} {user.atproto_did} PDS {pds} is not us')
            return False

        # load repo
        repo = arroba.server.storage.load_repo(user.atproto_did)
        assert repo
        repo.callback = lambda _: common.create_task(queue='atproto-commit')

        # create record and commit
        record = to_cls.convert(obj, fetch_blobs=True)
        type = record['$type']
        lex_type = LEXICONS[type]['type']
        assert lex_type == 'record', f"Can't store {type} object of type {lex_type}"

        ndb.transactional()
        def write():
            tid = next_tid()
            logger.info(f'Storing ATProto app.bsky.feed.post {tid}: ' +
                        json_dumps(dag_json.encode(record).decode(), indent=2))

            repo.apply_writes(
                [Write(action=Action.CREATE, collection='app.bsky.feed.post',
                       rkey=tid, record=record)])

            at_uri = f'at://{user.atproto_did}/app.bsky.feed.post/{tid}'
            base_obj.add('copies', Target(uri=at_uri, protocol=to_cls.LABEL))
            base_obj.put()

        write()
        return True

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

        # did:plc, did:web
        if id.startswith('did:'):
            try:
                obj.raw = did.resolve(id, get_fn=util.requests_get)
                return True
            except (ValueError, requests.RequestException) as e:
                util.interpret_http_exception(e)
                return False

        pds = cls.pds_for(obj)
        if not pds:
            return False

        # at:// URI
        # examples:
        # at://did:plc:s2koow7r6t7tozgd4slc3dsg/app.bsky.feed.post/3jqcpv7bv2c2q
        # https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        repo, collection, rkey = parse_at_uri(obj.key.id())
        client = Client(pds, headers={'User-Agent': USER_AGENT})
        ret = client.com.atproto.repo.getRecord(
            repo=repo, collection=collection, rkey=rkey)
        # TODO: verify sig?
        obj.bsky = ret['value']
        return True

    @classmethod
    def convert(cls, obj, fetch_blobs=False):
        """Converts a :class:`models.Object` to ``app.bsky.*`` lexicon JSON.

        Args:
          obj (models.Object)
          fetch_blobs (bool): whether to fetch images and other blobs, store
            them in :class:`arroba.datastore_storage.AtpRemoteBlob`\s if they
            don't already exist, and fill them into the returned object.

        Returns:
          dict: JSON object
        """
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

        return bluesky.from_as1(cls.translate_ids(obj.as1), blobs=blobs)


# URL route is registered in hub.py
def poll_notifications():
    """Fetches and enqueueus new activities from the AppView for our users.

    Uses the ``listNotifications`` endpoint, which is intended for end users. 🤷

    https://github.com/bluesky-social/atproto/discussions/1538
    """
    repos = {r.key.id(): r for r in AtpRepo.query()}
    logger.info(f'Got {len(repos)} repos')

    # TODO: switch from atproto_did to copies
    users = itertools.chain(*(cls.query(cls.atproto_did.IN(list(repos)))
                              for cls in set(PROTOCOLS.values())
                              if cls and cls != ATProto))

    # TODO: convert to Session for connection pipelining!
    client = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                    headers={'User-Agent': USER_AGENT})

    for user in users:
        logging.debug(f'Fetching notifs for {user.key.id()}')

        # TODO: store and use cursor
        # seenAt would be easier, but they don't support it yet
        # https://github.com/bluesky-social/atproto/issues/1636
        repo = repos[user.atproto_did]
        client.session['accessJwt'] = service_jwt(os.environ['APPVIEW_HOST'],
                                                  repo_did=user.atproto_did,
                                                  privkey=repo.signing_key)
        resp = client.app.bsky.notification.listNotifications()
        for notif in resp['notifications']:
            logger.debug(f'Got {notif["reason"]} from {notif["author"]["handle"]} {notif["uri"]} {notif["cid"]} : {json_dumps(notif, indent=2)}')

            # TODO: verify sig. skipping this for now because we're getting
            # these from the AppView, which is trusted, specifically we expect
            # the BGS and/or the AppView already checked sigs.
            obj = Object.get_or_create(id=notif['uri'], bsky=notif['record'],
                                       source_protocol=ATProto.ABBREV)
            if not obj.status:
                obj.status = 'new'
            obj.add('notify', user.key)
            obj.put()

            common.create_task(queue='receive', obj=obj.key.urlsafe(),
                               authed_as=notif['author']['did'])
            # note that we don't pass a user param above. it's the acting user,
            # which is different for every notif, and may not actually have a BF
            # User yet.

    return 'OK'
