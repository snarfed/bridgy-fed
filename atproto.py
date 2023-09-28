"""ATProto protocol implementation.

https://atproto.com/
"""
import itertools
import logging
import os
import re

from arroba import did
from arroba.datastore_storage import AtpRepo, DatastoreStorage
from arroba.repo import Repo, Write
import arroba.server
from arroba.storage import Action, CommitData
from arroba.util import next_tid, parse_at_uri, service_jwt
from flask import abort, request
from google.cloud import ndb
from granary import as1, bluesky
from lexrpc import Client
from oauth_dropins.webutil import util
import requests

import common
from common import (
    add,
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    error,
    USER_AGENT,
)
import flask_app
import hub
from models import Object, PROTOCOLS, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)

arroba.server.storage = DatastoreStorage()


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'atproto'

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web.

        Also check that the atproto_did property isn't set.
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
        """Returns the PDS URL for the given object, or None.

        If the repo DID/handle doesn't exist in the PLC directory, defaults to
        returning Bridgy Fed's URL as the PDS.

        Args:
          obj: :class:`Object`

        Returns:
          str
        """
        id = obj.key.id()
        if id.startswith('did:'):
            return None

        logger.info(f'Finding ATProto PDS for {id}')
        if id.startswith('https://bsky.app/'):
            return cls.target_for(Object(id=bluesky.web_url_to_at_uri(id)))

        if id.startswith('at://'):
            repo, collection, rkey = parse_at_uri(id)

            if not repo.startswith('did:'):
                # repo is a handle; resolve it
                repo_did = did.resolve_handle(repo, get_fn=util.requests_get)
                if repo_did:
                    return cls.target_for(Object(id=id.replace(
                        f'at://{repo}', f'at://{repo_did}')))
                else:
                    return None

            did_obj = ATProto.load(repo)
            if did_obj:
                return cls._pds_for(did_obj)
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
                        return cls.target_for(Object(id=f'at://{user.atproto_did}'))

        return common.host_url()

    @classmethod
    def _pds_for(cls, did_obj):
        """
        Args:
          did_obj: :class:`Object`

        Returns:
          str, PDS URL, or None
        """
        assert did_obj.key.id().startswith('did:')

        for service in did_obj.raw.get('service', []):
            if service.get('id') in ('#atproto_pds',
                                     f'{did_obj.key.id()}#atproto_pds'):
                return service.get('serviceEndpoint')

        logger.info(f"{did_obj.key.id()}'s DID doc has no ATProto PDS")
        return None

    def is_blocklisted(url):
        # don't block common.DOMAINS since we want ourselves, ie our own PDS, to
        # be a valid domain to send to
        return util.domain_or_parent_in(util.domain_from_link(url), DOMAIN_BLOCKLIST)

    @classmethod
    def send(to_cls, obj, url, log_data=True):
        """Creates a record if we own its repo.

        Creates the repo first if it doesn't exist.

        If the repo's DID doc doesn't say we're its PDS, does nothing and
        returns False.

        Doesn't deliver anywhere externally! BGS(es) will receive this record
        through subscribeRepos and then deliver it to AppView(s), which will
        notify recipients as necessary.
        """
        if url.rstrip('/') != common.host_url().rstrip('/'):
            logger.info(f'Target PDS {url} is not us')
            return False

        type = as1.object_type(obj.as1)
        if type in ('accept', 'undo'):
            logger.info(f'Skipping sending to {url}')
            return False
        elif type == 'post':
            type = as1.object_type(as1.get_object(obj.as1))
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
        pds = to_cls._pds_for(did_doc)
        if not pds or pds.rstrip('/') != url.rstrip('/'):
            logger.warning(f'{from_key} {user.atproto_did} PDS {pds} is not us')
            return False

        # load repo
        repo = arroba.server.storage.load_repo(user.atproto_did)
        assert repo
        repo.callback = lambda _: common.create_task(queue='atproto-commit')

        # create record and commit
        ndb.transactional()
        def write():
            tid = next_tid()
            repo.apply_writes(
                [Write(action=Action.CREATE, collection='app.bsky.feed.post',
                       rkey=tid, record=obj.as_bsky())])

            at_uri = f'at://{user.atproto_did}/app.bsky.feed.post/{tid}'
            add(obj.copies, Target(uri=at_uri, protocol=to_cls.ABBREV))
            obj.put()

        write()
        return True

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Tries to fetch a ATProto object.

        Args:
          obj: :class:`Object` with the id to fetch. Fills data into the as2
            property.
          kwargs: ignored

        Returns:
          True if the object was fetched and populated successfully,
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

        pds = cls.target_for(obj)
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
    def serve(cls, obj):
        """Serves an :class:`Object` as AS2.

        This is minimally implemented to serve app.bsky.* lexicon data, but
        BGSes and other clients will generally receive ATProto commits via
        `com.atproto.sync.subscribeRepos` subscriptions, not BF-specific
        /convert/... HTTP requests, so this should never be used in practice.
        """
        return bluesky.from_as1(obj.as1), {'Content-Type': 'application/json'}


@hub.app.get('/_ah/queue/atproto-poll-notifs')
def poll_notifications():
    """Fetches and enqueueus new activities from the AppView for our users.

    Uses the `listNotifications` endpoint, which is intended for end users. 🤷

    https://github.com/bluesky-social/atproto/discussions/1538
    """
    repos = {r.key.id(): r for r in AtpRepo.query()}
    logger.info(f'Got {len(repos)} repos')

    repo_dids = []
    users = itertools.chain(*(cls.query(cls.atproto_did.IN(list(repos)))
                              for cls in set(PROTOCOLS.values())
                              if cls and cls != ATProto))

    # TODO: convert to Session for connection pipelining!
    client = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                    headers={'User-Agent': USER_AGENT})

    for user in users:
        # TODO: store and use cursor
        # seenAt would be easier, but they don't support it yet
        # https://github.com/bluesky-social/atproto/issues/1636
        repo = repos[user.atproto_did]
        client.access_token = service_jwt(os.environ['APPVIEW_HOST'],
                                          repo_did=user.atproto_did,
                                          privkey=repo.signing_key)
        resp = client.app.bsky.notification.listNotifications()
        for notif in resp['notifications']:
            logger.info(f'Got {notif["reason"]} from {notif["author"]["handle"]} {notif["uri"]} {notif["cid"]}')

            # TODO: verify sig. skipping this for now because we're getting
            # these from the AppView, which is trusted, specifically we expect
            # the BGS and/or the AppView already checked sigs.
            obj = Object.get_or_create(id=notif['uri'], bsky=notif['record'],
                                       source_protocol=ATProto.ABBREV)
            if not obj.status:
                obj.status = 'new'
            add(obj.notify, user.key)
            obj.put()

            common.create_task(queue='receive', obj=obj.key.urlsafe(),
                               # TODO: should this be the receiving user?
                               # or the sending user?
                               user=user.key.urlsafe())

    return 'OK'
