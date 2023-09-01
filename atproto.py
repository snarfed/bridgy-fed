"""ATProto protocol implementation.

https://atproto.com/

TODO
* signup. resolve DID, fetch DID doc, extract PDS
  * use alsoKnownAs as handle? or call getProfile on PDS to get handle?
  * maybe need getProfile to store profile object?
"""
import json
import logging
from pathlib import Path
import re

from arroba import did
from arroba.datastore_storage import DatastoreStorage
from arroba.repo import Repo, Write
from arroba.storage import Action
from arroba.util import next_tid, new_key, parse_at_uri
from flask import abort, g, request
from google.cloud import ndb
from granary import as1, bluesky
from lexrpc import Client
from oauth_dropins.webutil import flask_util, util
import requests
from urllib.parse import urljoin, urlparse

import common
from common import (
    add,
    error,
    is_blocklisted,
    USER_AGENT,
)
from flask_app import app, cache
from models import Follower, Object, PROTOCOLS, User
from protocol import Protocol

logger = logging.getLogger(__name__)

lexicons = []
for filename in (Path(__file__).parent / 'lexicons').glob('**/*.json'):
    with open(filename) as f:
        lexicons.append(json.load(f))

storage = DatastoreStorage()

class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'atproto'

    @ndb.ComputedProperty
    def readable_id(self):
        """Prefers handle, then DID."""
        did_obj = ATProto.load(self.key.id(), remote=False)
        if did_obj:
            handle, _, _ = parse_at_uri(
                util.get_first(did_obj.raw, 'alsoKnownAs', ''))
            if handle:
                return handle

        return self.key.id()

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
                    and not is_blocklisted(domain)), domain
        else:
            assert False, f'{id} is not valid did:plc or did:web'

        assert not self.atproto_did, \
            f"{self.key} shouldn't have atproto_did {self.atproto_did}"

    def web_url(self):
        return bluesky.Bluesky.user_url(self.readable_id)

    def ap_address(self):
        """Returns this user's AP address, eg '@handle.com@bsky.brid.gy'."""
        return f'@{self.readable_id}@{self.ABBREV}{common.SUPERDOMAIN}'

    @classmethod
    def owns_id(cls, id):
        return (id.startswith('at://')
                or id.startswith('did:plc:')
                or id.startswith('did:web:'))

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns the PDS URL for the given object, or None.

        Args:
          obj: :class:`Object`

        Returns:
          str
        """
        if obj.key.id().startswith('did:'):
            return None

        if obj.key.id().startswith('at://'):
            repo, collection, rkey = parse_at_uri(obj.key.id())
            did_obj = ATProto.load(repo)
            if did_obj:
                return did_obj.raw.get('services', {})\
                                  .get('atproto_pds', {})\
                                  .get('endpoint')

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
    def send(cls, obj, url, log_data=True):
        """Creates a record if we own its repo.

        Creates the repo first if it doesn't exist.

        If the repo's DID doc doesn't say we're its PDS, does nothing and
        returns False.

        Doesn't deliver anywhere externally! BGS(es) will receive this record
        through subscribeRepos and then deliver it to AppView(s), which will
        notify recipients as necessary.
        """
        # TODO
        if url.rstrip('/') != common.host_url().rstrip('/'):
            logger.info(f'Target PDS {url} is not us')
            return False

        type = as1.object_type(obj.as1)
        if type == 'post':
            type = as1.object_type(as1.get_object(obj.as1))
        assert type in ('note', 'article')

        user_key = PROTOCOLS[obj.source_protocol].actor_key(obj)
        if not user_key:
            logger.info(f"Couldn't find {obj.source_protocol} user for {obj.key}")
            return False

        user = user_key.get()
        privkey = user.k256_key()
        if user.atproto_did:
            did_doc = cls.load(user.atproto_did)
            pds = did_doc.raw['services']['atproto_pds']['endpoint']
            if pds.rstrip('/') != url.rstrip('/'):
                logger.warning(f'{user_key} {user.atproto_did} PDS {pds} is not us')
                return False
        else:
            # STATE: (unneeded?) new User.atproto_handle()
            did_plc = did.create_plc(user.atproto_handle(), privkey=privkey,
                                     pds_hostname=request.host,
                                     post_fn=util.requests_post)
            assert did_plc.privkey == privkey

            ndb.transactional()
            def update():
                Object.get_or_create(did_plc.did, raw=did_plc.doc)
                user.atproto_did = did_plc.did
                user.put()
            update()

        repo = storage.load_repo(did=user.atproto_did)
        if repo is None:
            handle = user.readable_id if user.readable_id != user.atproto_did else None
            repo = Repo.create(storage, user.atproto_did, privkey, handle=handle)

        create = Write(action=Action.CREATE, collection='app.bsky.feed.post',
                       rkey=next_tid(), record=obj.as_bsky())
        repo.apply_writes([create], privkey)
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

        # at:// URI
        # examples:
        # at://did:plc:s2koow7r6t7tozgd4slc3dsg/app.bsky.feed.post/3jqcpv7bv2c2q
        # https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        repo, collection, rkey = parse_at_uri(obj.key.id())
        client = Client(cls.target_for(obj), lexicons,
                        headers={'User-Agent': USER_AGENT})
        obj.bsky = client.com.atproto.repo.getRecord(
            repo=repo, collection=collection, rkey=rkey)
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
