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
from arroba.util import parse_at_uri
from flask import abort, g, request
from google.cloud import ndb
from granary import as1, bluesky
from lexrpc import Client
from oauth_dropins.webutil import flask_util, util
import requests
from urllib.parse import urljoin, urlparse

from flask_app import app, cache
import common
from common import (
    add,
    error,
    is_blocklisted,
    USER_AGENT,
)
from models import Follower, Object, User
from protocol import Protocol

logger = logging.getLogger(__name__)

lexicons = []
for filename in (Path(__file__).parent / 'lexicons').glob('**/*.json'):
    with open(filename) as f:
        lexicons.append(json.load(f))


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'atproto'

    @ndb.ComputedProperty
    def readable_id(self):
        """Prefers handle, then DID."""
        pass  # TODO

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web."""
        super()._pre_put_hook()
        id = self.key.id()
        assert id

        if id.startswith('did:plc:'):
            assert id.removeprefix('did:plc:')
            return

        if id.startswith('did:web:'):
            domain = id.removeprefix('did:web:')
            assert (re.match(common.DOMAIN_RE, domain)
                    and not is_blocklisted(domain)), domain
            return

        assert False, f'{id} is not valid did:plc or did:web'

    def handle(self):
        # TODO get from self.obj
        pass

    def web_url(self):
        return bluesky.Bluesky.user_url(self.handle() or self.key.id())

    # def ap_address(self):
    #     """Returns this user's AP address, eg '@foo.com@foo.com'."""
    #     if self.obj and self.obj.as1:
    #         addr = as2.address(self.as2())
    #         if addr:
    #             return addr

    #     return as2.address(self.key.id())

    # def ap_actor(self, rest=None):
    #     """Returns this user's AP/AS2 actor id URL.

    #     Eg 'https://fed.brid.gy/foo.com'
    #     """
    #     return self.key.id()

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
        if not obj.key.id().startswith('at://'):
            return None

        repo, collection, rkey = parse_at_uri(obj.key.id())
        did_obj = ATProto.load(repo)
        if not did_obj:
            return None

        return did_obj.raw.get('services', {}).get('atproto_pds', {}).get('endpoint')

    # @classmethod
    # def send(cls, obj, url, log_data=True):
    #     """Delivers an event to a relay.
    #     """
    #     if is_blocklisted(url):
    #         logger.info(f'Skipping sending to {url}')
    #         return False

    #     # this is set in web.webmention_task()
    #     orig_obj = getattr(obj, 'orig_obj', None)
    #     orig_as2 = orig_obj.as_as2() if orig_obj else None
    #     activity = obj.as2 or postprocess_as2(as2.from_as1(obj.as1),
    #                                           orig_obj=orig_as2)

    #     if g.user:
    #         activity['actor'] = g.user.ap_actor()
    #     elif not activity.get('actor'):
    #         logger.warning('Outgoing AP activity has no actor!')

    #     return signed_post(url, log_data=True, data=activity).ok

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
