"""ATProto protocol implementation.

https://atproto.com/

TODO
* signup. resolve DID, fetch DID doc, extract PDS
  * use alsoKnownAs as handle? or call getProfile on PDS to get handle?
  * maybe need getProfile to store profile object?
"""
import logging
import re

from flask import abort, g, request
from google.cloud import ndb
from granary import as1
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

from flask_app import app, cache
from granary.bluesky import Bluesky
import common
from common import (
    add,
    error,
    is_blocklisted,
)
from models import Follower, Object, User
from protocol import Protocol

logger = logging.getLogger(__name__)


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
        return Bluesky.user_url(self.handle() or self.key.id())

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

    # @classmethod
    # def target_for(cls, obj, shared=False):
    #     """Returns a relay that the receiving user uses."""
    #     ...
    #     return actor.get('publicInbox') or actor.get('inbox')

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

    # @classmethod
    # def fetch(cls, obj, **kwargs):
    #     """Tries to fetch a ATProto event.

    #     Args:
    #       obj: :class:`Object` with the id to fetch. Fills data into the as2
    #         property.
    #       kwargs: ignored

    #     Returns:
    #       True if the object was fetched and populated successfully,
    #       False otherwise

    #     Raises:
    #       TODO
    #     """
    #     url = obj.key.id()
    #     if not util.is_web(url):
    #         logger.info(f'{url} is not a URL')
    #         return False

    #     resp = None

    #     def _error(extra_msg=None):
    #         msg = f"Couldn't fetch {url} as ActivityStreams 2"
    #         if extra_msg:
    #             msg += ': ' + extra_msg
    #         logger.warning(msg)
    #         # protocol.for_id depends on us raising this when an AP network
    #         # fetch fails. if we change that, update for_id too!
    #         err = BadGateway(msg)
    #         err.requests_response = resp
    #         raise err

    #     def _get(url, headers):
    #         """Returns None if we fetched and populated, resp otherwise."""
    #         nonlocal resp

    #         try:
    #             resp = signed_get(url, headers=headers, gateway=True)
    #         except BadGateway as e:
    #             # ugh, this is ugly, should be something structured
    #             if '406 Client Error' in str(e):
    #                 return
    #             raise

    #         if not resp.content:
    #             _error('empty response')
    #         elif common.content_type(resp) in as2.CONTENT_TYPES:
    #             try:
    #                 return resp.json()
    #             except requests.JSONDecodeError:
    #                 _error("Couldn't decode as JSON")

    #     obj.as2 = _get(url, CONNEG_HEADERS_AS2_HTML)

    #     if obj.as2:
    #         return True
    #     elif not resp:
    #         return False

    #     # look in HTML to find AS2 link
    #     if common.content_type(resp) != 'text/html':
    #         logger.info('no AS2 available')
    #         return False

    #     parsed = util.parse_html(resp)
    #     link = parsed.find('link', rel=('alternate', 'self'), type=(
    #         as2.CONTENT_TYPE, as2.CONTENT_TYPE_LD))
    #     if not (link and link['href']):
    #         logger.info('no AS2 available')
    #         return False

    #     obj.as2 = _get(link['href'], as2.CONNEG_HEADERS)
    #     if obj.as2:
    #         return True

    #     return False

    @classmethod
    def serve(cls, obj):
        """Serves an :class:`Object` as AS2."""
        return (postprocess_as2(as2.from_as1(obj.as1)),
                {'Content-Type': as2.CONTENT_TYPE})
