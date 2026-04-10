"""Farcaster protocol implementation.

https://farcaster.xyz/
https://github.com/farcasterxyz/protocol/blob/main/docs/SPECIFICATION.md
https://snapchain.farcaster.xyz/
"""
import logging

from google.cloud import ndb
import granary.farcaster

from models import User
from protocol import Protocol

logger = logging.getLogger(__name__)


class Farcaster(User, Protocol):
    """Farcaster class.

    Key id is string fid.
    """
    ABBREV = 'fc'
    PHRASE = 'Farcaster'
    LOGO_EMOJI = '🏛️'
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    HAS_COPIES = True

    def fid(self):
        """Returns this user's Farcaster FID as an integer.

        Returns:
          int
        """
        return int(self.key.id())

    @ndb.ComputedProperty
    def handle(self):
        """Returns the Farcaster username from the user's profile."""
        # TODO: switch to self.obj.fc's USER_DATA_TYPE_USERNAME
        if self.obj and self.obj.as1:
            if username := self.obj.as1.get('username'):
                return username

        if self.key:
            return self.key.id()

    def web_url(self):
        if self.key:
            return granary.farcaster.Farcaster.user_url(self.fid())
