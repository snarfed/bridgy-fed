"""Stub UI Protocol class, for objects created in the UI.

Needed for serving /convert/ui/web/... requests.
"""
from oauth_dropins.webutil import util

from google.cloud import ndb

import models
import protocol


class UIProtocol(models.User, protocol.Protocol):
    LABEL = 'ui'
    SUPPORTED_AS1_TYPES = ('comment', 'like', 'note', 'post', 'share')

    def _pre_put_hook(self):
        raise NotImplementedError()

    @classmethod
    def owns_id(self, id):
        if id.startswith('ui:'):
            return True
        elif util.is_web(id) and not self.is_blocklisted(id, allow_internal=True):
            return None

        return False

    @ndb.ComputedProperty
    def handle(self):
        return None

    @classmethod
    def handle_to_id(cls, handle):
        return None

    @classmethod
    def create_for(cls, user):
        raise ValueError()

    @classmethod
    def send(to_cls, *args, **kwargs):
        return False

    @classmethod
    def fetch(cls, obj, **kwargs):
        return False

    @classmethod
    def target_for(cls, obj, **kwargs):
        return None

