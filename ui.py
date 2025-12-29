"""Stub UI Protocol class, for objects created in the UI.

Needed for serving /convert/ui/web/... requests.
"""
from google.cloud import ndb

import models
import protocol


class UIProtocol(models.User, protocol.Protocol):
    LABEL = 'ui'

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

