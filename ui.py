"""Stub UI Protocol class, for objects created in the UI.

Needed for serving /convert/ui/web/... requests.
"""
from models import User
from protocol import Protocol


class UIProtocol(User, Protocol):
    LABEL = 'ui'

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

