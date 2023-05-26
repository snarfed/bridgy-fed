"""Stub UI Protocol class, for objects created in the UI.

Needed for serving /convert/ui/webmention/... requests.
"""
from models import User
from protocol import Protocol


class UIProtocol(User, Protocol):
    LABEL = 'ui'
