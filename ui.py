"""Stub UI Protocol class, for objects created in the UI.

Needed for serving /convert/ui/webmention/... requests.
"""
from protocol import Protocol


class UIProtocol(Protocol):
    LABEL = 'ui'
