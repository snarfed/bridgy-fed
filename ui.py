"""Stub protocol class for internal objects, ie objects that we create ourselves.

"UI" isn 't an ideal name. It now includes internal objects broadly, eg responses
that users create via the Mastodon API, not just objects created via our own UI(s).

Examples of where we currently create these:

* Follows generated in follow.py (except their ids are often URLs instead)
* Responses generated in pages.respond_*
* Interactions with unbridged users via our Mastodon and PDS APIs.

(DMs we send in dms.py use web URLs instead.)

* Ids are ``ui:...``, opaque and protocol independent. Nothing should parse them.
* ``source_protocol`` is ``ui``.
* ``users` should be populated with the *author's* key.
* Get the author's protocol via :meth:`models.Object.owner_protocol`, which uses
  ``users` if available, then falls back to ``author``/``actor`` ids.
* :meth:`protocol.Protocol.translate_ids` etc generates ids on the author's protocol
  subdomain, eg ``https://bsky.brid.gy/convert/ap/ui:...``, which we serve from
  :func:`convert.convert`.
"""
import logging

from google.cloud import ndb

import models
import protocol

logger = logging.getLogger(__name__)


class UIProtocol(models.User, protocol.Protocol):
    LABEL = 'ui'
    SUPPORTED_AS1_TYPES = ('comment', 'block', 'like', 'note', 'post', 'share')

    def _pre_put_hook(self):
        raise NotImplementedError()

    @classmethod
    def owns_id(self, id):
        return id.startswith('ui:')

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
    def load(cls, id, remote=None, **kwargs):
        """We're the origin for internal objects, so they're never fetchable."""
        if remote:
            logger.info(f'Overriding remote=True to remote=False for UIProtocol.load of{id} because ui: objects are internal only')

        return super().load(id, remote=False, **kwargs)

    @classmethod
    def target_for(cls, obj, **kwargs):
        return None

