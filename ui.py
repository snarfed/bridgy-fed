"""Stub protocol class for internal objects, ie objects that we create ourselves.

"UI" isn't an ideal name. It now includes internal objects broadly, eg responses
that users create via the Mastodon API, not just objects created via our own UI(s).

Examples of where we currently create these:

* Responses generated in pages.respond_*
* Interactions with unbridged users and objects via our Mastodon API

(follow.py's follows and dms.py's DMs aren't internal objects. Their ids are in
their author's id space, eg ``https://user.com/#follow-...``, so their
``source_protocol`` is their author's protocol.)

* Ids are ``ui:...``, opaque and protocol independent. Nothing should parse them.
* ``source_protocol`` is ``ui``.
* ``users`` must be populated with the *author's* key.
  :meth:`models.Object._pre_put_hook` asserts it.
* Get the author's protocol via :meth:`models.Object.owner_protocol`, which uses
  ``users`` if available, then falls back to ``author``/``actor`` ids.
* :meth:`ids.translate_object_id` etc always wrap these ids on ``fed.brid.gy``, eg
  ``https://fed.brid.gy/convert/ap/ui:...``, which we serve from
  :func:`convert.convert`. They're ours, not their author's protocol's, and a given
  id should always be the same URL, whoever its author is.
"""
import logging

from google.cloud import ndb

import models
import protocol

logger = logging.getLogger(__name__)


class UIProtocol(models.User, protocol.Protocol):
    LABEL = 'ui'
    # no ui.brid.gy; make subdomain_wrap falls back to fed.brid.gy
    ABBREV = None
    SUPPORTED_AS1_TYPES = ('comment', 'block', 'delete', 'follow', 'like', 'note',
                           'post', 'share', 'undo')

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

    @classmethod
    def bot_user_id(cls):
        return None
