"""Filters for activities.

Every function in this module takes an :class:`models.Object` and optional
:class:`models.User` and returns False or None if it passes and should be handled, or
True if it should be filtered out and discarded.

Filters here should be very cheap. Ideally no network calls, few to no datastore
requests. Memcache is generally ok.

Currently only used in :meth:`Protocol.receive`.

https://github.com/snarfed/bridgy-fed/issues/1941
"""
from datetime import timedelta
from itertools import chain
import logging

from arroba.datastore_storage import AtpRemoteBlob
from granary import as1
from granary.source import html_to_text
from oauth_dropins.webutil import util
from oauth_dropins.webutil.models import Reloader
import requests

import memcache
from memcache import pickle_memcache
from models import Object

logger = logging.getLogger(__name__)

DUPLICATE_CONTENT_EXPIRATION = timedelta(hours=1)

MEDIA_ATTACHMENT_TYPES = ('image', 'video', 'audio')

RELOAD_BLOCKLISTS = timedelta(seconds=10)
CONTENT_BLOCKLIST = Reloader(Object, 'internal:content-blocklist', RELOAD_BLOCKLISTS)
MEDIA_BLOCKLIST = Reloader(Object, 'internal:media-blocklist', RELOAD_BLOCKLISTS)
DOMAIN_BLOCKLIST = Reloader(Object, 'internal:domain-blocklist', RELOAD_BLOCKLISTS)


def _relevant_objects(obj):
    """Returns an Object's relevant AS1 objects to filter on

    Args:
      obj (Object)

    Returns:
      sequence of dict: AS1 objects
    """
    if not obj.as1:
        return []

    objects = [obj.as1]
    if obj.as1.get('verb') in as1.CRUD_VERBS:
        objects.extend(as1.get_objects(obj.as1))

    return objects


def _blocklist_items(blocklist):
    """Reads blocklist items, ignoring leading/trailing whitespace and # comments.

    Also converts all items to lower case.

    TODO: unify with :meth:`Object.domain_blocklist`
    """
    return [val.split('#')[0].strip().lower() for val in blocklist.obj.raw]


def content_blocklisted(obj, from_user=None):
    """Returns True if obj's content matches any string in the content blocklist.

    The blocklist is a list of strings stored in the ``internal:content-blocklist``
    ``Object``. Matching is case-insensitive.
    """
    if not CONTENT_BLOCKLIST.obj or not CONTENT_BLOCKLIST.obj.raw:
        return False

    blocked = _blocklist_items(CONTENT_BLOCKLIST)

    for o in _relevant_objects(obj):
        for field in ('content', 'summary', 'displayName'):
            # don't use granary.source.html_to_text because we don't want Markdown
            text = util.parse_html(o.get(field) or '').get_text(strip=True).lower()
            for val in blocked:
                if val in text:
                    logger.info(f'content_blocklist matched {field}: {val}')
                    return True


def media_blocklisted(obj, from_user=None):
    """Returns True if any media in obj has a hash in the media blocklist.

    The blocklist is a list of CIDs stored in the ``internal:media-blocklist``
    ``Object``. Checks every element in ``image`` and every element in
    ``attachments`` with ``objectType`` ``image``, ``video``, or ``audio``. Uses
    :class:`arroba.datastore_storage.AtpRemoteBlob` to fetch media and get the CID.
    """
    if not MEDIA_BLOCKLIST.obj or not MEDIA_BLOCKLIST.obj.raw:
        return False

    blocked = _blocklist_items(MEDIA_BLOCKLIST)

    for o in _relevant_objects(obj):
        att_urls = [util.get_url(att) if att['objectType'] == 'image'
                    else as1.get_object(att, 'stream').get('url')
                    for att in as1.get_objects(o, 'attachments')
                    if att.get('objectType') in MEDIA_ATTACHMENT_TYPES]
        urls = util.dedupe_urls(att_urls + util.get_urls(o, 'image'))

        for url in urls:
            try:
                blob = AtpRemoteBlob.get_or_create(url=url, get_fn=util.requests_get)
            except requests.RequestException as e:
                continue  # requests_get logged the failure

            if blob.cid in blocked:
                logger.info(f'media_blocklisted matched url {url} cid {blob.cid}')
                return True


def domain_blocklisted(obj, from_user=None):
    """Returns True if obj or from_user matches the global domain blocklist.

    The blocklist is a list of domains stored in the ``internal:domain-blocklist``
    ``Object``. Checks the object's id, actor/author, and ``from_user``.
    """
    if not DOMAIN_BLOCKLIST.obj:
        return False

    candidates = [from_user] + list(chain.from_iterable(
        [o.get('id'), as1.get_owner(o)] for o in _relevant_objects(obj)))

    for candidate in candidates:
        if candidate and DOMAIN_BLOCKLIST.obj.domain_blocklist_matches(candidate):
            logger.info(f'domain_blocklisted matched {candidate}')
            return True


def duplicate_content(obj, from_user=None):
    """Returns True if this user recently posted the exact same content.

    Uses memcache with key ``f'{user_id} {text_content}'``.

    Args:
      obj (models.Object)
      from_user (models.User or None)

    Returns:
      bool
    """
    user_id = from_user.key.id() if from_user else as1.get_owner(obj.as1)
    if not user_id or not obj.as1:
        return False

    obj_as1 = (as1.get_object(obj.as1) if obj.as1.get('verb') in as1.CRUD_VERBS
               else obj.as1)
    if not (content := obj_as1.get('content')):
        return False
    elif not (text := util.parse_html(content).get_text()):
        return False

    key = memcache.key(f'{user_id} {text}')
    if cached := pickle_memcache.get(key):
        if not as1.activity_changed(cached, obj.as1):
            logger.info(f'duplicate_content matched {key}')
            return True
    else:
        # store and compare full AS1 object, allow eg same text with a different image
        pickle_memcache.set(key, obj.as1,
                            expire=int(DUPLICATE_CONTENT_EXPIRATION.total_seconds()))

    return False
