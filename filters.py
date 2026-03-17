"""Filters for activities.

Every function in this module takes an :class:`Object` and returns False or None if
it passes and should be handled, or True if it should be filtered out and discarded.

Filters here should be very cheap. Ideally no network calls, few to no datastore
requests. Memcache is generally ok.

Currently only used in :meth:`Protocol.receive`.

https://github.com/snarfed/bridgy-fed/issues/1941
"""
import logging

from arroba.datastore_storage import AtpRemoteBlob
from granary import as1
from granary.source import html_to_text
from oauth_dropins.webutil import util
import requests

from memcache import memcache
from models import Object

logger = logging.getLogger(__name__)

CONTENT_BLOCKLIST_KEY = 'content-blocklist'
MEDIA_BLOCKLIST_KEY = 'media-blocklist'
MEDIA_ATTACHMENT_TYPES = ('image', 'video', 'audio')

# GLOBAL_DOMAIN_BLOCKLIST = Object.get_by_id('global-domain-blocklist')


def content_blocklisted(obj):
    """Returns True if obj's content matches any string in the content blocklist.

    The blocklist is a newline-separated list of strings stored in memcache
    at key ``content-blocklist``. Matching is case-insensitive.

    Args:
      obj (models.Object)

    Returns:
      bool
    """
    raw = memcache.get(CONTENT_BLOCKLIST_KEY)
    if not raw:
        return False

    blocked = [s.strip().lower() for s in raw.splitlines()]

    objects = [obj.as1]
    if obj.as1.get('verb') in as1.CRUD_VERBS:
        objects.extend(as1.get_objects(obj.as1))

    for o in objects:
        for field in ('content', 'summary', 'displayName'):
            # don't use granary.source.html_to_text because we don't want Markdown
            text = util.parse_html(o.get(field) or '').get_text(strip=True).lower()
            for val in blocked:
                if val in text:
                    logger.info(f'content_blocklist matched {field}: {val}')
                    return True


def media_blocklisted(obj):
    """Returns True if any media in obj has a hash in the media blocklist.

    The blocklist is a newline-separated list of CIDs stored in memcache at key
    ``media-blocklist``. Checks every element in ``image`` and every element
    in ``attachments`` with ``objectType`` ``image``, ``video``, or ``audio``.
    Uses :class:`arroba.datastore_storage.AtpRemoteBlob` to fetch media and get
    the CID.

    Args:
      obj (models.Object)

    Returns:
      bool
    """
    if not (raw := memcache.get(MEDIA_BLOCKLIST_KEY)):
        return False

    if not (blocked := set(s.strip() for s in raw.splitlines())):
        return False

    objects = [obj.as1]
    if obj.as1.get('verb') in as1.CRUD_VERBS:
        objects.extend(as1.get_objects(obj.as1))

    for o in objects:
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
