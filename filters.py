"""Filters for activities.

Every function in this module takes an :class:`Object` and returns False or None if
it passes and should be handled, or True if it should be filtered out and discarded.

Currently only used in :meth:`Protocol.receive`.

https://github.com/snarfed/bridgy-fed/issues/1941
"""
import logging

from granary import as1
from granary.source import html_to_text
from oauth_dropins.webutil import util

from memcache import memcache

logger = logging.getLogger(__name__)

CONTENT_BLOCKLIST_KEY = 'content-blocklist'


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
