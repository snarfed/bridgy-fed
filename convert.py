"""Serves /convert/... URLs to convert data from one protocol to another.

URL pattern is /convert/SOURCE/DEST , where SOURCE and DEST are the LABEL
constants from the :class:`Protocol` subclasses.

Currently only supports /convert/activitypub/webmention/...
"""
import logging
import re
import urllib.parse

from flask import request
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error

from activitypub import ActivityPub
from common import CACHE_TIME
from flask_app import app, cache
from protocol import protocols
from webmention import Webmention

logger = logging.getLogger(__name__)

SOURCES = frozenset((
    ActivityPub.LABEL,
))
DESTS = frozenset((
    Webmention.LABEL,
))


@app.get(f'/convert/<any({",".join(SOURCES)}):src>/<any({",".join(DESTS)}):dest>/<path:url>')
@flask_util.cached(cache, CACHE_TIME, headers=['Accept'])
def convert(src, dest, url):
    """Converts data from one protocol to another and serves it.

    Fetches the source data if it's not already stored.
    """
    if request.args:
        url += '?' + urllib.parse.urlencode(request.args)
    # some browsers collapse repeated /s in the path down to a single slash.
    # if that happened to this URL, expand it back to two /s.
    url = re.sub(r'^(https?:/)([^/])', r'\1/\2', url)

    if not util.is_web(url):
        error(f'Expected fully qualified URL; got {url}')

    obj = protocols[src].load(url)
    return protocols[dest].serve(obj)
