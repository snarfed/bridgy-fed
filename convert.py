"""Serves /convert/... URLs to convert data from one protocol to another.

URL pattern is /convert/SOURCE/DEST , where SOURCE and DEST are the LABEL
constants from the :class:`Protocol` subclasses.
"""
import logging
import re
import urllib.parse

from flask import g, redirect, request
from granary import as1
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error

from activitypub import ActivityPub
from common import CACHE_TIME, SUPERDOMAIN
from flask_app import app, cache
from models import Object, PROTOCOLS
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)

SOURCES = frozenset((
    ActivityPub.ABBREV,
    ActivityPub.LABEL,
    Web.ABBREV,
    Web.LABEL,
))
DESTS = frozenset((
    ActivityPub.ABBREV,
    ActivityPub.LABEL,
    Web.ABBREV,
    Web.LABEL,
))


@app.get(f'/convert/<any({",".join(DESTS)}):dest>/<path:_>')
@flask_util.cached(cache, CACHE_TIME, headers=['Accept'])
def convert(dest, _):
    """Converts data from one protocol to another and serves it.

    Fetches the source data if it's not already stored.
    """
    src_cls = Protocol.for_request()
    if not src_cls:
        error(f'Unknown protocol {request.host.removesuffix(SUPERDOMAIN)}', status=404)

    # don't use urllib.parse.urlencode(request.args) because that doesn't
    # guarantee us the same query param string as in the original URL, and we
    # want exactly the same thing since we're looking up the URL's Object by id
    path_prefix = f'convert/{dest}/'
    url = request.url.removeprefix(request.root_url).removeprefix(path_prefix)

    # our redirects evidently collapse :// down to :/ , maybe to prevent URL
    # parsing bugs? if that happened to this URL, expand it back to ://
    url = re.sub(r'^(https?:/)([^/])', r'\1/\2', url)

    if not util.is_web(url):
        error(f'Expected fully qualified URL; got {url}')

    # require g.user for AP since postprocess_as2 currently needs it. ugh
    dest_cls = PROTOCOLS[dest]
    if dest_cls == ActivityPub:
        domain = util.domain_from_link(url, minimize=False)
        g.user = Web.get_by_id(domain)
        if not g.user:
            error(f'No web user found for {domain}')

    # load, and maybe fetch. if it's a post/update, redirect to inner object.
    obj = src_cls.load(url)
    if not obj.as1:
        error(f'Stored object for {id} has no data', status=404)

    type = as1.object_type(obj.as1)
    if type in ('post', 'update', 'delete'):
        obj_id = as1.get_object(obj.as1).get('id')
        if obj_id:
            # TODO: PROTOCOLS[src].load() this instead?
            obj_obj = Object.get_by_id(obj_id)
            if (obj_obj and obj_obj.as1 and
                not obj_obj.as1.keys() <= set(['id', 'url', 'objectType'])):
                logger.info(f'{type} activity, redirecting to Object {obj_id}')
                return redirect(f'/{path_prefix}{obj_id}', code=301)

    # don't serve deletes or deleted objects
    if obj.deleted or type == 'delete':
        return '', 410

    # convert and serve
    return dest_cls.serve(obj)


@app.get('/render')
def render_redirect():
    """Redirect from old /render?id=... endpoint to /convert/..."""
    id = flask_util.get_required_param('id')
    return redirect(ActivityPub.subdomain_url(f'/convert/web/{id}'), code=301)


@app.get(f'/convert/<any({",".join(SOURCES)}):src>/<any({",".join(DESTS)}):dest>/<path:_>')
def convert_source_path_redirect(src, dest, _):
    """Old route that included source protocol in path instead of subdomain."""
    if Protocol.for_request() not in (None, 'web'):  # no per-protocol subdomains
        error(f'Try again on fed.brid.gy', status=404)

    new_path = request.full_path.replace(f'/{src}/', '/')
    return redirect(PROTOCOLS[src].subdomain_url(new_path), code=301)
