"""Serves ``/convert/...`` URLs to convert data from one protocol to another.

URL pattern is ``/convert/SOURCE/DEST``, where ``SOURCE`` and ``DEST`` are the
``LABEL`` constants from the :class:`protocol.Protocol` subclasses.
"""
import logging
import re
from urllib.parse import quote, unquote

from flask import g, redirect, request
from granary import as1
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error

from activitypub import ActivityPub
from common import CACHE_TIME, LOCAL_DOMAINS, subdomain_wrap, SUPERDOMAIN
from flask_app import app, cache
from models import Object, PROTOCOLS
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)


@app.get(f'/convert/<dest>/<path:_>')
@flask_util.cached(cache, CACHE_TIME, headers=['Accept'])
def convert(dest, _, src=None):
    """Converts data from one protocol to another and serves it.

    Fetches the source data if it's not already stored.

    Args:
      dest (str): protocol
      src (str): protocol, only used when called by
        :func:`convert_source_path_redirect`
    """
    if src:
        src_cls = PROTOCOLS.get(src)
        if not src_cls:
            error(f'No protocol found for {src}', status=404)
        logger.info(f'Overriding any domain protocol with {src}')
    else:
        src_cls = Protocol.for_request(fed=Protocol)
    if not src_cls:
        error(f'Unknown protocol {request.host.removesuffix(SUPERDOMAIN)}', status=404)

    dest_cls = PROTOCOLS.get(dest)
    if not dest_cls:
        error('Unknown protocol {dest}', status=404)

    # don't use urllib.parse.urlencode(request.args) because that doesn't
    # guarantee us the same query param string as in the original URL, and we
    # want exactly the same thing since we're looking up the URL's Object by id
    path_prefix = f'convert/{dest}/'
    id = unquote(request.url.removeprefix(request.root_url).removeprefix(path_prefix))

    # our redirects evidently collapse :// down to :/ , maybe to prevent URL
    # parsing bugs? if that happened to this URL, expand it back to ://
    id = re.sub(r'^(https?:/)([^/])', r'\1/\2', id)

    logger.info(f'Converting from {src_cls.LABEL} to {dest}: {id}')

    # load, and maybe fetch. if it's a post/update, redirect to inner object.
    obj = src_cls.load(id)
    if not obj:
        error(f"Couldn't load {id}", status=404)
    elif not obj.as1:
        error(f'Stored object for {id} has no data', status=404)

    type = as1.object_type(obj.as1)
    if type in ('post', 'update', 'delete'):
        obj_id = as1.get_object(obj.as1).get('id')
        if obj_id:
            obj_obj = src_cls.load(obj_id, remote=False)
            if (obj_obj and obj_obj.as1
                    and not obj_obj.as1.keys() <= set(['id', 'url', 'objectType'])):
                logger.info(f'{type} activity, redirecting to Object {obj_id}')
                return redirect(f'/{path_prefix}{obj_id}', code=301)

    # don't serve deletes or deleted objects
    if obj.deleted or type == 'delete':
        return '', 410

    # convert and serve
    return dest_cls.convert(obj), {'Content-Type': dest_cls.CONTENT_TYPE}


@app.get('/render')
def render_redirect():
    """Redirect from old /render?id=... endpoint to /convert/..."""
    id = flask_util.get_required_param('id')
    return redirect(subdomain_wrap(ActivityPub, f'/convert/web/{id}'), code=301)


@app.get(f'/convert/<src>/<dest>/<path:_>')
def convert_source_path_redirect(src, dest, _):
    """Old route that included source protocol in path instead of subdomain.

    DEPRECATED! Only kept to support old webmention source URLs.
    """
    if Protocol.for_request() not in (None, 'web'):  # no per-protocol subdomains
        error(f'Try again on fed.brid.gy', status=404)

    # in prod, eg gunicorn, the path somehow gets URL-decoded before we see
    # it, so we need to re-encode.
    new_path = quote(request.full_path.rstrip('?').replace(f'/{src}/', '/'),
                     safe=':/%')

    if request.host in LOCAL_DOMAINS:
        request.url = request.url.replace(f'/{src}/', '/')
        return convert(dest, None, src)

    proto = PROTOCOLS.get(src)
    if not proto:
        error(f'No protocol found for {src}', status=404)

    return redirect(subdomain_wrap(proto, new_path), code=301)
