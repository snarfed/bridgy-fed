"""Serves ``/convert/...`` URLs to convert data from one protocol to another.

URL pattern is ``/convert/SOURCE/DEST``, where ``SOURCE`` and ``DEST`` are the
``LABEL`` constants from the :class:`protocol.Protocol` subclasses.
"""
import logging
import re
from urllib.parse import quote, unquote

from flask import redirect, request
from granary import as1
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error

from activitypub import ActivityPub
from common import (
    CACHE_CONTROL_VARY_ACCEPT,
    LOCAL_DOMAINS,
    subdomain_wrap,
    SUPERDOMAIN,
)
from flask_app import app
from models import Object, PROTOCOLS
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)


@app.get(f'/convert/<to>/<path:_>')
@flask_util.headers(CACHE_CONTROL_VARY_ACCEPT)
def convert(to, _, from_=None):
    """Converts data from one protocol to another and serves it.

    Fetches the source data if it's not already stored.

    Args:
      to (str): protocol
      from_ (str): protocol, only used when called by
        :func:`convert_source_path_redirect`
    """
    if from_:
        from_proto = PROTOCOLS.get(from_)
        if not from_proto:
            error(f'No protocol found for {from_}', status=404)
        logger.info(f'Overriding any domain protocol with {from_}')
    else:
        from_proto = Protocol.for_request(fed=Protocol)
    if not from_proto:
        error(f'Unknown protocol {request.host.removesuffix(SUPERDOMAIN)}', status=404)

    to_proto = PROTOCOLS.get(to)
    if not to_proto:
        error('Unknown protocol {to}', status=404)

    # don't use urllib.parse.urlencode(request.args) because that doesn't
    # guarantee us the same query param string as in the original URL, and we
    # want exactly the same thing since we're looking up the URL's Object by id
    path_prefix = f'convert/{to}/'
    id = unquote(request.url.removeprefix(request.root_url).removeprefix(path_prefix))

    # our redirects evidently collapse :// down to :/ , maybe to prevent URL
    # parsing bugs? if that happened to this URL, expand it back to ://
    id = re.sub(r'^(https?:/)([^/])', r'\1/\2', id)

    logger.debug(f'Converting from {from_proto.LABEL} to {to}: {id}')

    # load, and maybe fetch. if it's a post/update, redirect to inner object.
    obj = from_proto.load(id)
    if not obj:
        error(f"Couldn't load {id}", status=404)
    elif not obj.as1:
        error(f'Stored object for {id} has no data', status=404)

    type = as1.object_type(obj.as1)
    if type in as1.CRUD_VERBS or type == 'share':
        if obj_id := as1.get_object(obj.as1).get('id'):
            if obj_obj := from_proto.load(obj_id, remote=False):
                if type == 'share':
                    # TODO: should this be Source.base_object? That's broad
                    # though, includes inReplyTo
                    check_bridged_to(obj_obj, to_proto=to_proto)
                elif (type in as1.CRUD_VERBS
                      and obj_obj.as1
                      and obj_obj.as1.keys() - set(['id', 'url', 'objectType'])):
                    logger.info(f'{type} activity, redirecting to Object {obj_id}')
                    return redirect(f'/{path_prefix}{obj_id}', code=301)

    check_bridged_to(obj, to_proto=to_proto)

    # convert and serve
    return to_proto.convert(obj), {
        'Content-Type': to_proto.CONTENT_TYPE,
    }


def check_bridged_to(obj, to_proto):
    """If ``object`` or its owner isn't bridged to ``to_proto``, raises :class:`werkzeug.exceptions.HTTPException`.

    Args:
      obj (models.Object)
      to_proto (subclass of protocol.Protocol)
    """
    # don't serve deletes or deleted objects
    if obj.deleted or obj.type == 'delete':
        error('Deleted', status=410)

    # don't serve for a given protocol if we haven't bridged it there
    if to_proto.HAS_COPIES and not obj.get_copy(to_proto):
        error(f"{obj.key.id()} hasn't been bridged to {to_proto.LABEL}", status=404)

    # check that owner has this protocol enabled
    if owner := as1.get_owner(obj.as1):
        if from_proto := Protocol.for_id(owner):
            user = from_proto.get_by_id(owner)
            if not user:
                error(f"{from_proto.LABEL} user {owner} not found", status=404)
            elif not user.is_enabled(to_proto):
                error(f"{from_proto.LABEL} user {owner} isn't bridged to {to_proto.LABEL}", status=404)


@app.get(f'/convert/<from_>/<to>/<path:_>')
def convert_source_path_redirect(from_, to, _):
    """Old route that included source protocol in path instead of subdomain.

    DEPRECATED! Only kept to support old webmention source URLs.
    """
    if Protocol.for_request() not in (None, 'web'):  # no per-protocol subdomains
        error(f'Try again on fed.brid.gy', status=404)

    # in prod, eg gunicorn, the path somehow gets URL-decoded before we see
    # it, so we need to re-encode.
    new_path = quote(request.full_path.rstrip('?').replace(f'/{from_}/', '/'),
                     safe=':/%')

    if request.host in LOCAL_DOMAINS:
        request.url = request.url.replace(f'/{from_}/', '/')
        return convert(to, None, from_=from_)

    proto = PROTOCOLS.get(from_)
    if not proto:
        error(f'No protocol found for {from_}', status=404)

    return redirect(subdomain_wrap(proto, new_path), code=301)
