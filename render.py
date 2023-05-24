"""Renders mf2 proxy pages based on stored Object entities."""
import datetime
import logging
from urllib.parse import urlencode

from flask import redirect, request
from granary import as1, as2, atom, microformats2
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil import util

import activitypub
from flask_app import app, cache
import common
from models import Object
from webmention import Webmention

logger = logging.getLogger(__name__)


@app.get('/render')
@flask_util.cached(cache, common.CACHE_TIME)
def render():
    """Fetches a stored Object and renders it as HTML."""
    id = flask_util.get_required_param('id')
    obj = Object.get_by_id(id)
    if not obj:
        error(f'No stored object for {id}', status=404)
    elif not obj.as1:
        error(f'Stored object for {id} has no AS1', status=404)

    # redirect creates, updates, etc to inner object
    type = as1.object_type(obj.as1)
    if type in ('post', 'update', 'delete'):
        obj_id = as1.get_object(obj.as1).get('id')
        if obj_id:
            obj_obj = Object.get_by_id(obj_id)
            if (obj_obj and obj_obj.as1 and
                not obj_obj.as1.keys() <= set(['id', 'url', 'objectType'])):
                logger.info(f'{type} activity, redirecting to Object {obj_id}')
                return redirect('/render?' + urlencode({'id': obj_id}), code=301)

    if obj.deleted or type == 'delete':
        return '', 410

    return Webmention.serve(obj)
