"""Renders mf2 proxy pages based on stored Object entities."""
import datetime
import logging
from urllib.parse import urlencode

from flask import redirect, request
from granary import as1, as2, atom, microformats2
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil import util

from app import app, cache
import common
from models import Object

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

    type = as1.object_type(obj.as1)
    if type in ('post', 'update', 'delete'):
        # redirect to inner object
        obj_id = as1.get_object(obj.as1).get('id')
        if obj_id:
            obj_obj = Object.get_by_id(obj_id)
            if (obj_obj and obj_obj.as1 and
                not obj_obj.as1.keys() <= set(['id', 'url', 'objectType'])):
                logger.info(f'{type} activity, redirecting to Object {obj_id}')
                return redirect('/render?' + urlencode({'id': obj_id}), code=301)

    if obj.deleted or type == 'delete':
        return '', 410

    # add HTML meta redirect to source page. should trigger for end users in
    # browsers but not for webmention receivers (hopefully).
    html = microformats2.activities_to_html([obj.as1])
    utf8 = '<meta charset="utf-8">'
    url = util.get_url(obj.as1)
    if url:
        refresh = f'<meta http-equiv="refresh" content="0;url={url}">'
        html = html.replace(utf8, utf8 + '\n' + refresh)

    return html
