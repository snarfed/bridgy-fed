# coding=utf-8
"""Renders mf2 proxy pages based on stored Activity entities."""
import datetime

from flask import request
from granary import as2, atom, microformats2
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_loads

from app import app, cache
import common
from models import Activity

CACHE_TIME = datetime.timedelta(minutes=15)


@app.get('/render')
@flask_util.cached(cache, CACHE_TIME)
def render():
    """Fetches a stored Activity and renders it as HTML."""
    source = flask_util.get_required_param('source')
    target = flask_util.get_required_param('target')

    id = f'{source} {target}'
    activity = Activity.get_by_id(id)
    if not activity:
        error(f'No stored activity for {id}', status=404)

    if activity.source_mf2:
        as1 = microformats2.json_to_object(json_loads(activity.source_mf2))
    elif activity.source_as2:
        as1 = as2.to_as1(json_loads(activity.source_as2))
    elif activity.source_atom:
        as1 = atom.atom_to_activity(activity.source_atom)
    else:
        error(f'Stored activity for {id} has no data', status=404)

    # add HTML meta redirect to source page. should trigger for end users in
    # browsers but not for webmention receivers (hopefully).
    html = microformats2.activities_to_html([as1])
    utf8 = '<meta charset="utf-8">'
    refresh = f'<meta http-equiv="refresh" content="0;url={source}">'
    return html.replace(utf8, utf8 + '\n' + refresh)
