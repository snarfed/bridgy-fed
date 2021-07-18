# coding=utf-8
"""Renders mf2 proxy pages based on stored Responses."""
import datetime

from flask import request
from granary import as2, atom, microformats2
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.util import json_loads

from app import app, cache
import common
from common import error
from models import Response

CACHE_TIME = datetime.timedelta(minutes=15)


@app.get('/render')
@cache.cached(timeout=CACHE_TIME.total_seconds(), query_string=True,
              response_filter=flask_util.not_5xx)
def render():
    """Fetches a stored Response and renders it as HTML."""
    source = flask_util.get_required_param('source')
    target = flask_util.get_required_param('target')

    id = f'{source} {target}'
    resp = Response.get_by_id(id)
    if not resp:
        return error(f'No stored response for {id}', status=404)

    if resp.source_mf2:
        as1 = microformats2.json_to_object(json_loads(resp.source_mf2))
    elif resp.source_as2:
        as1 = as2.to_as1(json_loads(resp.source_as2))
    elif resp.source_atom:
        as1 = atom.atom_to_activity(resp.source_atom)
    else:
        return error(f'Stored response for {id} has no data', status=404)

    # add HTML meta redirect to source page. should trigger for end users in
    # browsers but not for webmention receivers (hopefully).
    html = microformats2.activities_to_html([as1])
    utf8 = '<meta charset="utf-8">'
    refresh = f'<meta http-equiv="refresh" content="0;url={source}">'
    return html.replace(utf8, utf8 + '\n' + refresh)
