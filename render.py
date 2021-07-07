# coding=utf-8
"""Renders mf2 proxy pages based on stored Responses."""
import datetime

from flask import Flask, request
from flask_caching import Cache
from granary import as2, atom, microformats2
from oauth_dropins.webutil import appengine_config, handlers
from oauth_dropins.webutil.util import json_loads

import common
from models import Response

CACHE_TIME = datetime.timedelta(minutes=15)

app = Flask('bridgy-fed')
app.config.from_mapping({'CACHE_TYPE': 'SimpleCache'})
app.wsgi_app = handlers.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)
cache = Cache(app)


def not_5xx(resp):
    return isinstance(resp, tuple) and resp[1] // 100 != 5


@app.route('/render')
@cache.cached(timeout=CACHE_TIME.total_seconds(), query_string=True,
              response_filter=not_5xx)
def render():
    source = common.get_required_param(request, 'source')
    target = common.get_required_param(request, 'target')

    id = f'{source} {target}'
    resp = Response.get_by_id(id)
    if not resp:
        return (f'No stored response for {id}', 404)

    if resp.source_mf2:
        as1 = microformats2.json_to_object(json_loads(resp.source_mf2))
    elif resp.source_as2:
        as1 = as2.to_as1(json_loads(resp.source_as2))
    elif resp.source_atom:
        as1 = atom.atom_to_activity(resp.source_atom)
    else:
        return (f'Stored response for {id} has no data', 404)

    # add HTML meta redirect to source page. should trigger for end users in
    # browsers but not for webmention receivers (hopefully).
    html = microformats2.activities_to_html([as1])
    utf8 = '<meta charset="utf-8">'
    refresh = f'<meta http-equiv="refresh" content="0;url={source}">'
    return html.replace(utf8, utf8 + '\n' + refresh)
