# coding=utf-8
"""Renders mf2 proxy pages based on stored Responses."""
import datetime

from flask import Flask, request
from granary import as2, atom, microformats2
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.handlers import cache_response
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_loads

import common
from models import Response

CACHE_TIME = datetime.timedelta(minutes=15)

app = Flask(__name__)


@app.route('/render')
# TODO
# @cache_response(CACHE_TIME)
def render():
    source = request.args['source']
    target = request.args['target']

    id = f'{source} {target}'
    with ndb_client.context():
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
