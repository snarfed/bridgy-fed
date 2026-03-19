"""Admin pages and endpoints: admin UI, hub status, memcache API, etc."""
import logging

from google.cloud.ndb import Key

import arroba.server
from common import (
    render_template,
    secret_key_auth,
)
from flask import request
from flask_app import app
import memcache
from oauth_dropins.webutil import flask_util, logs, util

logger = logging.getLogger(__name__)


#
# internal Memcache API, since we can't connect to our Memorystore instance externally
# https://github.com/snarfed/bridgy-fed/issues/1472
#
@app.get('/admin/memcache/get')
@secret_key_auth
@flask_util.headers({'Content-Type': 'text/plain'})
def memcache_get():
    if key := request.values.get('key'):
        return repr(Key(urlsafe=key).get(use_cache=False, use_datastore=False,
                                         use_global_cache=True))
    elif raw := request.values.get('raw'):
        return repr(memcache.memcache.get(raw))
    else:
        error('either key or raw are required')


@app.post('/admin/memcache/evict')
@secret_key_auth
@flask_util.headers({'Content-Type': 'text/plain'})
def memcache_evict():
    if key := request.values.get('key'):
        memcache.evict(Key(urlsafe=key))
        return ''
    elif raw := request.values.get('raw'):
        deleted = memcache.evict_raw(raw)
        return 'deleted' if deleted else 'not found'
    else:
        error('either key or raw are required')


@app.post('/admin/sequences/alloc')
@secret_key_auth
@flask_util.headers({'Content-Type': 'text/plain'})
def alloc_seq():
    nsid = flask_util.get_required_param('nsid')
    result = arroba.server.storage.sequences.allocate(nsid)
    return str(result)


@app.get('/admin/sequences/last')
@secret_key_auth
@flask_util.headers({'Content-Type': 'text/plain'})
def last_seq():
    nsid = flask_util.get_required_param('nsid')
    result = arroba.server.storage.sequences.last(nsid)
    return str(result)
