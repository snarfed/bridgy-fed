"""Admin pages and endpoints: admin UI, hub status, memcache API, etc."""
from datetime import datetime
import logging

from google.cloud.ndb import Key

import arroba.server
from common import (
    secret_key_auth,
)
from flask import redirect, request
from flask_app import app
import filters
import memcache
import models
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import flash
import pytz

from pages import render

BLOCKLISTS = {
    bl.key_id: bl for bl in (
        filters.CONTENT_BLOCKLIST,
        filters.MEDIA_BLOCKLIST,
        filters.DOMAIN_BLOCKLIST,
    )
}

logger = logging.getLogger(__name__)


#
# admin UI
#
@app.get('/admin/')
def admin_home():
    for reloader in BLOCKLISTS.values():
        reloader.reload()
    return render('admin.html', filters=filters)


@app.post('/admin/blocklist/<id>')
def save_blocklist(id):
    values = [v.strip() for v in request.values['values'].splitlines() if v.strip()]
    BLOCKLISTS[id].obj.raw = values
    BLOCKLISTS[id].obj.put()
    flash(f'Saved {id}.')
    return redirect('/admin/')


@app.post('/admin/user')
def admin_user_lookup():
    id = flask_util.get_required_param('id')
    try:
        user = models.load_user(id, allow_opt_out=True)
        return redirect(f'/admin/user/{user.key.urlsafe().decode()}')
    except (AttributeError, RuntimeError, ValueError) as e:
        flash(str(e))
        return redirect('/admin/')


@app.get('/admin/user/<key>')
def admin_user(key):
    user = Key(urlsafe=key).get()
    if not user or not isinstance(user, models.User):
        flask_util.error('user not found', status=404)

    vars = {}

    pt = pytz.timezone('US/Pacific')
    for field in 'created', 'updated':
        # these are proto.datetime_helpers.DatetimeWithNanoseconds. have to recreate
        # them as plain datetimes because otherwise they crash on replace().
        # similar to: https://stackoverflow.com/q/54370012/186123
        vars[field] = datetime.fromtimestamp(getattr(user, field).timestamp()
                                             ).replace(microsecond=0).astimezone(pt)

    return render(
        'admin_user.html',
        user=user,
        **vars,
    )


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
