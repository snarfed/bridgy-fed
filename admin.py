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
from granary import as1, microformats2
import memcache
import models
from models import Object, PROTOCOLS, User
from oauth_dropins.webutil import flask_util, logs, util
from oauth_dropins.webutil.flask_util import flash
import pytz

from activitypub import ActivityPub
from atproto import ATProto
import ids
from nostr import Nostr
import pages

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
def render(template, **vars):
    return pages.render(
        template,
        PROTOCOLS={
            'activitypub': ActivityPub,
            'atproto': ATProto,
            'nostr': Nostr,
        },
        **vars)


def format_properties(entity):
    """Generates template variables based on misc User and Object properties:

    * created, updated: to ISO-8601 strings
    * bridged: dict mapping Protocol subclass to string id
    """
    vars = {}

    pt = pytz.timezone('US/Pacific')
    for field in 'created', 'updated':
        # these are proto.datetime_helpers.DatetimeWithNanoseconds. have to recreate
        # them as plain datetimes because otherwise they crash on replace().
        # similar to: https://stackoverflow.com/q/54370012/186123
        vars[field] = datetime.fromtimestamp(getattr(entity, field).timestamp()
                                             ).replace(microsecond=0).astimezone(pt)

    return vars


@app.get('/admin/')
def admin_home():
    for reloader in BLOCKLISTS.values():
        reloader.reload()
    return render('admin.html', filters=filters)


@app.post('/admin/blocklist/<id>')
def save_blocklist(id):
    """
    Form values:
      values (str)
    """
    values = [v.strip() for v in request.values['values'].splitlines() if v.strip()]
    BLOCKLISTS[id].obj.raw = values
    BLOCKLISTS[id].obj.put()
    flash(f'Saved {id}.')
    return redirect('/admin/')


@app.post('/admin/user')
def admin_user_lookup():
    """
    Form values:
      id (str)
    """
    id = request.values['id'].strip()
    try:
        user = models.load_user(id, allow_opt_out=True)
        return redirect(f'/admin/user/{user.key.urlsafe().decode()}')
    except RuntimeError as e:
        flash(str(e))
        return redirect('/admin/')


@app.get('/admin/user/<key>')
def admin_user(key):
    user = Key(urlsafe=key).get()
    if not user or not isinstance(user, User):
        flash('user not found')
        return redirect('/admin/')

    bridged_ids = {
        proto: ids.translate_user_id(id=user.key.id(), from_=user, to=proto)
        for proto in (ATProto, ActivityPub, Nostr)
        if not isinstance(user, proto)
    }

    return render(
        'admin_user.html',
        user=user,
        bridged_ids=bridged_ids,
        **format_properties(user))


@app.post('/admin/object')
def admin_object_lookup():
    """
    Form values:
      id (str)
    """
    id = request.values['id'].strip()
    key = Object(id=id).key.urlsafe().decode()
    return redirect(f'/admin/object/{key}')


@app.get('/admin/object/<key>')
def admin_object(key):
    obj = Key(urlsafe=key).get()
    if not obj or not isinstance(obj, Object):
        flash('object not found')
        return redirect('/admin/')

    if obj.as1 and as1.object_type(obj.as1) in as1.CRUD_VERBS:
        if inner_id := as1.get_object(obj.as1).get('id'):
            if inner := Object.get_by_id(inner_id):
                return redirect(f'/admin/object/{inner.key.urlsafe().decode()}')

    user = None
    if obj.users:
        user = obj.users[0].get()
    elif (obj.as1
          and (user_id := as1.get_owner(obj.as1))
          and (proto := PROTOCOLS[obj.source_protocol])):
        user = proto.get_by_id(user_id)

    return render(
        'admin_object.html',
        obj=obj,
        user=user,
        **format_properties(obj))


@app.post('/admin/enable/<key>')
def admin_enable(key):
    """
    Form values:
      protocol (str)
    """
    user = Key(urlsafe=key).get()
    proto = PROTOCOLS[request.values['protocol']]
    user.enable_protocol(proto)
    flash(f'Enabled {proto.LABEL} for {user.handle}')
    return redirect(f'/admin/user/{key}')


@app.post('/admin/disable/<key>')
def admin_disable(key):
    """
    Form values:
      protocol (str)
    """
    user = Key(urlsafe=key).get()
    proto = PROTOCOLS[request.values['protocol']]
    user.disable_protocol(proto)
    flash(f'Disabled {proto.LABEL} for {user.handle}')
    return redirect(f'/admin/user/{key}')


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
