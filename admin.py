"""Admin pages and endpoints: admin UI, hub status, memcache API, etc."""
from datetime import datetime
import logging
from urllib.parse import quote

from google.cloud import ndb
from google.cloud.ndb import Key

import arroba.server
import common
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

from activitypub import ActivityPub, FEDI_URL_RE
from atproto import ATProto
import ids
from nostr import Nostr
import pages
from web import Web

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
    return pages.render(template, **vars)


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


@app.post('/admin/blocklist')
def save_blocklist():
    """
    Form values:
      id (str): blocklist key id
      values (str)
    """
    id = request.values['id']
    values = [v.strip() for v in request.values['values'].splitlines() if v.strip()]
    BLOCKLISTS[id].obj.raw = values
    BLOCKLISTS[id].obj.put()
    flash(f'Saved {id}.')
    return redirect('/admin/')


@app.get('/admin/user')
def admin_user_search():
    """
    Query params:
      query (str)
    """
    query = orig_query = request.values['query'].strip()
    if not query:
        error('empty query')

    # preprocess search query, misc heuristics
    if query.endswith('.ap.brid.gy'):
        query = ids.translate_user_id(id=query, from_=ATProto, to=ActivityPub)
    elif query.endswith('.brid.gy'):
        query = query.rsplit('.', 3)[0]
    elif match := FEDI_URL_RE.fullmatch(query):
        query = ids.handle_as_domain(f'@{match.group("handle")}@{match.group("domain")}')

    queries = [query]
    if '@' in query:
        if handle_as_domain := ids.handle_as_domain(query):
            queries.append(handle_as_domain)

    futures = [
        proto.query(ndb.OR(
            proto.key.IN([proto(id=query).key for query in queries]),
            proto.handle.IN(queries),
            proto.handle_as_domain.IN(queries),
            proto.handle_pay_level_domain.IN(queries))).fetch_async()
        for proto in set(PROTOCOLS.values()) if proto]

    users = []
    for future in futures:
        users.extend(future.get_result())

    if not users:
        if key := models.get_original_user_key(query):
            users = [key.get()]

    for user in users:
        user.bridged_ids = {
            proto: ids.translate_user_id(id=user.key.id(), from_=user, to=proto)
            for proto in (ATProto, ActivityPub, Nostr)
            if not isinstance(user, proto)
        }
        user.sent_dms_ = ', '.join(
            f'{dm.type} ({dm.protocol})' for dm in user.sent_dms)


    return render('admin_users.html', query=orig_query, users=users)


@app.get('/admin/user/<key>')
def admin_user(key):
    user = Key(urlsafe=key).get()
    if not user or not isinstance(user, User):
        flash('user not found')
        return redirect('/admin/')

    return redirect(f'/admin/user?query={quote(user.key.id())}')


@app.post('/admin/object')
def admin_object_lookup():
    """
    Form values:
      id (str)
    """
    id = request.values['id'].strip()
    # ordered
    for proto in ActivityPub, ATProto, Nostr, Web:
        if proto and proto.owns_id(id) is not False:
            if obj := proto.load(id):
                return redirect(f'/admin/object/{obj.key.id()}')

    flash(f"Couldn't resolve {id}")
    return redirect('/admin/')


@app.get('/admin/object/<path:id>')
def admin_object(id):
    if not (obj := Object.get_by_id(id)):
        flash('object not found')
        return redirect('/admin/')

    if obj.as1 and as1.object_type(obj.as1) in as1.CRUD_VERBS:
        if inner_id := as1.get_object(obj.as1).get('id'):
            if inner := Object.get_by_id(inner_id):
                return redirect(f'/admin/object/{inner.key.id()}')

    proto = PROTOCOLS[obj.source_protocol]
    user = None
    if obj.users:
        user = obj.users[0].get()
    elif obj.as1 and proto and (user_id := as1.get_owner(obj.as1)):
        user = proto.get_by_id(user_id)

    bridged_ids = {
        to_proto: ids.translate_object_id(id=obj.key.id(), from_=proto, to=to_proto)
        for to_proto in (ATProto, ActivityPub, Nostr)
        if to_proto != proto and user and user.is_enabled(to_proto)
    }

    return render(
        'admin_object.html',
        obj=obj,
        user=user,
        bridged_ids=bridged_ids,
        **format_properties(obj))


@app.post('/admin/receive')
def admin_receive():
    obj_key = Key(urlsafe=request.values['obj_key'])
    user_key = Key(urlsafe=request.values['user_key'])
    common.create_task(queue='receive', obj_id=obj_key.id(),
                       authed_as=user_key.id(), force='true')
    return redirect(f'/admin/object/{obj_key.id()}')


@app.post('/admin/enable')
def admin_enable():
    """
    Form values:
      key (str): urlsafe user key
      protocol (str)
    """
    key = request.values['key']
    user = Key(urlsafe=key).get()
    proto = PROTOCOLS[request.values['protocol']]
    user.enable_protocol(proto)
    flash(f'Enabled {proto.LABEL} for {user.handle}')
    return redirect(f'/admin/user/{key}')


@app.post('/admin/disable')
def admin_disable():
    """
    Form values:
      key (str): urlsafe user key
      protocol (str)
    """
    key = request.values['key']
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
