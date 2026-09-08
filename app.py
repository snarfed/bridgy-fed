"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
import os

from arroba import xrpc_proxy
from arroba.datastore_storage import MemcacheSequences
import arroba.server
import lexrpc.flask_server
from webutil.appengine_info import DEBUG, LOCAL_SERVER

from flask_app import app

# import all modules to register their Flask handlers
import activitypub, admin, atproto, atproto_oauth, convert, farcaster, follow, mastodon_api, mastodon_oauth, nostr, oauth_server, pages, redirect, ui, webfinger, web

# https://docs.cloud.google.com/profiler/docs/profiling-python
# import googlecloudprofiler
# googlecloudprofiler.start(
#     service_version='2026-05-26',
#     disable_wall_profiling=True,
#     task_types=[googlecloudprofiler.TaskType.CPU, googlecloudprofiler.TaskType.HEAP])

import models
models.reset_protocol_properties()


@app.get('/.well-known/oauth-authorization-server')
@app.get('/.well-known/oauth-authorization-server/')
@oauth_server.log_request_response
def oauth_metadata():
    """Serves whichever OAuth authorization server this host runs.

    Here, and not in either OAuth module, because RFC 8414 pins this to one path
    per host, so the two servers have to share the route.
    """
    # atproto.brid.gy is our PDS, so it serves ATProto OAuth
    return (atproto_oauth.metadata() if atproto.is_pds_host()
            else mastodon_oauth.metadata())


@app.get('/oauth/authorize')
@app.get('/oauth/authorize/')
@oauth_server.log_request_response
def oauth_authorize():
    """Serves whichever OAuth authorization endpoint this host runs.

    Shared here for the same reason as :func:`oauth_metadata`. This is Mastodon's
    authorization endpoint, and the reference PDS's; some ATProto clients ignore
    our ``authorization_endpoint`` and hardcode this path, so serve them here too.

    Only GET. The ATProto branch redirects to its own path on
    :const:`domains.PRIMARY_DOMAIN`, so its consent POST never lands here.
    """
    return (atproto_oauth.authorize() if atproto.is_pds_host()
            else mastodon_oauth.authorize())


if DEBUG or LOCAL_SERVER:
    atproto.init(atproto.RemoteSequences)
else:
    atproto.init(MemcacheSequences)

# only serve subscribeRepos on atproto.brid.gy (hub), not on fed.brid.gy, so
# that relays don't think they're two separate PDSes.
#
# must be before init_flask below!
del arroba.server.server._methods['com.atproto.sync.subscribeRepos']

# methods we don't implement get service proxied to whichever service the client
# asks for in atproto-proxy, or to the appview.
# https://atproto.com/specs/xrpc#service-proxying
service_proxy = xrpc_proxy.handler(
    atproto_oauth.auth,
    default_service=f'did:web:{os.environ["APPVIEW_HOST"]}#bsky_appview')

# initialize XRPC server
lexrpc.flask_server.init_flask(arroba.server.server, app, fallback=service_proxy)
