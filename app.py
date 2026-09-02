"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from arroba.datastore_storage import MemcacheSequences
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

if DEBUG or LOCAL_SERVER:
    atproto.init(atproto.RemoteSequences)
else:
    atproto.init(MemcacheSequences)

# only serve subscribeRepos on atproto.brid.gy (hub), not on fed.brid.gy, so
# that relays don't think they're two separate PDSes.
#
# must be before flask_app import!
import arroba.server
del arroba.server.server._methods['com.atproto.sync.subscribeRepos']
