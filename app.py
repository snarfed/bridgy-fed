"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from arroba.datastore_storage import MemcacheSequences
from webutil.appengine_info import DEBUG, LOCAL_SERVER

from flask_app import app

# import all modules to register their Flask handlers
import activitypub, admin, atproto, convert, farcaster, follow, nostr, pages, redirect, ui, webfinger, web

# https://docs.cloud.google.com/profiler/docs/profiling-python
# import googlecloudprofiler
# googlecloudprofiler.start(
#     service_version='2026-05-26',
#     disable_wall_profiling=True,
#     task_types=[googlecloudprofiler.TaskType.CPU, googlecloudprofiler.TaskType.HEAP])

import models
models.reset_protocol_properties()

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
