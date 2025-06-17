"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from flask_app import app

# import all modules to register their Flask handlers
import activitypub, atproto, convert, follow, nostr, pages, redirect, ui, webfinger, web

import models
models.reset_protocol_properties()

# only serve subscribeRepos on atproto.brid.gy (hub), not on fed.brid.gy, so
# that relays don't think they're two separate PDSes.
#
# must be before flask_app import!
import arroba.server
del arroba.server.server._methods['com.atproto.sync.subscribeRepos']
