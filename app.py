"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from flask_app import app

# import all modules to register their Flask handlers
import atproto, convert, follow, pages, redirect, superfeedr, ui, webfinger, web
# import after others because it has URL routes that use PROTOCOLS
# TODO: figure out a better way
import activitypub

import models
models.reset_protocol_properties()
