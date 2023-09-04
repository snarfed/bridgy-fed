"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from flask_app import app

# import all modules to register their Flask handlers
import activitypub, convert, follow, pages, redirect, superfeedr, ui, webfinger, web

import models
models.reset_protocol_properties()
