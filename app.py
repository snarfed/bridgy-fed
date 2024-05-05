"""Bridgy Fed user-facing app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from flask_app import app

# import all modules to register their Flask handlers
import activitypub, atproto, convert, follow, pages, redirect, ui, webfinger, web

import models
models.reset_protocol_properties()

app.add_url_rule('/queue/atproto-poll-notifs',
                 view_func=atproto.poll_notifications,
                 methods=['GET', 'POST'])

app.add_url_rule('/queue/atproto-poll-posts',
                 view_func=atproto.poll_posts,
                 methods=['GET', 'POST'])
