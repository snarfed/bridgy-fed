"""app.bsky.actor.* XRPC methods."""
import logging
import json
import re

from flask import g
from granary import bluesky
from oauth_dropins.webutil import util

from flask_app import xrpc_server
from web import Web

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.actor.getProfile')
def getProfile(input, actor=None):
    """
    lexicons/app/bsky/actor/getProfile.json
    """
    # TODO: actor is either handle or DID
    # see actorWhereClause in atproto/packages/pds/src/db/util.ts
    if not actor or not re.match(util.DOMAIN_RE, actor):
        raise ValueError(f'{actor} is not a domain')

    g.user = Web.get_by_id(actor)
    if not g.user:
        raise ValueError(f'User {actor} not found')
    elif not g.user.obj.as1:
        return ValueError(f'User {actor} not fully set up')

    actor_as1 = g.user.obj.as1
    logger.info(f'AS1 actor: {json.dumps(actor_as1, indent=2)}')

    profile = bluesky.from_as1(actor_as1)
    logger.info(f'Bluesky profile: {json.dumps(profile, indent=2)}')
    return profile


@xrpc_server.method('app.bsky.actor.getSuggestions')
def getSuggestions(input):
    """
    lexicons/app/bsky/actor/getSuggestions.json
    """
    # TODO based on stored users
    return {'actors': []}


@xrpc_server.method('app.bsky.actor.searchActors')
def searchActors(input, term=None, limit=None, before=None):
    """
    lexicons/app/bsky/actor/searchActors.json
    """
    # TODO based on stored users
    return {'actors': []}


@xrpc_server.method('app.bsky.actor.searchActorsTypeahead')
def searchActorsTypeahead(input, term=None, limit=None):
    """
    lexicons/app/bsky/actor/searchActorsTypeahead.json
    """
    # TODO based on stored users
    return {'actors': []}
