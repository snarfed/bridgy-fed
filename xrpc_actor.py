"""app.bsky.actor.* XRPC methods."""
import logging
import json
import re

from granary import microformats2, bluesky
import mf2util
from oauth_dropins.webutil import util

from app import xrpc_server

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.actor.getProfile')
def getProfile(input, actor=None):
    """
    lexicons/app/bsky/actor/getProfile.json
    """
    # TODO: actor is either handle or DID
    # see actorWhereClause in atproto/packages/pds/src/db/util.ts
    if not re.match(util.DOMAIN_RE, actor):
        raise ValueError(f'{actor} is not a domain')

    url = f'https://{actor}/'
    mf2 = util.fetch_mf2(url)
    hcard = mf2util.representative_hcard(mf2, mf2['url'])
    if not hcard:
        raise ValueError(f"Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on {mf2['url']}")

    logger.info(f'Representative h-card: {json.dumps(hcard, indent=2)}')

    actor = microformats2.json_to_object(hcard)
    logger.info(f'AS1 actor: {json.dumps(actor, indent=2)}')

    profile = {
        **bluesky.from_as1(actor, from_url=url),
        'myState': {
            # ?
            'follow': 'TODO',
            'member': 'TODO',
        },
    }
    logger.info(f'Bluesky profile: {json.dumps(profile, indent=2)}')
    return profile


@xrpc_server.method('app.bsky.actor.getSuggestions')
def getSuggestions(input):
    """
    lexicons/app/bsky/actor/getSuggestions.json
    """
    # TODO based on stored users
    return {'actors': []}


@xrpc_server.method('app.bsky.actor.search')
def search(input, term=None, limit=None, before=None):
    """
    lexicons/app/bsky/actor/search.json
    """
    # TODO based on stored users
    return {'users': []}


@xrpc_server.method('app.bsky.actor.searchTypeahead')
def searchTypeahead(input, term=None, limit=None):
    """
    lexicons/app/bsky/actor/searchTypeahead.json
    """
    # TODO based on stored users
    return {'users': []}
