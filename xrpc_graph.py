"""app.bsky.graph.* XRPC methods."""
import logging
import re

from granary import bluesky
from oauth_dropins.webutil import util

from app import xrpc_server
from models import Follower

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.graph.getFollowers')
def getFollowers(input, user=None, limit=50, before=None):
    """
    lexicons/app/bsky/graph/getFollowers.json
    """
    # TODO: what is user?
    if not re.match(util.DOMAIN_RE, user):
        raise ValueError(f'{user} is not a domain')

    followers = []
    for follower in Follower.query(Follower.dest == user).fetch(limit):
        actor = follower.to_as1()
        print('@', actor)
        if actor:
            followers.append({
                **bluesky.actor_to_ref(actor),
                '$type': 'app.bsky.graph.getFollowers#follower',
                'indexedAt': util.now().isoformat(),
            })

    return {
        'subject': bluesky.actor_to_ref({'url': f'https://{user}/'}),
        'followers': followers,
        'cursor': '',
    }


@xrpc_server.method('app.bsky.graph.getFollows')
def getFollows(input, user=None, limit=None, before=None):
    """
    lexicons/app/bsky/graph/getFollows.json
    """

