"""app.bsky.graph.* XRPC methods."""
import logging
import re

from granary import bluesky
from oauth_dropins.webutil import util

from app import xrpc_server
from models import Follower

logger = logging.getLogger(__name__)


def get_followers(query_prop, output_field, user=None, limit=50, before=None):
    """Runs the getFollowers or getFollows method. (They're almost identical.)

    Args:
      query_prop: str, property of Follower class to query
      output_field: str, field in output to populate followers into

    Returns:
      dict, XRPC method output
    """
    # TODO: what is user?
    if not re.match(util.DOMAIN_RE, user):
        raise ValueError(f'{user} is not a domain')

    followers = []
    for follower in Follower.query(query_prop == user).fetch(limit):
        actor = follower.to_as1()
        if actor:
            followers.append({
                **bluesky.actor_to_ref(actor),
                '$type': 'app.bsky.graph.getFollowers#follower',
                'indexedAt': util.now().isoformat(),
            })

    return {
        'subject': bluesky.actor_to_ref({'url': f'https://{user}/'}),
        output_field: followers,
        'cursor': '',
    }


@xrpc_server.method('app.bsky.graph.getFollowers')
def getFollowers(input, **kwargs):
    """
    lexicons/app/bsky/graph/getFollowers.json
    """
    return get_followers(Follower.dest, 'followers', **kwargs)


@xrpc_server.method('app.bsky.graph.getFollows')
def getFollows(input, **kwargs):
    """
    lexicons/app/bsky/graph/getFollows.json
    """
    return get_followers(Follower.src, 'follows', **kwargs)
