"""app.bsky.graph.* XRPC methods."""
import logging
import re

from granary import bluesky
from oauth_dropins.webutil import util

from app import xrpc_server
import common
from models import Follower, User

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
    if not user or not re.match(util.DOMAIN_RE, user):
        raise ValueError(f'{user} is not a domain')
    elif not User.get_by_id(user):
        raise ValueError(f'Unknown user {user}')

    collection = 'followers' if output_field == 'followers' else 'following'
    followers, before, after = Follower.fetch_page(user, collection)

    actors = []
    for follower in followers:
        actor = follower.to_as1()
        if actor:
            actors.append({
                **bluesky.actor_to_ref(actor),
                '$type': 'app.bsky.graph.getFollowers#follower',
                'indexedAt': util.now().isoformat(),
            })

    return {
        'subject': bluesky.actor_to_ref({'url': f'https://{user}/'}),
        output_field: actors,
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
