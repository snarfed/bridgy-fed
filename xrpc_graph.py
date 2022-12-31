"""app.bsky.graph.* XRPC methods."""
import logging

from app import xrpc_server

logger = logging.getLogger(__name__)


# get these from datastore
@xrpc_server.method('app.bsky.graph.getFollowers')
def getFollowers(input):
    """
    lexicons/app/bsky/graph/getFollowers.json
    """

@xrpc_server.method('app.bsky.graph.getFollows')
def getFollows(input):
    """
    lexicons/app/bsky/graph/getFollows.json
    """

