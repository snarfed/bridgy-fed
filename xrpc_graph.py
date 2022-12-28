"""app.bsky.graph.* XRPC methods."""
import logging

from app import xrpc_server

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.graph.getAssertions')
def getAssertions(input):
    """
    lexicons/app/bsky/graph/getAssertions.json
    """

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

@xrpc_server.method('app.bsky.graph.getMembers')
def getMembers(input):
    """
    lexicons/app/bsky/graph/getMembers.json
    """

@xrpc_server.method('app.bsky.graph.getMemberships')
def getMemberships(input):
    """
    lexicons/app/bsky/graph/getMemberships.json
    """

