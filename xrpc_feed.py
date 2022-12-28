"""app.bsky.feed.* XRPC methods."""
import logging

from app import xrpc_server

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.feed.getAuthorFeed')
def getAuthorFeed(input):
    """
    lexicons/app/bsky/feed/getAuthorFeed.json
    """

@xrpc_server.method('app.bsky.feed.getPostThread')
def getPostThread(input):
    """
    lexicons/app/bsky/feed/getPostThread.json
    """

@xrpc_server.method('app.bsky.feed.getRepostedBy')
def getRepostedBy(input):
    """
    lexicons/app/bsky/feed/getRepostedBy.json
    """

@xrpc_server.method('app.bsky.feed.getTimeline')
def getTimeline(input):
    """
    lexicons/app/bsky/feed/getTimeline.json
    """

@xrpc_server.method('app.bsky.feed.getVotes')
def getVotes(input):
    """
    lexicons/app/bsky/feed/getVotes.json
    """

@xrpc_server.method('app.bsky.feed.setVote')
def setVote(input):
    """
    lexicons/app/bsky/feed/setVote.json
    """

