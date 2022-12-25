"""app.bsky.feed.* XRPC methods."""
from app import xrpc_server

@xrpc_server.method('app.bsky.feed.getAuthorFeed')
def getAuthorFeed():
    """
    lexicons/app/bsky/feed/getAuthorFeed.json
    """

@xrpc_server.method('app.bsky.feed.getPostThread')
def getPostThread():
    """
    lexicons/app/bsky/feed/getPostThread.json
    """

@xrpc_server.method('app.bsky.feed.getRepostedBy')
def getRepostedBy():
    """
    lexicons/app/bsky/feed/getRepostedBy.json
    """

@xrpc_server.method('app.bsky.feed.getTimeline')
def getTimeline():
    """
    lexicons/app/bsky/feed/getTimeline.json
    """

@xrpc_server.method('app.bsky.feed.getVotes')
def getVotes():
    """
    lexicons/app/bsky/feed/getVotes.json
    """

@xrpc_server.method('app.bsky.feed.setVote')
def setVote():
    """
    lexicons/app/bsky/feed/setVote.json
    """

