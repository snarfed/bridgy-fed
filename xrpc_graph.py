"""app.bsky.graph.* XRPC methods."""

@xrpc_server.method('app.bsky.graph.getAssertions')
def getAssertions():
    """
    lexicons/app/bsky/graph/getAssertions.json
    """

@xrpc_server.method('app.bsky.graph.getFollowers')
def getFollowers():
    """
    lexicons/app/bsky/graph/getFollowers.json
    """

@xrpc_server.method('app.bsky.graph.getFollows')
def getFollows():
    """
    lexicons/app/bsky/graph/getFollows.json
    """

@xrpc_server.method('app.bsky.graph.getMembers')
def getMembers():
    """
    lexicons/app/bsky/graph/getMembers.json
    """

@xrpc_server.method('app.bsky.graph.getMemberships')
def getMemberships():
    """
    lexicons/app/bsky/graph/getMemberships.json
    """

