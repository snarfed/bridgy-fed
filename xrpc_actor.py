"""app.bsky.actor.* XRPC methods."""

@xrpc_server.method('app.bsky.actor.createScene')
def createScene():
    """
    lexicons/app/bsky/actor/createScene.json
    """

@xrpc_server.method('app.bsky.actor.getProfile')
def getProfile():
    """
    lexicons/app/bsky/actor/getProfile.json
    """

@xrpc_server.method('app.bsky.actor.getSuggestions')
def getSuggestions():
    """
    lexicons/app/bsky/actor/getSuggestions.json
    """

@xrpc_server.method('app.bsky.actor.search')
def search():
    """
    lexicons/app/bsky/actor/search.json
    """

@xrpc_server.method('app.bsky.actor.searchTypeahead')
def searchTypeahead():
    """
    lexicons/app/bsky/actor/searchTypeahead.json
    """

@xrpc_server.method('app.bsky.actor.updateProfile')
def updateProfile():
    """
    lexicons/app/bsky/actor/updateProfile.json
    """

