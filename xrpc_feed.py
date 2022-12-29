"""app.bsky.feed.* XRPC methods."""
import logging

from app import xrpc_server

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.feed.getAuthorFeed')
def getAuthorFeed(input, author=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getAuthorFeed.json, feedViewPost.json
    """
    if not re.match(util.DOMAIN_RE, author):
        raise ValueError(f'{actor} is not a domain')

    url = f'https://{actor}/'
    mf2 = util.fetch_mf2(url, gateway=True)
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
