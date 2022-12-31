"""app.bsky.feed.* XRPC methods."""
import json
import logging
import re

from granary import microformats2, bluesky
import mf2util
from oauth_dropins.webutil import util

from app import xrpc_server

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.feed.getAuthorFeed')
def getAuthorFeed(input, author=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getAuthorFeed.json, feedViewPost.json
    """
    if not re.match(util.DOMAIN_RE, author):
        raise ValueError(f'{author} is not a domain')

    url = f'https://{author}/'
    mf2 = util.fetch_mf2(url, gateway=True)
    logger.info(f'Got mf2: {json.dumps(mf2, indent=2)}')

    feed_author = mf2util.find_author(mf2, source_url=url, fetch_mf2_func=util.fetch_mf2)
    if feed_author:
        logger.info(f'Authorship found: {feed_author}')
        actor = {
            'url': feed_author.get('url') or url,
            'displayName': feed_author.get('name'),
            'image': {'url': feed_author.get('photo')},
        }
    else:
        logger.info(f'No authorship result on {url} ; generated {feed_author}')
        actor = {
            'url': url,
            'displayName': author,
        }

    activities = microformats2.json_to_activities(mf2)  #, actor)
    # default actor to feed author
    for a in activities:
        a.setdefault('actor', actor)
    logger.info(f'AS1 activities: {json.dumps(activities, indent=2)}')

    return {'feed': [bluesky.from_as1(a) for a in activities]}


# all the rest come from fetching uri, parsing as mf2, and extracting responses
@xrpc_server.method('app.bsky.feed.getPostThread')
def getPostThread(input):
    """
    lexicons/app/bsky/feed/getPostThread.json
    """

@xrpc_server.method('app.bsky.feed.getRepostedBy')
def getRepostedBy(input, uri=None, cid=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getRepostedBy.json
    """

@xrpc_server.method('app.bsky.feed.getTimeline')
def getTimeline(input):
    """
    lexicons/app/bsky/feed/getTimeline.json
    """

# votes are likes
@xrpc_server.method('app.bsky.feed.getVotes')
def getVotes(input, uri=None, direction=None, cid=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getVotes.json
    """

@xrpc_server.method('app.bsky.feed.setVote')
def setVote(input):
    """
    lexicons/app/bsky/feed/setVote.json
    """
