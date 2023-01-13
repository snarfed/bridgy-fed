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

    activities = microformats2.json_to_activities(mf2)
    # default actor to feed author
    for a in activities:
        a.setdefault('actor', actor)
    logger.info(f'AS1 activities: {json.dumps(activities, indent=2)}')

    return {'feed': [bluesky.from_as1(a) for a in activities]}


@xrpc_server.method('app.bsky.feed.getPostThread')
def getPostThread(input, uri=None, depth=None):
    """
    lexicons/app/bsky/feed/getPostThread.json
    """
    mf2 = util.fetch_mf2(uri, gateway=True)
    logger.info(f'Got mf2: {json.dumps(mf2, indent=2)}')

    entry = mf2util.find_first_entry(mf2, ['h-entry'])
    logger.info(f'Entry: {json.dumps(entry, indent=2)}')
    if not entry:
        raise ValueError(f"No h-entry on {uri}")

    obj = microformats2.json_to_object(entry)
    logger.info(f'AS1: {json.dumps(obj, indent=2)}')

    return {
        'thread': {
            '$type': 'app.bsky.feed.getPostThread#threadViewPost',
            'post': bluesky.from_as1(obj)['post'],
            'replies': [{
                '$type': 'app.bsky.feed.getPostThread#threadViewPost',
                'post': bluesky.from_as1(reply)['post'],
            } for reply in obj.get('replies', {}).get('items', [])],
        },
    }


# TODO
# what's the mf2 for repost children of an h-entry? u-repost, like u-comment?
# nothing about markup on https://indieweb.org/reposts
# based on https://indieweb.org/comments-display , it would be u-repost
# @xrpc_server.method('app.bsky.feed.getRepostedBy')
# def getRepostedBy(input, uri=None, cid=None, limit=None, before=None):
#     """
#     lexicons/app/bsky/feed/getRepostedBy.json
#     """
#     mf2 = util.fetch_mf2(uri, gateway=True)
#     logger.info(f'Got mf2: {json.dumps(mf2, indent=2)}')

#     entry = mf2util.find_first_entry(mf2, ['h-entry'])
#     logger.info(f'Entry: {json.dumps(entry, indent=2)}')
#     if not entry:
#         raise ValueError(f"No h-entry on {uri}")

#     obj = microformats2.json_to_object(entry)
#     logger.info(f'AS1: {json.dumps(obj, indent=2)}')

#     return {
#         'uri': 'http://orig/post',
#         'repostBy': [{
#             '$type': 'app.bsky.feed.getRepostedBy#repostedBy',
#             'did': 'did:web:eve.net',
#             'declaration': {
#                 '$type': 'app.bsky.system.declRef',
#                 'cid': 'TODO',
#                 'actorType': 'app.bsky.system.actorUser',
#             },
#             'handle': 'eve.net',
#             'displayName': 'Eve',
#             'indexedAt': '2022-01-02T03:04:05+00:00',
#         }],
#     }


# TODO based on datastore
# @xrpc_server.method('app.bsky.feed.getTimeline')
# def getTimeline(input):
#     """
#     lexicons/app/bsky/feed/getTimeline.json
#     """


# TODO: use likes as votes?
@xrpc_server.method('app.bsky.feed.getVotes')
def getVotes(input, uri=None, direction=None, cid=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getVotes.json
    """
    return {
        'uri': uri,
        'votes': [],
    }
