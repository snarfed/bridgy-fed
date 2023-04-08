"""app.bsky.feed.* XRPC methods."""
import json
import logging
import re

from flask import g
from granary import bluesky, microformats2
import mf2util
from oauth_dropins.webutil import util

from app import xrpc_server
from models import Object, PAGE_SIZE, User

logger = logging.getLogger(__name__)


@xrpc_server.method('app.bsky.feed.getAuthorFeed')
def getAuthorFeed(input, author=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getAuthorFeed.json, feedViewPost.json
    """
    if not author or not re.match(util.DOMAIN_RE, author):
        raise ValueError(f'{author} is not a domain')

    g.user = User.get_by_id(author)
    if not g.user:
        raise ValueError(f'User {author} not found')
    elif not g.user.actor_as2:
        return ValueError(f'User {author} not fully set up')

    # TODO: unify with pages.feed?
    limit = min(limit or PAGE_SIZE, PAGE_SIZE)
    objects, _, _ = Object.query(Object.domains == author, Object.labels == 'user') \
        .order(-Object.created) \
        .fetch_page(limit)
    activities = [obj.as1 for obj in objects if not obj.deleted]
    logger.info(f'AS1 activities: {json.dumps(activities, indent=2)}')

    return {'feed': [bluesky.from_as1(a) for a in activities]}


@xrpc_server.method('app.bsky.feed.getPostThread')
def getPostThread(input, uri=None, depth=None):
    """
    lexicons/app/bsky/feed/getPostThread.json
    """
    if not uri:
        raise ValueError('Missing uri')

    obj = Object.get_by_id(uri)
    if not obj:
        raise ValueError(f'{uri} not found')

    logger.info(f'AS1: {json.dumps(obj.as1, indent=2)}')

    return {
        'thread': {
            '$type': 'app.bsky.feed.defs#threadViewPost',
            'post': bluesky.from_as1(obj.as1)['post'],
            'replies': [{
                '$type': 'app.bsky.feed.defs#threadViewPost',
                'post': bluesky.from_as1(reply)['post'],
            } for reply in obj.as1.get('replies', {}).get('items', [])],
        },
    }


@xrpc_server.method('app.bsky.feed.getRepostedBy')
def getRepostedBy(input, uri=None, cid=None, limit=None, before=None):
    """
    TODO: implement before, as query filter. what's input type? str or datetime?
    lexicons/app/bsky/feed/getRepostedBy.json
    """
    if not uri:
        raise ValueError('Missing uri')

    limit = min(limit or PAGE_SIZE, PAGE_SIZE)
    objects, _, _ = Object.query(Object.object_ids == uri) \
        .order(-Object.created) \
        .fetch_page(limit)
    activities = [obj.as1 for obj in objects if not obj.deleted]
    logger.info(f'AS1 activities: {json.dumps(activities, indent=2)}')

    return {
        'uri': 'http://orig/post',
        'repostBy': [{
            **bluesky.from_as1(a['actor']),
            '$type': 'app.bsky.feed.getRepostedBy#repostedBy',
        } for a in activities if a.get('actor')],
    }


# TODO: cursor
@xrpc_server.method('app.bsky.feed.getTimeline')
def getTimeline(input, algorithm=None, limit=50, before=None):
    """
    lexicons/app/bsky/feed/getTimeline.json
    """
    # TODO: how to get authed user?
    domain = 'user.com'

    # TODO: de-dupe with pages.feed()
    logger.info(f'Fetching {limit} objects for {domain}')
    objects, _, _ = Object.query(Object.domains == domain, Object.labels == 'feed') \
        .order(-Object.created) \
        .fetch_page(limit)

    return {'feed': [bluesky.from_as1(obj.as1) for obj in objects if not obj.deleted]}


# TODO
@xrpc_server.method('app.bsky.feed.getLikes')
def getLikes(input, uri=None, direction=None, cid=None, limit=None, before=None):
    """
    lexicons/app/bsky/feed/getLikes.json
    """
    return {
        'uri': uri,
        'likes': [],
    }
