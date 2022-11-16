"""Simple endpoint that redirects to the embedded fully qualified URL.

May also instead fetch and convert to AS2, depending on conneg.

Used to wrap ActivityPub ids with the fed.brid.gy domain so that Mastodon
accepts them. Background:

https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747
"""
import datetime
import logging
import re
import urllib.parse

from flask import redirect, request
from granary import as2, microformats2
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps
from werkzeug.exceptions import abort

from app import app, cache
import common
from models import Domain

logger = logging.getLogger(__name__)

CACHE_TIME = datetime.timedelta(seconds=15)


@app.get(r'/r/<path:to>')
@flask_util.cached(cache, CACHE_TIME)
def redir(to):
    """301 redirect to the embedded fully qualified URL.

    e.g. redirects /r/https://foo.com/bar?baz to https://foo.com/bar?baz
    """
    if request.args:
        to += '?' + urllib.parse.urlencode(request.args)
    # some browsers collapse repeated /s in the path down to a single slash.
    # if that happened to this URL, expand it back to two /s.
    to = re.sub(r'^(https?:/)([^/])', r'\1/\2', to)

    if not to.startswith('http://') and not to.startswith('https://'):
        error(f'Expected fully qualified URL; got {to}')

    # check that we've seen this domain before so we're not an open redirect
    domains = set((util.domain_from_link(to, minimize=True),
                   util.domain_from_link(to, minimize=False),
                   urllib.parse.urlparse(to).hostname))
    for domain in domains:
        if domain:
            entity = Domain.get_by_id(domain)
            if entity:
                logger.info(f'Found Domain for domain {domain}')
                break
    else:
        logger.info(f'No user found for any of {domains}; returning 404')
        abort(404)

    # poor man's conneg, only handle single Accept values, not multiple with
    # priorities.
    if request.headers.get('Accept') in (common.CONTENT_TYPE_AS2,
                                         common.CONTENT_TYPE_AS2_LD):
        return convert_to_as2(to, entity)

    # redirect
    logger.info(f'redirecting to {to}')
    return redirect(to, code=301)


def convert_to_as2(url, domain):
    """Fetch a URL as HTML, convert it to AS2, and return it.

    Currently mainly for Pixelfed.
    https://github.com/snarfed/bridgy-fed/issues/39

    Args:
      url: str
      domain: :class:`Domain`
    """
    mf2 = util.fetch_mf2(url)
    entry = mf2util.find_first_entry(mf2, ['h-entry'])
    logger.info(f"Parsed mf2 for {mf2['url']}: {json_dumps(entry, indent=2)}")

    obj = common.postprocess_as2(as2.from_as1(microformats2.json_to_object(entry)),
                                 domain)
    logger.info(f'Returning: {json_dumps(obj, indent=2)}')

    return obj, {
        'Content-Type': common.CONTENT_TYPE_AS2,
        'Access-Control-Allow-Origin': '*',
    }
