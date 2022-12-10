"""Remote follow handler.

https://github.com/snarfed/bridgy-fed/issues/60
https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020
https://www.rfc-editor.org/rfc/rfc7033
"""
import logging
import urllib.parse

from flask import redirect, request
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error, flash
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app
import common
from models import User

logger = logging.getLogger(__name__)

SUBSCRIBE_LINK_REL = 'http://ostatus.org/schema/1.0/subscribe'


@app.post('/follow')
def remote_follow():
    """Discovers and redirects to a remote follow page for a given user."""
    logger.info(f'Got: {request.values}')

    domain = request.values['domain']
    user = User.get_by_id(domain)
    if not user:
        error(f'No Bridgy Fed user found for domain {domain}')

    addr = request.values['address'].strip().strip('@')
    split = addr.split('@')
    if len(split) == 2:
        addr_domain = split[1]
        resource = f'acct:{addr}'
    elif util.is_web(addr):
        addr_domain = util.domain_from_link(addr, minimize=False)
        resource = addr
    else:
        flash('Enter your fediverse address in @user@domain.social format')
        return redirect(f'/user/{domain}')

    # look up remote user via webfinger
    try:
        resp = util.requests_get(
            f'https://{addr_domain}/.well-known/webfinger?resource={resource}')
    except BaseException as e:
        if util.is_connection_failure(e):
            flash(f"Couldn't connect to {addr_domain}")
            return redirect(f'/user/{domain}')
        raise

    if not resp.ok:
        flash(f'WebFinger on {addr_domain} returned HTTP {resp.status_code}')
        return redirect(f'/user/{domain}')

    # find remote follow link and redirect
    try:
        data = resp.json()
    except ValueError as e:
        logger.warning(f'Got {e}', exc_info=True)
        flash(f'WebFinger on {domain} returned non-JSON')
        return redirect(f'/user/{domain}')

    logger.info(f'Got: {json_dumps(data, indent=2)}')
    for link in data.get('links', []):
        if link.get('rel') == SUBSCRIBE_LINK_REL:
            template = link.get('template')
            if template and '{uri}' in template:
                return redirect(template.replace('{uri}', user.address()))

    flash(f"Couldn't find remote follow link for {addr}")
    return redirect(f'/user/{domain}')
