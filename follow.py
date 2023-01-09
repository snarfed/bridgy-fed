"""Remote follow handler.

https://github.com/snarfed/bridgy-fed/issues/60
https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020
https://www.rfc-editor.org/rfc/rfc7033
"""
import logging
import urllib.parse

from flask import redirect, request
from granary import as2
from oauth_dropins import indieauth
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error, flash
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW
from oauth_dropins.webutil.util import json_dumps, json_loads

from app import app
import common
from models import Activity, Follower, User

logger = logging.getLogger(__name__)

SUBSCRIBE_LINK_REL = 'http://ostatus.org/schema/1.0/subscribe'


def fetch_webfinger(addr):
    """Fetches and returns an address's Webfinger data.

    On failure, flashes a message and returns None.

    Args:
      addr: str, a Webfinger-compatible address, eg @x@y, acct:x@y, or
        https://x/y

    Returns:
      dict, fetched Webfinger data
    """
    addr = addr.strip().strip('@')
    split = addr.split('@')
    if len(split) == 2:
        addr_domain = split[1]
        resource = f'acct:{addr}'
    elif util.is_web(addr):
        addr_domain = util.domain_from_link(addr, minimize=False)
        resource = addr
    else:
        flash('Enter a fediverse address in @user@domain.social format')
        return None

    try:
        resp = util.requests_get(
            f'https://{addr_domain}/.well-known/webfinger?resource={resource}')
    except BaseException as e:
        if util.is_connection_failure(e):
            flash(f"Couldn't connect to {addr_domain}")
            return None
        raise

    if not resp.ok:
        flash(f'WebFinger on {addr_domain} returned HTTP {resp.status_code}')
        return None

    try:
        data = resp.json()
    except ValueError as e:
        logger.warning(f'Got {e}', exc_info=True)
        flash(f'WebFinger on {addr_domain} returned non-JSON')
        return None

    logger.info(f'Got: {json_dumps(data, indent=2)}')
    return data


@app.post('/remote-follow')
def remote_follow():
    """Discovers and redirects to a remote follow page for a given user."""
    logger.info(f'Got: {request.values}')

    domain = request.values['domain']
    user = User.get_by_id(domain)
    if not user:
        error(f'No Bridgy Fed user found for domain {domain}')

    addr = request.values['address']
    webfinger = fetch_webfinger(addr)
    if webfinger is None:
        return redirect(f'/user/{domain}')

    for link in webfinger.get('links', []):
        if link.get('rel') == SUBSCRIBE_LINK_REL:
            template = link.get('template')
            if template and '{uri}' in template:
                return redirect(template.replace('{uri}', user.address()))

    flash(f"Couldn't find remote follow link for {addr}")
    return redirect(f'/user/{domain}')


class FollowStart(indieauth.Start):
    """Starts the IndieAuth flow to add a follower to an existing user."""
    def dispatch_request(self):
        address = request.form['address']

        try:
            return redirect(self.redirect_url(state=address))
        except Exception as e:
            if util.is_connection_failure(e) or util.interpret_http_exception(e)[0]:
                flash(f"Couldn't fetch your web site: {e}")
                return redirect(f'/user/{domain}/following?address={address}')
            raise


class FollowCallback(indieauth.Callback):
    """IndieAuth callback to add a follower to an existing user."""
    def finish(self, auth_entity, state=None):
        if not auth_entity:
            return

        domain = util.domain_from_link(auth_entity.key.id())
        if not User.get_by_id(domain):
            error(f'No user for domain {domain}')

        addr = state
        if not state:
            error('Missing state')
        elif util.is_web(state):
            as2_url = state
        else:
            webfinger = fetch_webfinger(addr)
            if webfinger is None:
                return redirect(f'/user/{domain}/following')

            as2_url = None
            for link in webfinger.get('links', []):
                if link.get('rel') == 'self' and link.get('type') == as2.CONTENT_TYPE:
                    as2_url = link.get('href')

        if not as2_url:
            flash(f"Couldn't find ActivityPub profile link for {addr}")
            return redirect(f'/user/{domain}/following')

        resp = common.get_as2(as2_url)
        followee = resp.json()
        id = followee.get('id')
        inbox = followee.get('inbox')
        if not id or not inbox:
            flash(f"AS2 profile {as2_url} missing id or inbox")
            return redirect(f'/user/{domain}/following')

        timestamp = NOW.replace(microsecond=0, tzinfo=None).isoformat()
        follow_id = common.host_url(f'/user/{domain}/following#{timestamp}-{addr}')
        follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': follow_id,
            'object': followee,
            'actor': common.host_url(domain),
            'to': [as2.PUBLIC_AUDIENCE],
       }
        common.signed_post(inbox, data=follow_as2)

        follow_json = json_dumps(follow_as2, sort_keys=True)
        Follower.get_or_create(dest=id, src=domain, status='active',
                                last_follow=follow_json)
        Activity.get_or_create(source=follow_id, target=id, domain=[domain],
                               direction='out', protocol='activitypub', status='complete',
                               source_as2=follow_json)

        link = util.pretty_link(util.get_url(followee) or id, text=addr)
        flash(f'Followed {link}.')
        return redirect(f'/user/{domain}/following')


app.add_url_rule('/follow/start',
                 view_func=FollowStart.as_view('follow_start', '/follow/callback'),
                 methods=['POST'])
app.add_url_rule('/follow/callback',
                 view_func=FollowCallback.as_view('follow_callback', 'unused'),
                 methods=['GET'])
