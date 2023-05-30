"""Remote follow handler.

https://github.com/snarfed/bridgy-fed/issues/60
https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020
https://www.rfc-editor.org/rfc/rfc7033
"""
import logging
import urllib.parse

from flask import g, redirect, request, session
from granary import as2
from oauth_dropins import indieauth
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error, flash
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import NOW
from oauth_dropins.webutil.util import json_dumps, json_loads

from activitypub import ActivityPub
from flask_app import app
import common
import models
from web import Web

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
    # TODO(#512): parameterize by protocol
    g.user = Web.get_by_id(domain)
    if not g.user:
        error(f'No web user found for domain {domain}')

    addr = request.values['address']
    webfinger = fetch_webfinger(addr)
    if webfinger is None:
        return redirect(g.user.user_page_path())

    for link in webfinger.get('links', []):
        if link.get('rel') == SUBSCRIBE_LINK_REL:
            template = link.get('template')
            if template and '{uri}' in template:
                return redirect(template.replace('{uri}', g.user.address()))

    flash(f"Couldn't find remote follow link for {addr}")
    return redirect(g.user.user_page_path())


class FollowStart(indieauth.Start):
    """Starts the IndieAuth flow to add a follower to an existing user."""
    def dispatch_request(self):
        address = request.form['address']
        me = request.form['me']

        session_me = session.get('indieauthed-me')
        if session_me:
            logger.info(f'found indieauthed-me: {session_me} in session cookie')
            if session_me == me:
                logger.info('  skipping IndieAuth')
                return FollowCallback('-').finish(indieauth.IndieAuth(id=me), address)

        try:
            return redirect(self.redirect_url(state=address))
        except Exception as e:
            if util.is_connection_failure(e) or util.interpret_http_exception(e)[0]:
                flash(f"Couldn't fetch your web site: {e}")
                domain = util.domain_from_link(me)
                return redirect(f'/web/{domain}/following?address={address}')
            raise


class FollowCallback(indieauth.Callback):
    """IndieAuth callback to add a follower to an existing user."""
    def finish(self, auth_entity, state=None):
        if not auth_entity:
            return

        me = auth_entity.key.id()
        logger.info(f'Storing indieauthed-me: {me} in session cookie')
        session['indieauthed-me'] = me

        domain = util.domain_from_link(me)
        # TODO(#512): parameterize by protocol
        g.user = Web.get_by_id(domain)
        if not g.user:
            error(f'No web user for domain {domain}')
        domain = g.user.key.id()

        addr = state
        if not state:
            error('Missing state')
        elif util.is_web(state):
            as2_url = state
        else:
            webfinger = fetch_webfinger(addr)
            if webfinger is None:
                return redirect(g.user.user_page_path('following'))

            as2_url = None
            for link in webfinger.get('links', []):
                type = link.get('type', '').split(';')[0]
                if link.get('rel') == 'self' and type in as2.CONTENT_TYPES:
                    as2_url = link.get('href')

        if not as2_url:
            flash(f"Couldn't find ActivityPub profile link for {addr}")
            return redirect(g.user.user_page_path('following'))

        # TODO: make this generic across protocols
        followee = ActivityPub.load(as2_url).as2
        id = followee.get('id')
        inbox = followee.get('inbox')
        if not id or not inbox:
            flash(f"AS2 profile {as2_url} missing id or inbox")
            return redirect(g.user.user_page_path('following'))

        timestamp = NOW.replace(microsecond=0, tzinfo=None).isoformat()
        follow_id = common.host_url(g.user.user_page_path(f'following#{timestamp}-{addr}'))
        follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': follow_id,
            'object': followee,
            'actor': g.user.actor_id(),
            'to': [as2.PUBLIC_AUDIENCE],
        }
        obj = models.Object(id=follow_id, domains=[domain], labels=['user'],
                            source_protocol='ui', status='complete', as2=follow_as2)
        ActivityPub.send(obj, inbox)

        models.Follower.get_or_create(dest=id, src=domain, status='active',
                                      last_follow=follow_as2)
        obj.put()

        link = common.pretty_link(util.get_url(followee) or id, text=addr)
        flash(f'Followed {link}.')
        return redirect(g.user.user_page_path('following'))


class UnfollowStart(indieauth.Start):
    """Starts the IndieAuth flow to remove a follower from an existing user."""
    def dispatch_request(self):
        key = request.form['key']
        me = request.form['me']

        session_me = session.get('indieauthed-me')
        if session_me:
            logger.info(f'has IndieAuth session for {session_me}')
            if session_me == me:
                return UnfollowCallback('-').finish(indieauth.IndieAuth(id=me), key)

        try:
            return redirect(self.redirect_url(state=key))
        except Exception as e:
            if util.is_connection_failure(e) or util.interpret_http_exception(e)[0]:
                flash(f"Couldn't fetch your web site: {e}")
                return redirect(g.user.user_page_path('following'))
            raise


class UnfollowCallback(indieauth.Callback):
    """IndieAuth callback to remove a follower."""
    def finish(self, auth_entity, state=None):
        if not auth_entity:
            return

        me = auth_entity.key.id()
        # store login in a session cookie
        session['indieauthed-me'] = me

        domain = util.domain_from_link(me)
        # TODO(#512): parameterize by protocol
        g.user = Web.get_by_id(domain)
        if not g.user:
            error(f'No web user for domain {domain}')
        domain = g.user.key.id()

        follower = models.Follower.get_by_id(state)
        if not follower:
            error(f'Bad state {state}')

        followee_id = follower.dest
        followee = follower.last_follow['object']

        # TODO: make this generic across protocols
        if isinstance(followee, str):
            # fetch as AS2 to get full followee with inbox
            followee_id = followee
            followee = ActivityPub.load(followee_id).as2

        inbox = followee.get('inbox')
        if not inbox:
            flash(f"AS2 profile {followee_id} missing inbox")
            return redirect(g.user.user_page_path('following'))

        timestamp = NOW.replace(microsecond=0, tzinfo=None).isoformat()
        unfollow_id = common.host_url(g.user.user_page_path(f'following#undo-{timestamp}-{followee_id}'))
        unfollow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Undo',
            'id': unfollow_id,
            'actor': g.user.actor_id(),
            'object': follower.last_follow,
        }

        obj = models.Object(id=unfollow_id, domains=[domain], labels=['user'],
                            source_protocol='ui', status='complete', as2=unfollow_as2)
        ActivityPub.send(obj, inbox)

        follower.status = 'inactive'
        follower.put()
        obj.put()

        link = common.pretty_link(util.get_url(followee) or followee_id)
        flash(f'Unfollowed {link}.')
        return redirect(g.user.user_page_path('following'))


app.add_url_rule('/follow/start',
                 view_func=FollowStart.as_view('follow_start', '/follow/callback'),
                 methods=['POST'])
app.add_url_rule('/follow/callback',
                 view_func=FollowCallback.as_view('follow_callback', 'unused'),
                 methods=['GET'])
app.add_url_rule('/unfollow/start',
                 view_func=UnfollowStart.as_view('unfollow_start', '/unfollow/callback'),
                 methods=['POST'])
app.add_url_rule('/unfollow/callback',
                 view_func=UnfollowCallback.as_view('unfollow_callback', 'unused'),
                 methods=['GET'])
