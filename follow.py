"""Remote follow handler.

* https://github.com/snarfed/bridgy-fed/issues/60
* https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020
* https://www.rfc-editor.org/rfc/rfc7033
"""
import logging

from flask import redirect, request, session
from oauth_dropins import indieauth
import requests
from webutil import util
from webutil.flask_util import error, flash
from werkzeug.exceptions import BadGateway, HTTPException

from activitypub import ActivityPub
from flask_app import app
import common
from domains import DOMAINS
from models import Follower, load_user, Object, PROTOCOLS
from protocol import Protocol
from web import Web
import webfinger

logger = logging.getLogger(__name__)


@app.post('/remote-follow')
def remote_follow():
    """Discovers and redirects to a remote follow page for a given user."""
    common.log_request()

    cls = PROTOCOLS.get(request.values['protocol'])
    if not cls:
        error(f'Unknown protocol {request.values["protocol"]}')

    id = request.values['id']
    user = cls.get_by_id(id)
    if not user:
        error(f'No {cls.LABEL} user found for {id}')

    addr = request.values['address']
    resp = webfinger.fetch(addr)
    if resp is None:
        return redirect(user.user_page_path())

    for link in resp.get('links', []):
        if link.get('rel') == webfinger.SUBSCRIBE_LINK_REL:
            template = link.get('template')
            if template and '{uri}' in template:
                return redirect(template.replace('{uri}', user.handle_as(ActivityPub)))

    flash(f"Couldn't find remote follow link for {addr}")
    return redirect(user.user_page_path())


class FollowStart(indieauth.Start):
    """Starts the IndieAuth flow to add a follower to an existing user."""
    def dispatch_request(self):
        common.log_request()

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
        # Web is hard-coded here since this is IndieAuth
        user = Web.get_by_id(domain)
        if not user:
            error(f'No web user for domain {domain}')

        if not state:
            error('Missing state')

        addr = state
        addr_domain = (util.domain_from_link(addr) if util.is_web(addr)
                       else addr.split('@')[-1])
        if util.domain_or_parent_in(addr_domain, DOMAINS):
            proto = Protocol.for_bridgy_subdomain(addr_domain)
            on = f' on {proto.PHRASE}' if proto else ''
            flash(f'{addr} is a bridged account. Try following them with their native handle{on}!')
            return redirect(user.user_page_path('following'))

        try:
            followee = load_user(addr, create=True, allow_opt_out=True, raise_=True,
                                 resolve=True)
        except BadGateway as e:
            if (e.requests_response is not None
                    and e.requests_response.status_code in (401, 403)):
                flash(f"Couldn't load {addr}; they or their server may be blocking Bridgy Fed.")
            else:
                flash(f"Couldn't load {addr}: {e.description}")
            return redirect(user.user_page_path('following'))
        except (RuntimeError, ValueError, requests.RequestException,
                HTTPException) as e:
            _, msg = util.interpret_http_exception(e)
            flash(msg or str(e))
            return redirect(user.user_page_path('following'))

        logger.info(f'{addr} resolved to {followee.key}')
        if type(followee) == type(user):
            flash(f'{addr} is on {user.PHRASE} too! Try following them in a feed reader.')
            return redirect(user.user_page_path('following'))
        elif not user.is_enabled(type(followee)):
            flash(f'Bridge your site into {followee.PHRASE} first, then try following {addr} again.')
            return redirect(user.user_page_path('following'))
        elif not followee.is_enabled(Web):
            msg = f"{addr} isn't bridged into {Web.PHRASE}"
            if desc := followee.status_description():
                msg += f': {desc}'
            flash(msg)
            return redirect(user.user_page_path('following'))

        followee_id = followee.key.id()
        timestamp = util.now().replace(microsecond=0, tzinfo=None).isoformat()
        follow_id = f'{user.web_url()}#follow-{timestamp}-{followee_id}'
        follow_as1 = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': follow_id,
            'actor': user.key.id(),
            'object': followee_id,
        }
        follow_obj = Object(id=follow_id, users=[user.key], our_as1=follow_as1,
                            source_protocol='web')

        resp = Web.receive(follow_obj, authed_as=domain, internal=True)
        logger.info(f'Web.receive returned {resp}')

        link = common.pretty_link(followee.web_url(), text=addr)
        flash(f'Followed {link}.', escape=False)
        return redirect(user.user_page_path('following'))


class UnfollowStart(indieauth.Start):
    """Starts the IndieAuth flow to remove a follower from an existing user."""
    def dispatch_request(self):
        common.log_request()
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
                domain = util.domain_from_link(me)
                return redirect(f'/web/{domain}/following')
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
        # Web is hard-coded here since this is IndieAuth
        user = Web.get_by_id(domain)
        if not user:
            error(f'No web user for domain {domain}')

        if util.is_int(state):
            state = int(state)
        follower = Follower.get_by_id(state)
        if not follower:
            error(f'Bad state {state}')

        followee_id = follower.to.id()
        followee = follower.to.get()

        timestamp = util.now().replace(microsecond=0, tzinfo=None).isoformat()
        unfollow_id = f'{user.web_url()}#bridgy-fed-unfollow-{timestamp}-{followee_id}'
        unfollow_as1 = {
            'objectType': 'activity',
            'verb': 'stop-following',
            'id': unfollow_id,
            'actor': user.key.id(),
            'object': followee.key.id(),
        }

        # don't include the followee User who's being unfollowed in the users
        # property, since we don't want to notify or show them. (standard social
        # network etiquette.)
        unfollow_obj = Object(id=unfollow_id, users=[user.key],
                              source_protocol='web', our_as1=unfollow_as1)
        resp = Web.receive(unfollow_obj, authed_as=domain, internal=True)

        follower.status = 'inactive'
        follower.put()

        link = common.pretty_link(followee.web_url())
        flash(f'Unfollowed {link}.', escape=False)
        return redirect(user.user_page_path('following'))


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
