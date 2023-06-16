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
from models import Follower, Object, PROTOCOLS
from web import Web
import webfinger

logger = logging.getLogger(__name__)


@app.post('/remote-follow')
def remote_follow():
    """Discovers and redirects to a remote follow page for a given user."""
    logger.info(f'Got: {request.values}')

    cls = PROTOCOLS.get(request.values['protocol'])
    if not cls:
        error(f'Unknown protocol {request.values["protocol"]}')

    domain = request.values['domain']
    g.user = cls.get_by_id(domain)
    if not g.user:
        error(f'No web user found for domain {domain}')

    addr = request.values['address']
    resp = webfinger.fetch(addr)
    if resp is None:
        return redirect(g.user.user_page_path())

    for link in resp.get('links', []):
        if link.get('rel') == webfinger.SUBSCRIBE_LINK_REL:
            template = link.get('template')
            if template and '{uri}' in template:
                return redirect(template.replace('{uri}', g.user.ap_address()))

    flash(f"Couldn't find remote follow link for {addr}")
    return redirect(g.user.user_page_path())


class FollowStart(indieauth.Start):
    """Starts the IndieAuth flow to add a follower to an existing user."""
    def dispatch_request(self):
        logger.info(f'Got: {request.values}')

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
        g.user = Web.get_by_id(domain)
        if not g.user:
            error(f'No web user for domain {domain}')

        addr = state
        if not state:
            error('Missing state')
        elif util.is_web(state):
            as2_url = state
        else:
            resp = webfinger.fetch(addr)
            if resp is None:
                return redirect(g.user.user_page_path('following'))

            as2_url = None
            for link in resp.get('links', []):
                type = link.get('type', '').split(';')[0]
                if link.get('rel') == 'self' and type in as2.CONTENT_TYPES:
                    as2_url = link.get('href')

        if not as2_url:
            flash(f"Couldn't find ActivityPub profile link for {addr}")
            return redirect(g.user.user_page_path('following'))

        # TODO(#512): follower will always be Web here, but we should generalize
        # followee support in UI and here across protocols
        followee = ActivityPub.load(as2_url)
        followee_id = followee.as1.get('id')
        inbox = followee.as2.get('inbox')
        if not followee_id or not inbox:
            flash(f"AS2 profile {as2_url} missing id or inbox")
            return redirect(g.user.user_page_path('following'))

        timestamp = NOW.replace(microsecond=0, tzinfo=None).isoformat()
        follow_id = common.host_url(g.user.user_page_path(f'following#{timestamp}-{addr}'))
        follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': follow_id,
            'object': followee.as2,
            'actor': g.user.ap_actor(),
            'to': [as2.PUBLIC_AUDIENCE],
        }
        followee_user = ActivityPub.get_or_create(followee_id, obj=followee)
        follow_obj = Object(id=follow_id, users=[g.user.key, followee_user.key],
                            labels=['user'], source_protocol='ui', status='complete',
                            as2=follow_as2)
        ActivityPub.send(follow_obj, inbox)

        Follower.get_or_create(from_=g.user, to=followee_user, status='active',
                               follow=follow_obj.key)
        follow_obj.put()

        link = common.pretty_link(util.get_url(followee.as1) or followee_id,
                                  text=addr)
        flash(f'Followed {link}.')
        return redirect(g.user.user_page_path('following'))


class UnfollowStart(indieauth.Start):
    """Starts the IndieAuth flow to remove a follower from an existing user."""
    def dispatch_request(self):
        logger.info(f'Got: {request.values}')
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
        # Web is hard-coded here since this is IndieAuth
        g.user = Web.get_by_id(domain)
        if not g.user:
            error(f'No web user for domain {domain}')

        if util.is_int(state):
            state = int(state)
        follower = Follower.get_by_id(state)
        if not follower:
            error(f'Bad state {state}')

        followee_id = follower.to.id()
        followee = follower.to.get()

        if not followee.obj or not followee.obj.as1:
            # fetch to get full followee so we can find its target to deliver to
            followee.obj = ActivityPub.load(followee_id)
            followee.put()

        # TODO(#529): generalize
        inbox = followee.as2().get('inbox')
        if not inbox:
            flash(f"AS2 profile {followee_id} missing inbox")
            return redirect(g.user.user_page_path('following'))

        timestamp = NOW.replace(microsecond=0, tzinfo=None).isoformat()
        unfollow_id = common.host_url(g.user.user_page_path(f'following#undo-{timestamp}-{followee_id}'))
        unfollow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Undo',
            'id': unfollow_id,
            'actor': g.user.ap_actor(),
            'object': follower.follow.get().as2 if follower.follow else None,
        }

        # don't include the followee User who's being unfollowed in the users
        # property, since we don't want to notify or show them. (standard social
        # network etiquette.)
        obj = Object(id=unfollow_id, users=[g.user.key], labels=['user'],
                     source_protocol='ui', status='complete', as2=unfollow_as2)
        ActivityPub.send(obj, inbox)

        follower.status = 'inactive'
        follower.put()
        obj.put()

        link = common.pretty_link(util.get_url(followee.obj.as1) or followee_id)
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
