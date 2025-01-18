"""Remote follow handler.

* https://github.com/snarfed/bridgy-fed/issues/60
* https://socialhub.activitypub.rocks/t/what-is-the-current-spec-for-remote-follow/2020
* https://www.rfc-editor.org/rfc/rfc7033
"""
import logging

from flask import redirect, request, session
from granary import as1
from oauth_dropins import indieauth
from oauth_dropins.webutil import util
from oauth_dropins.webutil.flask_util import error, flash

from activitypub import ActivityPub
from flask_app import app
import common
from models import Follower, Object, PROTOCOLS
from protocol import Protocol
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
        user = Web.get_by_id(domain)
        if not user:
            error(f'No web user for domain {domain}')

        if not state:
            error('Missing state')

        addr = state
        if util.is_web(addr):
            as2_url = addr
        else:  # it's an @-@ handle
            # if ActivityPub.owns_handle(addr) is False:
            #     flash(f"{addr} isn't a native fediverse account")
            #     return redirect(user.user_page_path('following'))
            as2_url = webfinger.fetch_actor_url(addr)

        if util.domain_or_parent_in(util.domain_from_link(as2_url), common.DOMAINS):
            proto = Protocol.for_id(as2_url)
            flash(f"{addr} is a bridged account. Try following them on {proto.PHRASE}!")
            return redirect(user.user_page_path('following'))
        elif ActivityPub.owns_id(as2_url) is False:
            flash(f"{addr} isn't a native fediverse account")
            return redirect(user.user_page_path('following'))

        # TODO(#512): follower will always be Web here, but we should generalize
        # followee support in UI and here across protocols
        followee = ActivityPub.load(as2_url)
        if not followee:
            flash(f"Couldn't load {as2_url} as AS2")
            return redirect(user.user_page_path('following'))

        followee_id = followee.as1.get('id')
        timestamp = util.now().replace(microsecond=0, tzinfo=None).isoformat()
        follow_id = f'{user.web_url()}#follow-{timestamp}-{addr}'
        follow_as1 = {
            'objectType': 'activity',
            'verb': 'follow',
            'id': follow_id,
            'actor': user.key.id(),
            'object': followee_id,
        }
        followee_user = ActivityPub.get_or_create(followee_id, obj=followee)
        follow_obj = Object(id=follow_id, our_as1=follow_as1, source_protocol='ui',
                            labels=['user'])

        resp = Web.receive(follow_obj, authed_as=domain, internal=True)
        logger.info(f'Web.receive returned {resp}')

        follow_obj = follow_obj.key.get()
        follow_obj.source_protocol = 'ui'
        follow_obj.put()

        url = as1.get_url(followee.as1) or followee_id
        link = common.pretty_link(url, text=addr)
        flash(f'Followed {link}.')
        return redirect(user.user_page_path('following'))


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

        if not followee.obj or not followee.obj.as1:
            # fetch to get full followee so we can find its target to deliver to
            followee.obj = ActivityPub.load(followee_id)
            if not followee.obj:
                error("Couldn't load {followee_id} as AS2")
            followee.put()

        # TODO(#529): generalize
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
        follow_obj = Object(id=unfollow_id, users=[user.key], labels=['user'],
                            source_protocol='ui', our_as1=unfollow_as1)
        resp = Web.receive(follow_obj, authed_as=domain, internal=True)

        follower.status = 'inactive'
        follower.put()

        follow_obj = follow_obj.key.get()
        follow_obj.source_protocol = 'ui'
        follow_obj.put()

        link = common.pretty_link(as1.get_url(followee.obj.as1) or followee_id)
        flash(f'Unfollowed {link}.')
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
