"""Patreon login and linking Patreon accounts to users for donor features.

https://github.com/snarfed/bridgy-fed/issues/2760
"""
import logging

import oauth_dropins
import oauth_dropins.patreon
from oauth_dropins.patreon import Membership, PatreonAuth
from webutil.flask_util import flash

from common import FlashErrors
from flask_app import app
import pages

logger = logging.getLogger(__name__)


def link(auth, users, overwrite=False):
    """Links users to a Patreon account.

    Updates their ``donor_key`` and ``is_donor``. Flashes a message with the users
    that were newly linked, if any.

    Args:
      auth (oauth_dropins.patreon.PatreonAuth)
      users (sequence of models.User)
      overwrite (bool): whether to relink users that are already linked to a
        different Patreon account
    """
    membership = auth.get_membership()
    logger.info(f'Patreon user {auth.key.id()} membership: {membership}')
    is_donor = membership == Membership.PAID

    linked = []
    for user in users:
        if not overwrite and user.donor_key not in (None, auth.key):
            logger.info(f'{user.key.id()} is already linked to Patreon user {user.donor_key.id()}')
            continue

        if user.donor_key != auth.key or user.is_donor != is_donor:
            logger.info(f'Linking {user.key.id()} to Patreon user {auth.key.id()}, is_donor={is_donor}')
            if user.donor_key != auth.key:
                linked.append(user.handle_or_id())
            user.donor_key = auth.key
            user.is_donor = is_donor
            user.put()

    if linked:
        flash(f'Linked {", ".join(linked)} to Patreon.')


class PatreonStart(FlashErrors, oauth_dropins.patreon.Start):
    pass


class PatreonCallback(FlashErrors, oauth_dropins.patreon.Callback):
    def finish(self, auth_entity, state=None):
        """Drops any existing Patreon login so that there's only one at a time."""
        if auth_entity:
            for login in pages.get_logins():
                if isinstance(login, PatreonAuth) and login.key != auth_entity.key:
                    logger.info(f'Replacing Patreon login {login.key.id()} with {auth_entity.key.id()}')
                    oauth_dropins.logout(login)

        return super().finish(auth_entity, state=state)


app.add_url_rule('/oauth/patreon/start', view_func=PatreonStart.as_view(
                     '/oauth/patreon/start', '/oauth/patreon/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/patreon/finish', view_func=PatreonCallback.as_view(
                     '/oauth/patreon/finish', '/settings'))


