"""Patreon login and linking to users for donor-only features.

https://github.com/snarfed/bridgy-fed/issues/2760
"""
import logging

from google.cloud import ndb
import oauth_dropins
import oauth_dropins.patreon
from oauth_dropins.patreon import Membership, parse_membership, PatreonAuth
from requests_oauth2client import BearerToken, OAuth2Client
from webutil import util
from webutil.flask_util import flash
from webutil.util import json_dumps

from common import FlashErrors
from flask_app import app
from models import PROTOCOLS_BY_KIND
import pages

logger = logging.getLogger(__name__)

# https://docs.patreon.com/#get-api-oauth2-v2-campaigns-campaign_id-members
CAMPAIGN_ID = '14153710'
API_MEMBERS_URL = f'https://www.patreon.com/api/oauth2/v2/campaigns/{CAMPAIGN_ID}/members?include=user&fields%5Bmember%5D=patron_status,currently_entitled_amount_cents&page%5Bcount%5D=1000'

# Datastore key id of PatreonAuth with our creator tokens. Patreon user ids are
# numeric, so this can't collide with a real user's PatreonAuth.
CREATOR_AUTH_ID = 'creator'


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


def sync():
    """Syncs all users' ``is_donor`` with our Patreon campaign's members.

    Uses our creator tokens, which we store in a :class:`PatreonAuth` with id
    ``CREATOR_AUTH_ID``. Refreshes them if they've expired.

    Uses a :class:`oauth_dropins.patreon.PatreonAuth` with key id ``creator``
    with our access and refresh tokens, created with eg:

    PatreonAuth(id='creator', token_json=json.dumps({
        'access_token': '...',
        'refresh_token': '...',
    }), user_json='{}').put()
    """
    creator = PatreonAuth.get_by_id(CREATOR_AUTH_ID)
    assert creator

    logger.info('fetch A New Social members from Patreon API')
    paid_user_ids = set()  # strings
    url = API_MEMBERS_URL
    refreshed = False
    while url:
        resp = util.requests_get(url, auth=BearerToken(creator.access_token()))

        if resp.status_code == 401 and not refreshed:
            logger.info('Refreshing Patreon creator access token')
            client = OAuth2Client(
                token_endpoint=oauth_dropins.patreon.ACCESS_TOKEN_URL,
                client_id=oauth_dropins.patreon.CLIENT_ID,
                client_secret=oauth_dropins.patreon.CLIENT_SECRET,
                session=util.session)
            token = client.refresh_token(creator.refresh_token)
            creator.token_json = json_dumps(token.as_dict())
            creator.put()
            refreshed = True
            continue

        resp.raise_for_status()
        members = resp.json()
        for member in members.get('data', []):
            user_id = member['relationships']['user']['data']['id']
            if parse_membership(member.get('attributes')) == Membership.PAID:
                paid_user_ids.add(user_id)

        url = members.get('links', {}).get('next')

    logger.info(f'Paid Patreon members ({len(paid_user_ids)}): {paid_user_ids}')
    paid_keys = set(ndb.Key(PatreonAuth, id) for id in paid_user_ids)

    user_keys = set()
    for cls in set(PROTOCOLS_BY_KIND.values()):
        user_keys.update(cls.query(cls.is_donor == True).iter(keys_only=True))
        if paid_keys:
            user_keys.update(
                cls.query(cls.donor_key.IN(paid_keys)).iter(keys_only=True))

    @ndb.transactional()
    def update(user_key):
        user = user_key.get()
        is_donor = user.donor_key in paid_keys
        if user.is_donor != is_donor:
            logger.info(f'Setting {user_key.id()} is_donor={is_donor}')
            user.is_donor = is_donor
            user.put()

    for user_key in user_keys:
        update(user_key)

    return 'OK'


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
