"""Patreon login and linking to users for donor-only features.

https://github.com/snarfed/bridgy-fed/issues/2760
"""
from collections import defaultdict
import hmac
import logging

from flask import request
from google.cloud import ndb
import oauth_dropins
import oauth_dropins.patreon
from oauth_dropins.patreon import Membership, parse_membership, PatreonAuth
from requests_oauth2client import BearerToken, OAuth2Client
from webutil import util
from webutil.flask_util import error, flash
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

# https://docs.patreon.com/#webhooks
WEBHOOK_SECRET = util.read('patreon_webhook_secret')


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
    """Syncs Patreon members' memberships and their users' ``is_donor``.

    Uses our creator tokens, stored in a :class:`PatreonAuth` with key id
    ``CREATOR_AUTH_ID``, and refreshes them if they've expired. Create it with eg:

    PatreonAuth(id='creator', token_json=json.dumps({
        'access_token': '...',
        'refresh_token': '...',
    }), user_json='{}').put()

    If there are no paid members at all, assumes something went wrong and skips
    updating, so that we don't clear everyone's ``is_donor``.
    """
    creator = PatreonAuth.get_by_id(CREATOR_AUTH_ID)
    assert creator, f'No PatreonAuth {CREATOR_AUTH_ID} with our creator tokens'

    logger.info('fetching A New Social Patreon members from API')
    members = {}  # Patreon string user id => member attributes dict
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
        page = resp.json()
        for member in page.get('data', []):
            user_id = member['relationships']['user']['data']['id']
            members[user_id] = member.get('attributes') or {}

        url = page.get('links', {}).get('next')

    logger.info(f'Got {len(members)} Patreon members')
    if not any(parse_membership(attrs) == Membership.PAID
               for attrs in members.values()):
        error('No paid Patreon members! Skipping updates', status=304)

    user_keys_by_auth = defaultdict(list)
    for cls in set(PROTOCOLS_BY_KIND.values()):
        for user in cls.query(cls.donor_key != None):
            user_keys_by_auth[user.donor_key].append(user.key)

    for auth_key, user_keys in user_keys_by_auth.items():
        update_donor(auth_key, user_keys, members.get(auth_key.id()))

    return 'OK'


@app.post('/patreon/webhook')
def webhook():
    """Handles a Patreon webhook for a member update.

    Verifies the signature, then updates ``is_donor`` on the member's linked users.

    https://docs.patreon.com/#webhooks
    """
    assert WEBHOOK_SECRET, 'No patreon_webhook_secret'
    signature = request.headers.get('X-Patreon-Signature', '')
    expected = hmac.new(WEBHOOK_SECRET.encode(), request.get_data(), 'md5'
                        ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        error('Invalid X-Patreon-Signature', status=401)

    event = request.headers.get('X-Patreon-Event', '')
    member = request.json['data']
    user_id = member['relationships']['user']['data']['id']
    logger.info(f'Patreon {event} for user {user_id}')

    attrs = member.get('attributes') or {}
    if event == 'members:delete':
        attrs = None
    elif event == 'members:pledge:delete':
        # attributes may be from before the pledge was deleted
        attrs = {**attrs, 'patron_status': 'former_patron'}

    auth_key = ndb.Key(PatreonAuth, user_id)
    user_keys = []
    for cls in set(PROTOCOLS_BY_KIND.values()):
        user_keys.extend(cls.query(cls.donor_key == auth_key).iter(keys_only=True))

    update_donor(auth_key, user_keys, attrs)
    return 'OK'


@ndb.transactional()
def update_donor(auth_key, user_keys, attrs):
    """Updates a Patreon account's membership and its linked users' ``is_donor``.

    Args:
      auth_key (google.cloud.ndb.Key): :class:`PatreonAuth` key
      user_keys (sequence of google.cloud.ndb.Key): :class:`models.User` keys
        linked to this Patreon account
      attrs (dict): JSON:API member attributes, or None if they're not a member
    """
    auth = auth_key.get()
    if not auth:
        logger.warning(f'No PatreonAuth for {auth_key.id()}')
        return

    user_json = auth.user_json
    auth.set_membership(attrs)
    if auth.user_json != user_json:
        auth.put()

    membership = auth.get_membership()
    is_donor = membership == Membership.PAID
    logger.info(f'Patreon user {auth_key.id()} membership: {membership}')

    for user in ndb.get_multi(user_keys):
        if user and user.is_donor != is_donor:
            logger.info(f'Setting {user.key.id()} is_donor={is_donor}')
            user.is_donor = is_donor
            user.put()


#
# OAuth
#
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
