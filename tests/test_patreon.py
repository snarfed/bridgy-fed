"""Unit tests for patreon.py."""
import hmac
from unittest.mock import patch

import oauth_dropins.patreon
from oauth_dropins.patreon import Membership, PatreonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from requests_oauth2client import BearerToken
from webutil import util
from webutil.testutil import requests_response
from webutil.util import json_dumps, json_loads

from .testutil import Fake, OtherFake, TestCase

import patreon


@patch.multiple(oauth_dropins.patreon, CLIENT_ID='abc', CLIENT_SECRET='xyz')
@patch.object(patreon, 'WEBHOOK_SECRET', 'sekret')
class PatreonTest(TestCase):

    def test_start(self):
        resp = self.client.post('/oauth/patreon/start')
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(
            'https://www.patreon.com/oauth2/authorize?'), resp.headers['Location'])

    @patch.object(util.session, 'request', return_value=requests_response({
        'access_token': 'towkin',
        'token_type': 'Bearer',
    }))
    @patch.object(util.session, 'get', return_value=requests_response({
        'data': {
            'id': '456',
            'attributes': {'full_name': 'Bob Patron'},
        },
    }))
    def test_finish_drops_existing_patreon_login(self, _, __):
        PatreonAuth(id='123', token_json='{}', user_json=json_dumps({
            'data': {
                'id': '123',
                'attributes': {'full_name': 'Alice Patron'},
            },
        })).put()
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [
                ('MastodonAuth', '@a@b.c'),
                ('PatreonAuth', '123'),
            ]

        resp = self.client.get('/oauth/patreon/finish?code=my_code')
        self.assertEqual(302, resp.status_code, resp.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            self.assertEqual([
                ('MastodonAuth', '@a@b.c'),
                ('PatreonAuth', '456'),
            ], sess[LOGINS_SESSION_KEY])

    @patch.object(util.session, 'get', side_effect=[
        requests_response({
            'data': [{
                'type': 'member',
                'attributes': {
                    'patron_status': 'active_patron',
                    'currently_entitled_amount_cents': 500,
                },
                'relationships': {'user': {'data': {'id': '111', 'type': 'user'}}},
            }, {
                'type': 'member',
                'attributes': {
                    'patron_status': 'active_patron',
                    'currently_entitled_amount_cents': 0,
                },
                'relationships': {'user': {'data': {'id': '222', 'type': 'user'}}},
            }],
            'links': {'next': 'https://www.patreon.com/next-page'},
        }),
        requests_response({
            'data': [{
                'type': 'member',
                'attributes': {
                    'patron_status': 'active_patron',
                    'currently_entitled_amount_cents': 300,
                },
                'relationships': {'user': {'data': {'id': '333', 'type': 'user'}}},
            }],
        }),
    ])
    def test_sync(self, mock_get):
        PatreonAuth(id='creator', token_json=json_dumps({
            'access_token': 'stored',
            'refresh_token': 'stored-refresh',
        }), user_json='{}').put()

        paid = PatreonAuth(id='111', token_json='{}', user_json='{}')
        paid.put()
        free = PatreonAuth(id='222', token_json='{}', user_json='{}')
        free.put()
        gone = PatreonAuth(id='444', token_json='{}', user_json='{}')
        gone.put()

        alice = self.make_user('fake:alice', cls=Fake, donor_key=paid.key,
                               is_donor=False)
        bob = self.make_user('other:bob', cls=OtherFake, donor_key=paid.key)
        carol = self.make_user('fake:carol', cls=Fake, donor_key=free.key,
                               is_donor=True)
        eve = self.make_user('fake:eve', cls=Fake, donor_key=gone.key,
                             is_donor=True)
        frank = self.make_user('fake:frank', cls=Fake)

        resp = self.get('/cron/patreon-sync')
        self.assertEqual(200, resp.status_code)

        self.assertEqual([
            self.req(patreon.API_MEMBERS_URL, auth=BearerToken('stored')),
            self.req('https://www.patreon.com/next-page', auth=BearerToken('stored')),
        ], mock_get.call_args_list)

        self.assertTrue(alice.key.get().is_donor)
        self.assertTrue(bob.key.get().is_donor)
        self.assertFalse(carol.key.get().is_donor)
        self.assertFalse(eve.key.get().is_donor)
        self.assertIsNone(frank.key.get().is_donor)

        self.assertEqual(Membership.PAID, paid.key.get().get_membership())
        self.assertEqual(Membership.FREE, free.key.get().get_membership())
        self.assertIsNone(gone.key.get().get_membership())

    @patch.object(util.session, 'get', return_value=requests_response({
        'data': [{
            'type': 'member',
            'attributes': {
                'patron_status': 'active_patron',
                'currently_entitled_amount_cents': 0,
            },
            'relationships': {'user': {'data': {'id': '111', 'type': 'user'}}},
        }],
    }))
    def test_sync_no_paid_members_skips_updates(self, _):
        PatreonAuth(id='creator', token_json=json_dumps({
            'access_token': 'stored',
        }), user_json='{}').put()

        patron = PatreonAuth(id='111', token_json='{}', user_json='{}')
        patron.put()
        alice = self.make_user('fake:alice', cls=Fake, donor_key=patron.key,
                               is_donor=True)

        resp = self.get('/cron/patreon-sync')
        self.assertEqual(304, resp.status_code)
        self.assertTrue(alice.key.get().is_donor)
        self.assertEqual('{}', patron.key.get().user_json)

    @patch.object(util.session, 'request', return_value=requests_response({
        'access_token': 'new',
        'refresh_token': 'new-refresh',
        'token_type': 'Bearer',
    }))
    @patch.object(util.session, 'get', side_effect=[
        requests_response('', status=401),
        requests_response({'data': []}),
    ])
    def test_sync_refreshes_token(self, mock_get, mock_request):
        PatreonAuth(id='creator', token_json=json_dumps({
            'access_token': 'old',
            'refresh_token': 'old-refresh',
        }), user_json='{}').put()

        resp = self.get('/cron/patreon-sync')
        self.assertEqual(304, resp.status_code)

        self.assertEqual([
            self.req(patreon.API_MEMBERS_URL, auth=BearerToken('old')),
            self.req(patreon.API_MEMBERS_URL, auth=BearerToken('new')),
        ], mock_get.call_args_list)

        mock_request.assert_called_once()
        self.assertEqual({
            'grant_type': 'refresh_token',
            'refresh_token': 'old-refresh',
        }, mock_request.call_args.kwargs['data'])

        self.assertEqual({
            'access_token': 'new',
            'refresh_token': 'new-refresh',
            'token_type': 'Bearer',
        }, json_loads(PatreonAuth.get_by_id('creator').token_json))

    def post_webhook(self, event, member, secret='sekret'):
        body = json_dumps({
            'data': {
                'type': 'member',
                'id': 'abc-def',
                'attributes': member,
                'relationships': {'user': {'data': {'id': '111', 'type': 'user'}}},
            },
        }).encode()
        return self.client.post('/patreon/webhook', data=body, headers={
            'Content-Type': 'application/json',
            'X-Patreon-Event': event,
            'X-Patreon-Signature': hmac.new(secret.encode(), body, 'md5').hexdigest(),
        })

    def test_webhook(self):
        patron = PatreonAuth(id='111', token_json='{}', user_json='{}')
        patron.put()
        other = PatreonAuth(id='222', token_json='{}', user_json='{}')
        other.put()

        alice = self.make_user('fake:alice', cls=Fake, donor_key=patron.key)
        bob = self.make_user('other:bob', cls=OtherFake, donor_key=patron.key,
                             is_donor=False)
        carol = self.make_user('fake:carol', cls=Fake, donor_key=other.key,
                               is_donor=True)

        paid = {
            'patron_status': 'active_patron',
            'currently_entitled_amount_cents': 300,
        }
        for event, member, expected in (
            ('members:pledge:create', paid, Membership.PAID),
            ('members:update', {'patron_status': 'active_patron',
                                'currently_entitled_amount_cents': 0},
             Membership.FREE),
            ('members:pledge:update', paid, Membership.PAID),
            ('members:pledge:update', {'patron_status': 'declined_patron',
                                       'currently_entitled_amount_cents': 300},
             Membership.FORMER),
            ('members:update', paid, Membership.PAID),
            ('members:pledge:delete', paid, Membership.FORMER),
            ('members:update', paid, Membership.PAID),
            ('members:delete', paid, None),
        ):
            with self.subTest(event=event, member=member):
                resp = self.post_webhook(event, member)
                self.assertEqual(200, resp.status_code)
                self.assertEqual(expected, patron.key.get().get_membership())
                is_donor = expected == Membership.PAID
                self.assertEqual(is_donor, alice.key.get().is_donor)
                self.assertEqual(is_donor, bob.key.get().is_donor)
                self.assertTrue(carol.key.get().is_donor)
                self.assertEqual('{}', other.key.get().user_json)

    def test_webhook_no_patreon_auth(self):
        resp = self.post_webhook('members:pledge:create', {
            'patron_status': 'active_patron',
            'currently_entitled_amount_cents': 500,
        })
        self.assertEqual(200, resp.status_code)
        self.assertIsNone(PatreonAuth.get_by_id('111'))

    def test_webhook_bad_signature(self):
        patron = PatreonAuth(id='111', token_json='{}', user_json='{}')
        patron.put()
        alice = self.make_user('fake:alice', cls=Fake, donor_key=patron.key)

        resp = self.post_webhook('members:pledge:create', {
            'patron_status': 'active_patron',
            'currently_entitled_amount_cents': 500,
        }, secret='wrong')
        self.assertEqual(401, resp.status_code)
        self.assertIsNone(alice.key.get().is_donor)

    def test_webhook_no_signature(self):
        resp = self.client.post('/patreon/webhook', json={'data': {}})
        self.assertEqual(401, resp.status_code)
