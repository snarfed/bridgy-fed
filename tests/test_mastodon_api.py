"""Unit tests for mastodon_api.py."""
import mastodon_oauth
from web import Web

from .testutil import TestCase


class MastodonApiTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web)

    def token(self, user=None):
        return mastodon_oauth.encode_jwt({
            'typ': mastodon_oauth.TOKEN_TYP,
            'user_key': (user or self.user).key.urlsafe().decode(),
            'client_id_hash': 'test',
            'scope': '',
        })

    def auth_headers(self, user=None):
        return {'Authorization': f'Bearer {self.token(user)}'}

    def get(self, path, **kwargs):
        return self.client.get(path, headers=self.auth_headers(), **kwargs)

    def test_verify_credentials(self):
        resp = self.get('/api/v1/accounts/verify_credentials')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('alice.com', resp.json['username'])

    def test_verify_credentials_no_token(self):
        resp = self.client.get('/api/v1/accounts/verify_credentials')
        self.assertEqual(401, resp.status_code)

    def test_verify_credentials_tampered_token(self):
        token = self.token()
        bad_token = token[:-1] + ('x' if token[-1] != 'x' else 'y')
        resp = self.client.get('/api/v1/accounts/verify_credentials',
                               headers={'Authorization': f'Bearer {bad_token}'})
        self.assertEqual(401, resp.status_code)

    def test_accounts_lookup(self):
        resp = self.get('/api/v1/accounts/lookup')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({}, resp.json)

    def test_accounts_relationships(self):
        resp = self.get('/api/v1/accounts/relationships')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_get(self):
        resp = self.get('/api/v1/accounts/alice.com')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({}, resp.json)

    def test_accounts_statuses(self):
        resp = self.get('/api/v1/accounts/alice.com/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_followers(self):
        resp = self.get('/api/v1/accounts/alice.com/followers')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_following(self):
        resp = self.get('/api/v1/accounts/alice.com/following')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_blocks(self):
        resp = self.get('/api/v1/blocks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_favourites(self):
        resp = self.get('/api/v1/favourites')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_statuses_get(self):
        resp = self.get('/api/v1/statuses/123')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({}, resp.json)

    def test_statuses_context(self):
        resp = self.get('/api/v1/statuses/123/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'ancestors': [], 'descendants': []}, resp.json)

    def test_statuses_favourited_by(self):
        resp = self.get('/api/v1/statuses/123/favourited_by')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_statuses_reblogged_by(self):
        resp = self.get('/api/v1/statuses/123/reblogged_by')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_public(self):
        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_tag(self):
        resp = self.get('/api/v1/timelines/tag/foo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_search(self):
        resp = self.get('/api/v2/search')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'accounts': [], 'statuses': [], 'hashtags': []}, resp.json)

    def test_stub_endpoints_require_auth(self):
        for path in (
            '/api/v1/accounts/lookup',
            '/api/v1/accounts/relationships',
            '/api/v1/accounts/alice.com',
            '/api/v1/accounts/alice.com/statuses',
            '/api/v1/accounts/alice.com/followers',
            '/api/v1/accounts/alice.com/following',
            '/api/v1/blocks',
            '/api/v1/favourites',
            '/api/v1/statuses/123',
            '/api/v1/statuses/123/context',
            '/api/v1/statuses/123/favourited_by',
            '/api/v1/statuses/123/reblogged_by',
            '/api/v1/timelines/public',
            '/api/v1/timelines/tag/foo',
            '/api/v2/search',
        ):
            resp = self.client.get(path)
            self.assertEqual(401, resp.status_code, path)
