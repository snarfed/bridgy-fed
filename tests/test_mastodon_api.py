"""Unit tests for mastodon_api.py."""
from unittest.mock import patch

from oauth_dropins.bluesky import BlueskyAuth
from webutil import util
from webutil.testutil import requests_response
from webutil.util import json_dumps

from atproto import ATProto
import mastodon_api, mastodon_oauth
from mastodon_api import to_account, to_status, to_notification
from models import Follower, Object, Target
from web import Web

from activitypub import ActivityPub
from .test_activitypub import ACTOR
from . import test_atproto
from .testutil import Fake, OtherFake, TestCase

WEBFINGER = requests_response({
    'subject': 'acct:foo@mas.to',
    'links': [{
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'https://mas.to/users/foo',
    }],
}, content_type='application/jrd+json')

DID_DOC = {
    **test_atproto.DID_DOC,
    'alsoKnownAs': ['at://han.dull'],
}

class MastodonApiTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:alice', cls=Fake,
                                   enabled_protocols=['activitypub'],
                                   obj_as1={
                                       'objectType': 'person',
                                       'displayName': 'Alice',
                                       'summary': 'hi im alice',
                                       'preferredUsername': 'alice',
                                   })

    def token(self, user=None):
        return mastodon_oauth.encode_jwt({
            'typ': mastodon_oauth.TOKEN_TYP,
            'user_key': (user or self.user).key.urlsafe().decode(),
            'client_id_hash': 'test',
            'scope': '',
        })

    def request(self, path, method=None, user=None, **kwargs):
        auth_header = {'Authorization': f'Bearer {self.token(user)}'}
        return self.client.open(path, headers=auth_header, method=method, **kwargs)

    def get(self, path, **kwargs):
        return self.request(path, method='GET', **kwargs)

    def post(self, path, **kwargs):
        return self.request(path, method='POST', **kwargs)

    def put(self, path, **kwargs):
        return self.request(path, method='PUT', **kwargs)

    def delete(self, path, **kwargs):
        return self.request(path, method='DELETE', **kwargs)

    def make_atproto_user(self):
        """Makes an ATProto user with a :class:`BlueskyAuth` for their own PDS."""
        BlueskyAuth(id='did:plc:user', pds_url='https://some.pds/',
                    user_json=json_dumps({'did': 'did:plc:user', 'handle': 'ha.nd'}),
                    session={'accessJwt': 'towkin', 'refreshJwt': 'reefresh'},
                    ).put()
        self.store_object(id='did:plc:user', raw=DID_DOC)
        return self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=['activitypub'])

    def test_health(self):
        resp = self.client.get('/health')
        self.assertEqual(200, resp.status_code)
        self.assertEqual({'status': 'UP'}, resp.json)

    def test_instance(self):
        resp = self.client.get('/api/v2/instance')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertIn('domain', resp.json)
        self.assertIn('title', resp.json)
        self.assertIn('version', resp.json)

    @patch('mastodon_api.DEBUG', False)
    @patch('mastodon_api.LOCAL_SERVER', False)
    def test_api_404s_on_non_primary_domain(self):
        resp = self.client.get('/api/v2/instance', base_url='https://bsky.brid.gy')
        self.assertEqual(404, resp.status_code)

    @patch('mastodon_api.DEBUG', False)
    @patch('mastodon_api.LOCAL_SERVER', False)
    def test_api_served_on_primary_domain(self):
        resp = self.client.get('/api/v2/instance', base_url='https://fed.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

    def test_instance_extended_description(self):
        resp = self.client.get('/api/v1/instance/extended_description')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertIn('content', resp.json)
        self.assertIn('updated_at', resp.json)

    def test_instance_privacy_policy(self):
        resp = self.client.get('/api/v1/instance/privacy_policy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertIn('content', resp.json)
        self.assertIn('updated_at', resp.json)

    def test_instance_terms_of_service(self):
        resp = self.client.get('/api/v1/instance/terms_of_service')
        self.assertEqual(200, resp.status_code)
        self.assertIn('content', resp.json)

    def test_verify_credentials(self):
        self.user.obj.our_as1['published'] = '2026-07-20T01:02:03Z'
        resp = self.get('/api/v1/accounts/verify_credentials')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'id': 'fake~3Aalice',
            'acct': 'fake-handle-alice@fa.brid.gy',
            'uri': 'https://fa.brid.gy/ap/fake:alice',
            'url': '',
            'created_at': '2026-07-20T01:02:03Z',
            'display_name': 'Alice',
            'username': 'alice',
            'note': 'hi im alice',
            'avatar': None,
            'avatar_static': None,
            'bot': False,
            'followers_count': 0,
            'following_count': 0,
            'header': '',
            'header_static': '',
            'locked': False,
            'statuses_count': 0,
        }, resp.json)

    def test_verify_credentials_no_token(self):
        resp = self.client.get('/api/v1/accounts/verify_credentials')
        self.assertEqual(401, resp.status_code)

    def test_verify_credentials_tampered_token(self):
        bad_token = self.token()[:-1] + '!'
        resp = self.client.get('/api/v1/accounts/verify_credentials',
                               headers={'Authorization': f'Bearer {bad_token}'})
        self.assertEqual(401, resp.status_code)

    def test_preferences(self):
        resp = self.get('/api/v1/preferences')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'posting:default:visibility': 'public',
            'posting:default:sensitive': False,
            'posting:default:language': None,
            'reading:expand:media': 'default',
            'reading:expand:spoilers': False,
        }, resp.json)

    def test_accounts_lookup(self):
        for acct in 'fake-handle-alice@fa.brid.gy', '@fake-handle-alice@fa.brid.gy':
            with self.subTest(acct=acct):
                resp = self.get(f'/api/v1/accounts/lookup?acct={acct}')
                self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
                self.assertEqual('fake~3Aalice', resp.json['id'])
                self.assertEqual('hi im alice', resp.json['note'])

    def test_accounts_lookup_fediverse(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)

        for acct in 'foo@mas.to', '@foo@mas.to':
            with self.subTest(acct=acct):
                resp = self.get(f'/api/v1/accounts/lookup?acct={acct}')
                self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
                self.assertEqual('https~3A~2F~2Fmas.to~2Fusers~2Ffoo', resp.json['id'])
                self.assertEqual('https://mas.to/users/foo', resp.json['uri'])

    def test_accounts_lookup_not_found(self):
        resp = self.get('/api/v1/accounts/lookup?acct=nope@fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_accounts_relationships(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/relationships?id[]=other:bob')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([{
            'id': 'other~3Abob',
            'following': False,
            'showing_reblogs': False,
            'notifying': False,
            'followed_by': False,
            'blocking': False,
            'blocked_by': False,
            'muting': False,
            'muting_notifications': False,
            'requested': False,
            'domain_blocking': False,
            'endorsed': False,
            'note': '',
        }], resp.json)

    def test_accounts_relationships_client_encoded_id(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/relationships?id[]=other%7E3Abob')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('other~3Abob', resp.json[0]['id'])

    def test_accounts_relationships_unknown_id(self):
        resp = self.get('/api/v1/accounts/relationships?id[]=fake:nope')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_relationships_following(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Follower.get_or_create(from_=self.user, to=bob)
        resp = self.get('/api/v1/accounts/relationships?id[]=other:bob')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json[0]['following'])
        self.assertFalse(resp.json[0]['followed_by'])

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.graph.follow/456',
        'cid': 'bafyreifollowsyddddddddddddddddddddddddddddddddddddddddd',
    }))
    def test_accounts_follow(self, mock_post):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/follow", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json['following'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.graph.follow',
            'record': {
                '$type': 'app.bsky.graph.follow',
                'subject': 'did:plc:bob',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    def test_accounts_follow_not_bridged(self):
        user = self.make_atproto_user()
        bob = self.make_user('fake:bob', cls=Fake)

        resp = self.post("/api/v1/accounts/fake~3Abob/follow", user=user)
        self.assertEqual(422, resp.status_code)

    def test_accounts_follow_not_found(self):
        user = self.make_atproto_user()
        resp = self.post('/api/v1/accounts/nope/follow', user=user)
        self.assertEqual(404, resp.status_code)

    def test_accounts_follow_non_atproto_user(self):
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])
        resp = self.post("/api/v1/accounts/fake~3Abob/follow")
        self.assertEqual(501, resp.status_code)

    # deleteRecord
    @patch.object(util.session, 'post', return_value=requests_response({}))
    def test_accounts_unfollow(self, mock_post):
        user = self.make_atproto_user()
        bob = self.make_user('fake:bob', cls=Fake,
                             copies=[Target(uri='did:plc:bob', protocol='atproto')])
        follow_obj = Object(id='at://did:plc:user/app.bsky.graph.follow/456',
                            source_protocol='atproto', users=[user.key],
                            our_as1={
                                'objectType': 'activity',
                                'verb': 'follow',
                                'actor': 'did:plc:user',
                                'object': 'fake:bob',
                            })
        follow_obj.put()
        Follower.get_or_create(from_=user, to=bob, follow=follow_obj.key)

        resp = self.post("/api/v1/accounts/fake~3Abob/unfollow", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['following'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.deleteRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.graph.follow',
            'rkey': '456',
        }, mock_post.call_args.kwargs['json'])

    def test_accounts_unfollow_not_following(self):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/unfollow", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['following'])

    def test_accounts_unfollow_non_atproto_user(self):
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/unfollow")
        self.assertEqual(501, resp.status_code)

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.graph.block/456',
        'cid': 'bafyreiblocksyddddddddddddddddddddddddddddddddddddddddd',
    }))
    def test_accounts_block(self, mock_post):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/block", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json['blocking'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.graph.block',
            'record': {
                '$type': 'app.bsky.graph.block',
                'subject': 'did:plc:bob',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    def test_accounts_block_not_bridged(self):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake)

        resp = self.post("/api/v1/accounts/fake~3Abob/block", user=user)
        self.assertEqual(422, resp.status_code)

    def test_accounts_block_not_found(self):
        user = self.make_atproto_user()
        resp = self.post('/api/v1/accounts/nope/block', user=user)
        self.assertEqual(404, resp.status_code)

    def test_accounts_block_non_atproto_user(self):
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/block")
        self.assertEqual(501, resp.status_code)

    # deleteRecord
    @patch.object(util.session, 'post', return_value=requests_response({}))
    def test_accounts_unblock(self, mock_post):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])
        Object(id='at://did:plc:user/app.bsky.graph.block/456',
              source_protocol='atproto', users=[user.key],
              our_as1={
                  'objectType': 'activity',
                  'verb': 'block',
                  'actor': 'did:plc:user',
                  'object': 'fake:bob',
              }).put()

        resp = self.post("/api/v1/accounts/fake~3Abob/unblock", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['blocking'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.deleteRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.graph.block',
            'rkey': '456',
        }, mock_post.call_args.kwargs['json'])

    def test_accounts_unblock_not_blocking(self):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/unblock", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['blocking'])

    def test_accounts_unblock_non_atproto_user(self):
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        resp = self.post("/api/v1/accounts/fake~3Abob/unblock")
        self.assertEqual(501, resp.status_code)

    def test_follow_requests(self):
        resp = self.get('/api/v1/follow_requests')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts(self):
        resp = self.get('/api/v1/accounts/fake:alice')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('fake~3Aalice', resp.json['id'])
        self.assertEqual('https://fa.brid.gy/ap/fake:alice', resp.json['uri'])

    def test_accounts_client_encoded_id(self):
        resp = self.get('/api/v1/accounts/fake%7E3Aalice')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('fake~3Aalice', resp.json['id'])

    def test_accounts_activitypub_actor_id(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)
        resp = self.get('/api/v1/accounts/https://mas.to/users/foo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('https~3A~2F~2Fmas.to~2Fusers~2Ffoo', resp.json['id'])
        self.assertEqual('foo@mas.to', resp.json['acct'])

    def test_accounts_web_domain(self):
        self.make_user('user.com', cls=Web, enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/user.com')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('user.com', resp.json['id'])
        self.assertEqual('user.com@web.brid.gy', resp.json['acct'])

    def test_accounts_not_found(self):
        resp = self.get('/api/v1/accounts/nope:nope')
        self.assertEqual(404, resp.status_code)

    def test_accounts_statuses(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

    def test_accounts_statuses_loads_reblog_author(self):
        self.make_user('fake:bob', cls=Fake, obj_as1={
            'objectType': 'person',
            'displayName': 'Bob',
        })
        Object(id='fake:post', our_as1={
            'objectType': 'note',
            'author': 'fake:bob',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:share', users=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:alice',
            'object': 'fake:post',
            'published': '2022-01-02T03:04:05',
        }).put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('Bob', resp.json[0]['reblog']['account']['display_name'])

    def test_accounts_statuses_drops_unresolvable_reblog(self):
        Fake.fetchable['fake:profile:bob'] = {
            'objectType': 'person',
            'id': 'fake:profile:bob',
            'displayName': 'Bob',
        }
        post = self.store_object(id='fake:post', our_as1={
            'objectType': 'note',
            'author': 'fake:bob',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        })
        self.store_object(id='fake:share', users=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:alice',
            'object': 'fake:post',
            'published': '2022-01-02T03:04:05',
        })

        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        # bob isn't in the datastore yet, and we don't load externally
        # outside of search/lookup, so the repost should be dropped
        self.assertEqual(to_status(post), resp.json[0]['reblog'])

    def test_accounts_statuses_pinned(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:not-pinned', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'not pinned',
            'published': '2022-01-02T03:04:05',
        }).put()

        self.user.obj.our_as1['featured'] = {
            'totalItems': 1,
            'items': ['fake:post'],
        }
        self.user.obj.put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses?pinned=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

    def test_accounts_statuses_pinned_none(self):
        resp = self.get('/api/v1/accounts/fake:alice/statuses?pinned=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_statuses_pinned_unconvertible(self):
        Object(id='fake:nope', our_as1={
            'objectType': 'note',
            'content': 'orphan',
        }).put()

        self.user.obj.our_as1['featured'] = {
            'totalItems': 1,
            'items': ['fake:nope'],
        }
        self.user.obj.put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses?pinned=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_statuses_pinned_unconvertible_only_media(self):
        Object(id='fake:nope', our_as1={
            'objectType': 'note',
            'content': 'orphan',
        }).put()

        self.user.obj.our_as1['featured'] = {
            'totalItems': 1,
            'items': ['fake:nope'],
        }
        self.user.obj.put()

        resp = self.get(
            '/api/v1/accounts/fake:alice/statuses?pinned=true&only_media=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_statuses_max_since_min_id(self):
        for i in range(1, 4):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
                'published': '2022-01-02T03:04:05',
            }).put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses?max_id=fake:post3')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['post 2', 'post 1'], [s['content'] for s in resp.json])

        resp = self.get('/api/v1/accounts/fake:alice/statuses?since_id=fake:post1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['post 3', 'post 2'], [s['content'] for s in resp.json])

        resp = self.get('/api/v1/accounts/fake:alice/statuses?min_id=fake:post1&limit=1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['post 2'], [s['content'] for s in resp.json])

    def test_accounts_statuses_max_id_not_found(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        resp = self.get('/api/v1/accounts/fake:alice/statuses?max_id=fake:nope')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))

    def test_accounts_statuses_exclude_replies(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:reply', users=[self.user.key], our_as1={
            'objectType': 'comment',
            'content': 'a reply',
            'inReplyTo': 'fake:post',
            'published': '2022-01-02T03:04:05',
        }).put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(2, len(resp.json))

        resp = self.get('/api/v1/accounts/fake:alice/statuses?exclude_replies=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

    def test_accounts_statuses_exclude_reblogs(self):
        Object(id='fake:post', our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:share', users=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:alice',
            'object': 'fake:post',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:own-post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my own post',
            'published': '2022-01-02T03:04:05',
        }).put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(2, len(resp.json))

        resp = self.get('/api/v1/accounts/fake:alice/statuses?exclude_reblogs=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('my own post', resp.json[0]['content'])

    def test_accounts_statuses_only_media(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        Object(id='fake:media-post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'a photo',
            'published': '2022-01-02T03:04:05',
            'attachments': [{
                'objectType': 'image',
                'image': {'url': 'http://foo.com/image.jpg'},
            }],
        }).put()

        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(2, len(resp.json))

        resp = self.get('/api/v1/accounts/fake:alice/statuses?only_media=true')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('a photo', resp.json[0]['content'])

    def test_accounts_statuses_excludes_deleted_and_non_public(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
        }).put()
        Object(id='fake:deleted', users=[self.user.key], deleted=True, our_as1={
            'objectType': 'note',
            'content': 'deleted',
        }).put()
        Object(id='fake:private', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'private',
            'to': [{'alias': '@private'}],
        }).put()
        resp = self.get('/api/v1/accounts/fake:alice/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

    def test_accounts_followers(self):
        bob = self.make_user('other:bob', cls=OtherFake)
        Follower.get_or_create(from_=bob, to=self.user)
        resp = self.get('/api/v1/accounts/fake:alice/followers')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('other~3Abob', resp.json[0]['id'])

    def test_accounts_following(self):
        bob = self.make_user('other:bob', cls=OtherFake)
        Follower.get_or_create(from_=self.user, to=bob)
        resp = self.get('/api/v1/accounts/fake:alice/following')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('other~3Abob', resp.json[0]['id'])

    def test_accounts_statuses_account_not_found(self):
        resp = self.get('/api/v1/accounts/fake:nope/statuses')
        self.assertEqual(404, resp.status_code)

    def test_accounts_followers_account_not_found(self):
        resp = self.get('/api/v1/accounts/fake:nope/followers')
        self.assertEqual(404, resp.status_code)

    def test_accounts_following_account_not_found(self):
        resp = self.get('/api/v1/accounts/fake:nope/following')
        self.assertEqual(404, resp.status_code)

    def test_accounts_featured_tags(self):
        resp = self.get('/api/v1/accounts/fake:alice/featured_tags')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_lists(self):
        resp = self.get('/api/v1/accounts/fake:alice/lists')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_endorsements(self):
        resp = self.get('/api/v1/accounts/fake:alice/endorsements')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_familiar_followers(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/familiar_followers?id[]=other:bob&id[]=456')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([
            {'id': 'other:bob', 'accounts': []},
            {'id': '456', 'accounts': []},
        ], resp.json)

    def test_followed_tags(self):
        resp = self.get('/api/v1/followed_tags')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_blocks(self):
        resp = self.get('/api/v1/blocks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_bookmarks(self):
        resp = self.get('/api/v1/bookmarks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_favourites(self):
        Object(id='fake:liked', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'liked post',
        }).put()
        Object(id='fake:like', users=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'actor': 'fake:alice',
            'object': 'fake:liked',
        }).put()

        resp = self.get('/api/v1/favourites')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('liked post', resp.json[0]['content'])

    def test_statuses_multiple(self):
        Object(id='fake:post1', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'one',
        }).put()
        Object(id='fake:post2', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'two',
        }).put()
        Object(id='fake:deleted', deleted=True, our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'deleted',
        }).put()

        resp = self.get('/api/v1/statuses?id[]=fake:post1&id[]=fake:post2&id[]=fake:deleted&id[]=fake:nope')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['one', 'two'], [s['content'] for s in resp.json])

    def test_statuses_multiple_client_encoded_id(self):
        Object(id='fake:post1', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'one',
        }).put()

        resp = self.get('/api/v1/statuses?id[]=fake%7E3Apost1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['one'], [s['content'] for s in resp.json])

    def test_statuses_single(self):
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/fake:post')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_equals({
            'id': 'fake~3Apost',
            'uri': 'https://fa.brid.gy/convert/ap/fake:post',
            'url': '',
            'account': to_account(self.user),
            'content': 'hello',
            'created_at': None,
            'emojis': [],
            'favourites_count': 0,
            'in_reply_to_account_id': None,
            'in_reply_to_id': None,
            'media_attachments': [],
            'mentions': [],
            'reblogs_count': 0,
            'replies_count': 0,
            'sensitive': False,
            'spoiler_text': '',
            'tags': [],
            'visibility': 'public',
        }, resp.json)

    def test_statuses_repost(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        self.store_object(id='fake:post', users=[bob.key], our_as1={
            'objectType': 'note',
            'content': 'original',
        })
        self.store_object(id='fake:share', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'author': 'fake:alice',
            'object': 'fake:post',
        })

        resp = self.get('/api/v1/statuses/fake:share')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('original', resp.json['reblog']['content'])
        self.assertEqual(to_account(bob), resp.json['reblog']['account'])

    def test_statuses_single_not_found(self):
        resp = self.get('/api/v1/statuses/nope')
        self.assertEqual(404, resp.status_code)

    def test_statuses_single_client_encoded_id(self):
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/fake%7E3Apost')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])

    def test_statuses_single_url_id(self):
        # clients like Phanpy round trip ids through their own URLs, which
        # URL-decodes them. our encoding has no % or /, so that's a noop.
        Object(id='https://snarfed.org/a_b', source_protocol='web', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'hello',
        }).put()
        resp = self.get('/api/v1/statuses/https~3A~2F~2Fsnarfed.org~2Fa_b')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('https~3A~2F~2Fsnarfed.org~2Fa_b', resp.json['id'])
        self.assertEqual('hello', resp.json['content'])

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.like/456',
        'cid': 'bafyreiblikesyddddddddddddddddddddddddddddddddddddddddddd',
    }))
    # getRecord
    @patch.object(util.session, 'get', return_value=requests_response({
        'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
        'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
        'value': {},
    }))
    def test_statuses_favourite(self, _, mock_post):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        self.store_object(
            id='fake:post',
            source_protocol='fake',
            copies=[Target(uri='at://did:plc:bob/app.bsky.feed.post/123',
                           protocol='atproto')],
            our_as1={
                'objectType': 'note',
                'actor': 'did:plc:bob',
                'content': 'hello',
            },
        )

        resp = self.post('/api/v1/statuses/fake~3Apost/favourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertTrue(resp.json['favourited'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.like',
            'record': {
                '$type': 'app.bsky.feed.like',
                'subject': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                    'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
                },
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    def test_statuses_favourite_not_bridged_to_bluesky(self):
        user = self.make_atproto_user()
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()

        resp = self.post('/api/v1/statuses/fake~3Apost/favourite', user=user)
        self.assertEqual(422, resp.status_code)

    def test_statuses_favourite_not_found(self):
        user = self.make_atproto_user()
        resp = self.post('/api/v1/statuses/nope/favourite', user=user)
        self.assertEqual(404, resp.status_code)

    def test_statuses_favourite_non_atproto_user(self):
        self.store_object(
            id='fake:post',
            # users=[self.user.key],
            # source_protocol='fake',
            copies=[Target(uri='at://did:plc:bob/app.bsky.feed.post/123',
                           protocol='atproto')],
            our_as1={'objectType': 'note', 'content': 'hello'},
        )

        resp = self.post('/api/v1/statuses/fake~3Apost/favourite')
        self.assertEqual(501, resp.status_code)

    # deleteRecord
    @patch.object(util.session, 'post', return_value=requests_response({}))
    def test_statuses_unfavourite(self, mock_post):
        user = self.make_atproto_user()
        self.store_object(
            id='fake:post', users=[self.user.key], source_protocol='fake',
            our_as1={'objectType': 'note', 'content': 'hello'})
        Object(id='at://did:plc:user/app.bsky.feed.like/456',
              source_protocol='atproto', users=[user.key],
              our_as1={
                  'objectType': 'activity',
                  'verb': 'like',
                  'actor': 'did:plc:user',
                  'object': 'fake:post',
              }).put()

        resp = self.post('/api/v1/statuses/fake~3Apost/unfavourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertFalse(resp.json['favourited'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.deleteRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.like',
            'rkey': '456',
        }, mock_post.call_args.kwargs['json'])

    def test_statuses_unfavourite_not_favourited(self):
        user = self.make_atproto_user()
        self.store_object(
            id='fake:post', users=[self.user.key], source_protocol='fake',
            our_as1={'objectType': 'note', 'content': 'hello'})

        resp = self.post('/api/v1/statuses/fake~3Apost/unfavourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['favourited'])

    def test_statuses_unfavourite_not_found(self):
        user = self.make_atproto_user()
        resp = self.post('/api/v1/statuses/nope/unfavourite', user=user)
        self.assertEqual(404, resp.status_code)

    def test_statuses_unfavourite_non_atproto_user(self):
        self.store_object(
            id='fake:post', source_protocol='fake',
            our_as1={'objectType': 'note', 'content': 'hello'})

        resp = self.post('/api/v1/statuses/fake~3Apost/unfavourite')
        self.assertEqual(501, resp.status_code)

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.repost/456',
        'cid': 'bafyreibrepostsyddddddddddddddddddddddddddddddddddddddddd',
    }))
    # getRecord
    @patch.object(util.session, 'get', return_value=requests_response({
        'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
        'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
        'value': {},
    }))
    def test_statuses_reblog(self, _, mock_post):
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        self.store_object(
            id='fake:post',
            source_protocol='fake',
            copies=[Target(uri='at://did:plc:bob/app.bsky.feed.post/123',
                           protocol='atproto')],
            our_as1={
                'objectType': 'note',
                'actor': 'did:plc:bob',
                'content': 'hello',
            },
        )

        resp = self.post('/api/v1/statuses/fake~3Apost/reblog', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertTrue(resp.json['reblogged'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.repost',
            'record': {
                '$type': 'app.bsky.feed.repost',
                'subject': {
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                    'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
                },
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    # deleteRecord
    @patch.object(util.session, 'post', return_value=requests_response({}))
    def test_statuses_unreblog(self, mock_post):
        user = self.make_atproto_user()
        self.store_object(
            id='fake:post', users=[self.user.key], source_protocol='fake',
            our_as1={'objectType': 'note', 'content': 'hello'})
        Object(id='at://did:plc:user/app.bsky.feed.repost/456',
              source_protocol='atproto', users=[user.key],
              our_as1={
                  'objectType': 'activity',
                  'verb': 'share',
                  'actor': 'did:plc:user',
                  'object': 'fake:post',
              }).put()

        resp = self.post('/api/v1/statuses/fake~3Apost/unreblog', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertFalse(resp.json['reblogged'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.deleteRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.repost',
            'rkey': '456',
        }, mock_post.call_args.kwargs['json'])

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.post/456',
        'cid': 'bafyreipostsyddddddddddddddddddddddddddddddddddddddddddd',
    }))
    def test_statuses_create(self, mock_post):
        user = self.make_atproto_user()
        # a plain, non-bridged handle, so to_account(user) doesn't try to route it
        # back through ActivityPub's fa.brid.gy subdomain
        self.store_object(id='did:plc:user', raw=DID_DOC)

        resp = self.post('/api/v1/statuses', user=user, data={'status': 'hello world'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello world', resp.json['content'])
        self.assertEqual(to_account(user), resp.json['account'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.post',
            'record': {
                '$type': 'app.bsky.feed.post',
                'text': 'hello world',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.post/456',
        'cid': 'bafyreipostsyddddddddddddddddddddddddddddddddddddddddddd',
    }))
    def test_statuses_create_json(self, mock_post):
        user = self.make_atproto_user()
        self.store_object(id='did:plc:user', raw=DID_DOC)

        resp = self.post('/api/v1/statuses', user=user, json={'status': 'hello world'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello world', resp.json['content'])
        self.assertEqual(to_account(user), resp.json['account'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.createRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.post',
            'record': {
                '$type': 'app.bsky.feed.post',
                'text': 'hello world',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    # createRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.post/456',
        'cid': 'bafyreipostsyddddddddddddddddddddddddddddddddddddddddddd',
    }))
    # getRecord
    @patch.object(util.session, 'get', return_value=requests_response({
        'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
        'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
        'value': {},
    }))
    def test_statuses_create_reply(self, _, mock_post):
        user = self.make_atproto_user()
        self.store_object(id='did:plc:user', raw={
            **DID_DOC,
            'alsoKnownAs': ['at://han.dull'],
        })
        self.make_user('fake:bob', cls=Fake,
                       copies=[Target(uri='did:plc:bob', protocol='atproto')])

        self.store_object(
            id='fake:post',
            source_protocol='fake',
            copies=[Target(uri='at://did:plc:bob/app.bsky.feed.post/123',
                           protocol='atproto')],
            our_as1={'objectType': 'note', 'actor': 'did:plc:bob', 'content': 'orig'})

        params = {'status': 'a reply', 'in_reply_to_id': 'fake~3Apost'}
        for kwargs in ({'data': params}, {'json': params}):
            resp = self.post('/api/v1/statuses', user=user, **kwargs)
            self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
            self.assertEqual('a reply', resp.json['content'])
            self.assertEqual('fake~3Apost', resp.json['in_reply_to_id'])

            self.assert_equals({
                'repo': 'did:plc:user',
                'collection': 'app.bsky.feed.post',
                'record': {
                    '$type': 'app.bsky.feed.post',
                    'text': 'a reply',
                    'createdAt': '2022-01-02T03:04:05.000Z',
                    'reply': {
                        '$type': 'app.bsky.feed.post#replyRef',
                        'root': {
                            'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                            'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
                        },
                        'parent': {
                            'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                            'cid': 'bafyreibobsyddddddddddddddddddddddddddddddddddddddddddddd',
                        },
                    },
                },
            }, mock_post.call_args.kwargs['json'])

    def test_statuses_create_missing_status(self):
        user = self.make_atproto_user()
        resp = self.post('/api/v1/statuses', user=user, data={})
        self.assertEqual(400, resp.status_code)

    def test_statuses_create_reply_not_bridged(self):
        user = self.make_atproto_user()
        self.store_object(id='fake:post', users=[self.user.key], source_protocol='fake',
                          our_as1={'objectType': 'note', 'content': 'orig'})

        resp = self.post('/api/v1/statuses', user=user,
                         data={'status': 'a reply', 'in_reply_to_id': 'fake~3Apost'})
        self.assertEqual(422, resp.status_code)

    def test_statuses_create_non_atproto_user(self):
        resp = self.post('/api/v1/statuses', data={'status': 'hi'})
        self.assertEqual(501, resp.status_code)

    # putRecord
    @patch.object(util.session, 'post', return_value=requests_response({
        'uri': 'at://did:plc:user/app.bsky.feed.post/456',
        'cid': 'bafyreipostsyddddddddddddddddddddddddddddddddddddddddddd',
    }))
    def test_statuses_update(self, mock_post):
        user = self.make_atproto_user()
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.store_object(
            id='at://did:plc:user/app.bsky.feed.post/456',
            source_protocol='atproto', users=[user.key],
            our_as1={
                'objectType': 'note',
                'content': 'hello',
                'actor': 'did:plc:user',
                'published': '2022-01-02T03:04:05.000Z',
            })

        resp = self.put(
            "/api/v1/statuses/at~3A~2F~2Fdid:plc:user~2Fapp.bsky.feed.post~2F456",
            user=user, data={'status': 'updated'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('updated', resp.json['content'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.putRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.post',
            'rkey': '456',
            'record': {
                '$type': 'app.bsky.feed.post',
                'text': 'updated',
                'createdAt': '2022-01-02T03:04:05.000Z',
            },
        }, mock_post.call_args.kwargs['json'])

    def test_statuses_update_missing_status(self):
        user = self.make_atproto_user()
        self.store_object(
            id='at://did:plc:user/app.bsky.feed.post/456',
            source_protocol='atproto', users=[user.key],
            our_as1={'objectType': 'note', 'content': 'hello'})

        resp = self.put(
            "/api/v1/statuses/at~3A~2F~2Fdid:plc:user~2Fapp.bsky.feed.post~2F456",
            user=user, data={})
        self.assertEqual(400, resp.status_code)

    def test_statuses_update_non_atproto_user(self):
        self.store_object(id='fake:post', users=[self.user.key], source_protocol='fake',
                          our_as1={'objectType': 'note', 'content': 'hello'})
        resp = self.put('/api/v1/statuses/fake~3Apost', data={'status': 'updated'})
        self.assertEqual(501, resp.status_code)

    # deleteRecord
    @patch.object(util.session, 'post', return_value=requests_response({}))
    def test_statuses_delete(self, mock_post):
        user = self.make_atproto_user()
        self.store_object(id='did:plc:user', raw=DID_DOC)
        self.store_object(
            id='at://did:plc:user/app.bsky.feed.post/456',
            source_protocol='atproto', users=[user.key],
            our_as1={'objectType': 'note', 'content': 'hello', 'actor': 'did:plc:user'})

        resp = self.delete(
            "/api/v1/statuses/at~3A~2F~2Fdid:plc:user~2Fapp.bsky.feed.post~2F456",
            user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])

        self.assertEqual('https://some.pds/xrpc/com.atproto.repo.deleteRecord',
                         mock_post.call_args.args[0])
        self.assert_equals({
            'repo': 'did:plc:user',
            'collection': 'app.bsky.feed.post',
            'rkey': '456',
        }, mock_post.call_args.kwargs['json'])

    def test_statuses_delete_not_found(self):
        user = self.make_atproto_user()
        resp = self.delete('/api/v1/statuses/nope', user=user)
        self.assertEqual(404, resp.status_code)

    def test_statuses_delete_non_atproto_user(self):
        self.store_object(id='fake:post', users=[self.user.key], source_protocol='fake',
                          our_as1={'objectType': 'note', 'content': 'hello'})
        resp = self.delete('/api/v1/statuses/fake~3Apost')
        self.assertEqual(501, resp.status_code)

    def test_statuses_context(self):
        Object(id='fake:root', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'root',
        }).put()
        Object(id='fake:reply', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'reply',
            'inReplyTo': 'fake:root',
        }).put()

        resp = self.get('/api/v1/statuses/fake:reply/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json['ancestors']))
        self.assertEqual('root', resp.json['ancestors'][0]['content'])
        self.assertEqual([], resp.json['descendants'])

    def test_statuses_context_not_found(self):
        resp = self.get('/api/v1/statuses/nope/context')
        self.assertEqual(404, resp.status_code)

    def test_statuses_favourited_by(self):
        Object(id='fake:post', our_as1={
            'objectType': 'note',
            'content': 'hello',
        }).put()
        resp = self.get('/api/v1/statuses/fake:post/favourited_by')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_statuses_favourited_by_not_found(self):
        resp = self.get('/api/v1/statuses/nope/favourited_by')
        self.assertEqual(404, resp.status_code)

    def test_statuses_reblogged_by(self):
        Object(id='fake:post', our_as1={
            'objectType': 'note',
            'content': 'hello',
        }).put()
        resp = self.get('/api/v1/statuses/fake:post/reblogged_by')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_public(self):
        Object(id='fake:not-followed', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'not in my feed',
        }).put()
        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('not in my feed', resp.json[0]['content'])

    def test_timelines_public_multiple_owners(self):
        for name in ('bob', 'carol', 'dave'):
            self.make_user(f'fake:{name}', cls=Fake, obj_as1={
                'objectType': 'person',
                'displayName': name.capitalize(),
            })
            Object(id=f'fake:{name}-post', our_as1={
                'objectType': 'note',
                'author': f'fake:{name}',
                'content': f'hi from {name}',
                'published': '2022-01-02T03:04:05',
            }).put()

        Object(id='fake:alice-post', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'unrelated standalone post',
            'published': '2022-01-02T03:04:05',
        }).put()

        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        by_content = {}
        self.assertEqual({
            'hi from bob': 'Bob',
            'hi from carol': 'Carol',
            'hi from dave': 'Dave',
            'unrelated standalone post': 'Alice',
        }, {s['content']: s['account']['display_name'] for s in resp.json})

    def test_timelines_public_web_owner_by_home_page_url(self):
        self.make_user('user.com', cls=Web, enabled_protocols=['activitypub'],
                       obj_as1={'objectType': 'person', 'displayName': 'Dubya'})
        Object(id='http://user.com/post', source_protocol='web', our_as1={
            'objectType': 'note',
            'author': 'https://user.com/',
            'content': 'hi',
            'published': '2022-01-02T03:04:05',
        }).put()

        # the author id is the user's home page URL, but their key id is their
        # bare domain, so loading them requires normalizing first
        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('Dubya', resp.json[0]['account']['display_name'])

    def test_timelines_public_excludes_deleted_and_non_public(self):
        Object(id='fake:deleted', deleted=True, our_as1={
            'objectType': 'note',
            'content': 'deleted',
        }).put()
        Object(id='fake:private', our_as1={
            'objectType': 'note',
            'content': 'private',
            'to': [{'alias': '@private'}],
        }).put()
        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_home(self):
        self.make_user('fake:bob', cls=Fake, enabled_protocols=['activitypub'])
        Object(id='fake:post', feed=[self.user.key],
               source_protocol='fake', our_as1={
                   'objectType': 'note',
                   'content': 'in my feed',
                   'author': 'fake:bob',
               }).put()
        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('in my feed', resp.json[0]['content'])

    def test_to_status_owner_from_author_no_users(self):
        self.make_user('fake:bob', cls=Fake, enabled_protocols=['activitypub'])
        obj = Object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'hi',
            'author': 'fake:bob',
        })
        status = to_status(obj)
        self.assertEqual('fake~3Abob', status['account']['id'])

    def test_to_status_no_owner_no_users(self):
        obj = Object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'hi',
        })
        status = to_status(obj)
        self.assertIsNone(status)

    @patch.object(util.session, 'get', return_value=requests_response(status=404))
    def test_to_status_owner_unresolvable_handle(self, _):
        obj = Object(id='fake:post', source_protocol='fake', our_as1={
            'objectType': 'note',
            'content': 'hi',
            'author': 'https://in.st/@user',
        })
        # shouldn't raise, even though the author can't be resolved to a protocol
        status = to_status(obj)
        self.assertEqual('hi', status['content'])

    def test_timelines_home_excludes_deleted_and_non_public(self):
        Object(id='fake:deleted', feed=[self.user.key], deleted=True, our_as1={
            'objectType': 'note',
            'content': 'deleted',
        }).put()
        Object(id='fake:private', feed=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'private',
            'to': [{'alias': '@private'}],
        }).put()
        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_home_excludes_unsupported_type(self):
        self.store_object(id='fake:page', feed=[self.user.key], our_as1={
            'objectType': 'page',
            'content': 'a page',
            'author': 'fake:bob',
        })
        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_tag(self):
        resp = self.get('/api/v1/timelines/tag/foo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_search_accounts(self):
        for url in (
                '/api/v2/search?type=accounts&q=@fake-handle-alice@fa.brid.gy',
                '/api/v2/search?q=@fake-handle-alice@fa.brid.gy',
                '/api/v2/search?q=fake-handle-alice@fa.brid.gy',
        ):
          with self.subTest(url=url):
            resp = self.get(url)
            self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
            self.assert_equals({
                'accounts': [
                    {
                        'id': 'fake~3Aalice',
                        'acct': 'fake-handle-alice@fa.brid.gy',
                        'uri': 'https://fa.brid.gy/ap/fake:alice',
                        'username': 'alice',
                        'url': '',
                        'display_name': 'Alice',
                        'note': 'hi im alice',
                        'statuses_count': 0,
                    }
                ],
                'hashtags': [],
                'statuses': [],
            }, resp.json, ignore=[
                'avatar', 'avatar_static', 'bot', 'created_at', 'followers_count',
                'following_count', 'header', 'header_static', 'locked',
                'statuses_count', 'url'])

    def test_search_accounts_not_found(self):
        resp = self.get('/api/v2/search?type=accounts&q=@nope@fa.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'accounts': [],
            'hashtags': [],
            'statuses': []
        }, resp.json)

    def test_search_accounts_web_bare_domain(self):
        self.make_user('user.com', cls=Web, enabled_protocols=['activitypub'])
        resp = self.get('/api/v2/search?type=accounts&q=user.com')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [{
                'acct': 'user.com@web.brid.gy',
                'display_name': 'user.com',
                'id': 'user.com',
                'uri': 'http://localhost/user.com',
                'username': 'user.com',
            }],
            'hashtags': [],
            'statuses': [],
        }, resp.json, ignore=['created_at'])

    def test_search_accounts_web_acct_addr(self):
        self.make_user('user.com', cls=Web, enabled_protocols=['activitypub'])
        resp = self.get('/api/v2/search?type=accounts&q=@user.com@user.com')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [{
                'acct': 'user.com@web.brid.gy',
                'display_name': 'user.com',
                'id': 'user.com',
                'uri': 'http://localhost/user.com',
                'username': 'user.com',
            }],
            'hashtags': [],
            'statuses': [],
        }, resp.json, ignore=['created_at'])

    def test_search_accounts_fediverse(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)

        for q in '@foo@mas.to', 'foo@mas.to':
          with self.subTest(q=q):
            resp = self.get(f'/api/v2/search?type=accounts&q={q}')
            self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
            self.assert_equals({
                'accounts': [{
                    'id': 'https~3A~2F~2Fmas.to~2Fusers~2Ffoo',
                    'acct': 'foo@mas.to',
                    'uri': 'https://mas.to/users/foo',
                    'username': 'foo',
                    'display_name': 'Mrs. ☕ Foo',
                }],
                'hashtags': [],
                'statuses': [],
            }, resp.json, ignore=[
                'avatar', 'avatar_static', 'bot', 'created_at', 'followers_count',
                'following_count', 'header', 'header_static', 'locked', 'note',
                'statuses_count', 'url'])

    @patch.object(util.session, 'get', side_effect=[
        WEBFINGER,
        TestCase.as2_resp(ACTOR),
        WEBFINGER,
        WEBFINGER,
    ])
    def test_search_accounts_fediverse_resolve(self, _):
        resp = self.get('/api/v2/search?type=accounts&resolve=true&q=@foo@mas.to')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [{
                'id': 'https~3A~2F~2Fmas.to~2Fusers~2Ffoo',
                'acct': 'foo@mas.to',
                'uri': 'https://mas.to/users/foo',
                'username': 'foo',
                'display_name': 'Mrs. ☕ Foo',
            }],
            'hashtags': [],
            'statuses': [],
        }, resp.json, ignore=[
            'avatar', 'avatar_static', 'bot', 'created_at', 'followers_count',
            'following_count', 'header', 'header_static', 'locked', 'note',
            'statuses_count', 'url'])

    def test_search_status(self):
        obj = self.store_object(id='fake:post', our_as1={
            'objectType': 'note',
            'actor': 'fake:alice',
            'content': 'foo',
        })

        for q in ('fake~3Apost',
                  'fake%7E3Apost',
                  # Phanpy search format: [domain]/s/[id]
                  'fed.brid.gy/s/fake%3Apost',
                  'fed.brid.gy/s/fake%7E3Apost',
                  ):
            with self.subTest(q=q):
                resp = self.get(f'/api/v2/search?type=statuses&q={q}')
                self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
                self.assert_equals({
                    'accounts': [],
                    'hashtags': [],
                    'statuses': [to_status(obj)],
                }, resp.json, ignore=['created_at'])

    def test_search_status_not_found(self):
        resp = self.get('/api/v2/search?type=statuses&q=fake:post')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'accounts': [],
            'hashtags': [],
            'statuses': []
        }, resp.json)

    def test_search_unsupported_type(self):
        resp = self.get('/api/v2/search?type=statuses&q=hello')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'accounts': [], 'statuses': [], 'hashtags': []}, resp.json)

    def test_domain_blocks_empty(self):
        resp = self.get('/api/v1/domain_blocks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_domain_blocks_with_blocklists(self):
        list1 = Object(id='fake:blocklist1', raw=['foo.com', 'bar.org']).put()
        list2 = Object(id='fake:blocklist2', raw=['baz.net']).put()
        self.user.blocks = [list1, list2]
        self.user.put()

        resp = self.get('/api/v1/domain_blocks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['foo.com', 'bar.org', 'baz.net'], resp.json)

    def test_conversations(self):
        resp = self.get('/api/v1/conversations')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_lists(self):
        resp = self.get('/api/v1/lists')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_lists_get_not_found(self):
        resp = self.get('/api/v1/lists/123')
        self.assertEqual(404, resp.status_code)

    def test_lists_accounts_not_found(self):
        resp = self.get('/api/v1/lists/123/accounts')
        self.assertEqual(404, resp.status_code)

    def test_markers(self):
        resp = self.get('/api/v1/markers')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({}, resp.json)

    def test_notifications_favourite(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my post',
        }).put()
        Object(id='fake:like', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
            'published': '2026-07-20T01:02:03Z',
        }).put()

        resp = self.get('/api/v1/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        notif = resp.json[0]
        self.assertEqual('fake~3Alike', notif['id'])
        self.assertEqual('favourite', notif['type'])
        self.assertEqual('2026-07-20T01:02:03Z', notif['created_at'])
        self.assertEqual('other~3Abob', notif['account']['id'])
        self.assertEqual('my post', notif['status']['content'])

    def test_notifications_reblog(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my post',
        }).put()
        Object(id='fake:share', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'object': 'fake:post',
        }).put()

        resp = self.get('/api/v1/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('reblog', resp.json[0]['type'])
        self.assertEqual('my post', resp.json[0]['status']['content'])

    def test_notifications_follow(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:follow', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'object': 'fake:alice',
        }).put()

        resp = self.get('/api/v1/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('follow', resp.json[0]['type'])
        self.assertEqual(None, resp.json[0]['status'])
        self.assertEqual('other~3Abob',
                         resp.json[0]['account']['id'])

    def test_notifications_mention(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:reply', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'note',
            'content': '@alice hi',
            'inReplyTo': 'fake:post',
        }).put()

        resp = self.get('/api/v1/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('mention', resp.json[0]['type'])
        self.assertEqual('@alice hi', resp.json[0]['status']['content'])

    def test_to_notification_owner_from_actor_no_users(self):
        bob = self.make_user('fake:bob', cls=Fake, enabled_protocols=['activitypub'])
        obj = Object(id='fake:follow', notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'actor': 'fake:bob',
            'object': 'fake:alice',
        })
        obj.put()

        notif = to_notification(obj)
        self.assertEqual('fake~3Abob', notif['account']['id'])

    def test_to_notification_no_owner_no_users(self):
        obj = Object(id='fake:follow', notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'object': 'fake:alice',
        })
        obj.put()
        self.assertIsNone(to_notification(obj))

    def test_notifications(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:follow', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'object': 'fake:alice',
        }).put()

        resp = self.get('/api/v1/notifications/fake:follow')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('follow', resp.json['type'])

    def test_notifications_get_quoted_id(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:follow', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'object': 'fake:alice',
        }).put()

        # clients percent-encode the id the list endpoint returns (fake~3Afollow)
        # before putting it in the URL path, so it arrives double-encoded
        resp = self.get('/api/v1/notifications/fake%7E3Afollow')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('follow', resp.json['type'])

    def test_notifications_not_found(self):
        resp = self.get('/api/v1/notifications/nope')
        self.assertEqual(404, resp.status_code)

    def test_notifications_unread_count(self):
        resp = self.get('/api/v1/notifications/unread_count')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'count': 0}, resp.json)

    def test_endpoints_require_auth(self):
        for path in (
            '/api/v1/preferences',
            '/api/v1/accounts/lookup',
            '/api/v1/accounts/relationships',
            '/api/v1/accounts/fake:alice',
            '/api/v1/accounts/fake:alice/statuses',
            '/api/v1/accounts/fake:alice/followers',
            '/api/v1/accounts/fake:alice/following',
            '/api/v1/accounts/fake:alice/featured_tags',
            '/api/v1/accounts/fake:alice/lists',
            '/api/v1/accounts/fake:alice/endorsements',
            '/api/v1/accounts/familiar_followers',
            '/api/v1/follow_requests',
            '/api/v1/followed_tags',
            '/api/v1/blocks',
            '/api/v1/bookmarks',
            '/api/v1/conversations',
            '/api/v1/domain_blocks',
            '/api/v1/favourites',
            '/api/v1/lists',
            '/api/v1/lists/123',
            '/api/v1/lists/123/accounts',
            '/api/v1/markers',
            '/api/v1/notifications',
            '/api/v1/notifications/123',
            '/api/v1/notifications/unread_count',
            '/api/v1/statuses',
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
