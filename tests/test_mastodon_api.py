"""Unit tests for mastodon_api.py."""
from datetime import datetime
from unittest.mock import patch

from google.cloud.tasks_v2.types import Task
from granary import as2
from oauth_dropins.bluesky import BlueskyAuth
from webutil import util
from webutil.appengine_config import tasks_client
from webutil.testutil import requests_response
from webutil.util import json_dumps

from atproto import ATProto
import common
import mastodon_api, mastodon_oauth
from granary.mastodon import encode_id
from mastodon_api import (
    MAX_DESCENDANT_DEPTH,
    MAX_DESCENDANTS,
    to_account,
    to_notification,
    to_status,
)
from models import Follower, Object, Target
from web import Web

from activitypub import ActivityPub
from memcache import pickle_memcache
from .test_activitypub import ACTOR, NOTE_OBJECT
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

    def make_atproto_user(self, enabled_protocols=['activitypub'], **kwargs):
        """Makes an ATProto user with a :class:`BlueskyAuth` for their own PDS."""
        BlueskyAuth(id='did:plc:user', pds_url='https://some.pds/',
                    user_json=json_dumps({'did': 'did:plc:user', 'handle': 'ha.nd'}),
                    session={'accessJwt': 'towkin', 'refreshJwt': 'reefresh'},
                    ).put()
        self.store_object(id='did:plc:user', raw=DID_DOC)
        return self.make_user('did:plc:user', cls=ATProto,
                              enabled_protocols=enabled_protocols, **kwargs)

    def make_followee(self, id, **kwargs):
        followee = self.make_user(id, cls=OtherFake, obj_as1={
            'objectType': 'person',
            'displayName': id.capitalize(),
        })
        Follower.get_or_create(from_=self.user, to=followee, **kwargs)
        return followee

    def store_post(self, followee, content, **kwargs):
        return self.store_object(
            id=f'other:{content}', users=[followee.key], source_protocol='other',
            our_as1={
                'objectType': 'note',
                'author': followee.key.id(),
                'content': content,
            }, **kwargs)

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

    def test_user_not_bridged_to_activitypub(self):
        user = self.make_user('fake:bob', cls=Fake)
        self.assertFalse(user.is_enabled(ActivityPub))

        resp = self.get('/api/v1/accounts/verify_credentials', user=user)
        self.assertEqual(403, resp.status_code, resp.get_data(as_text=True))

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_accounts_follow_not_bridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake)

        resp = self.post("/api/v1/accounts/fake~3Abob/follow", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json['following'])

        id = 'ui:follow-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'follow',
            'id': id,
            'object': 'fake:bob',
            'actor': 'did:plc:user',
        })

    @patch.object(util.session, 'post')
    def test_accounts_follow_unbridged_activitypub_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        bob = self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })

        resp = self.post(
            '/api/v1/accounts/https~3A~2F~2Fmas.to~2Fusers~2Fbob/follow', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        # the Follow is delivered, and we don't accept it on bob's behalf
        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Follow',
            'id': 'https://bsky.brid.gy/convert/ap/ui:follow-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': 'https://mas.to/users/bob',
        }, ignore=['@context', 'to', 'url'])

        follower = Follower.query().get()
        self.assertEqual(user.key, follower.from_)
        self.assertEqual(bob.key, follower.to)
        self.assertEqual('active', follower.status)

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_accounts_unfollow_unbridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        bob = self.make_user('fake:bob', cls=Fake)
        follow_obj = self.store_object(
            id='ui:follow-atproto-han.dull-2022-01-02T03:04:04+00:00',
            source_protocol='ui', users=[user.key], our_as1={
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'did:plc:user',
                'object': 'fake:bob',
            })
        Follower.get_or_create(from_=user, to=bob, follow=follow_obj.key)

        resp = self.post("/api/v1/accounts/fake~3Abob/unfollow", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['following'])

        id = 'ui:undo-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'id': id,
            'actor': 'did:plc:user',
            'object': {
                'objectType': 'activity',
                'verb': 'follow',
                'id': 'ui:follow-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'actor': 'did:plc:user',
                'object': 'fake:bob',
            },
        })

    @patch.object(util.session, 'post')
    def test_accounts_unfollow_unbridged_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        bob = self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })
        follow_obj = self.store_object(
            id='ui:follow-atproto-han.dull-2022-01-02T03:04:04+00:00',
            source_protocol='ui', users=[user.key], our_as1={
                'objectType': 'activity',
                'verb': 'follow',
                'actor': 'did:plc:user',
                'object': 'https://mas.to/users/bob',
            })
        Follower.get_or_create(from_=user, to=bob, follow=follow_obj.key)

        resp = self.post(
            '/api/v1/accounts/https~3A~2F~2Fmas.to~2Fusers~2Fbob/unfollow', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Undo',
            'id': 'https://bsky.brid.gy/convert/ap/ui:undo-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': {
                'type': 'Follow',
                'id': 'https://bsky.brid.gy/convert/ap/ui:follow-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'actor': 'https://bsky.brid.gy/ap/did:plc:user',
                'object': 'https://mas.to/users/bob',
            },
        }, ignore=['@context', 'to', 'cc', 'url'])

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_accounts_block_not_bridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake)

        resp = self.post("/api/v1/accounts/fake~3Abob/block", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json['blocking'])

        id = 'ui:block-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'block',
            'id': id,
            'object': 'fake:bob',
            'actor': 'did:plc:user',
        })

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_accounts_unblock_unbridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.make_user('fake:bob', cls=Fake)
        self.store_object(id='ui:block-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'activity',
                              'verb': 'block',
                              'actor': 'did:plc:user',
                              'object': 'fake:bob',
                          })

        resp = self.post("/api/v1/accounts/fake~3Abob/unblock", user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['blocking'])

        id = 'ui:undo-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'id': id,
            'actor': 'did:plc:user',
            'object': {
                'objectType': 'activity',
                'verb': 'block',
                'id': 'ui:block-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'actor': 'did:plc:user',
                'object': 'fake:bob',
            },
        })

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
        self.store_object(id='fake:post', our_as1={
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
        # bob isn't in the datastore yet, and we don't load externally outside of
        # search/lookup, so the repost is unrenderable and should be dropped
        self.assertEqual([], resp.json)

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

    def test_accounts_statuses_min_id_returns_newest_first(self):
        for i in range(1, 4):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
                'published': '2022-01-02T03:04:05',
            }).put()

        # the oldest posts newer than it, but returned newest first
        resp = self.get('/api/v1/accounts/fake:alice/statuses?min_id=fake:post1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['post 3', 'post 2'], [s['content'] for s in resp.json])

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

    def test_statuses_single_ui(self):
        Object(id='ui:reply-fake:user-fake:post', users=[self.user.key],
               source_protocol='ui', our_as1={
                   'objectType': 'comment',
                   'author': 'fake:user',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/ui%7E3Areply-fake%7E3Auser-fake%7E3Apost')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        # the author's subdomain, so that it matches their actor id
        self.assertEqual(
            'https://fa.brid.gy/convert/ap/ui:reply-fake:user-fake:post',
            resp.json['uri'])

    def test_statuses_single_ui_activitypub_author(self):
        # the author's protocol is the same as the protocol we're converting to,
        # so we can't use it as the id's protocol; the id would pass through
        # untranslated. it's only the subdomain we take from the author.
        alice = self.make_user(id='https://inst.com/alice', cls=ActivityPub,
                               obj_as1={'id': 'https://inst.com/alice'})
        Object(id='ui:reply-alice-fake:post', users=[alice.key],
               source_protocol='ui', our_as1={
                   'objectType': 'comment',
                   'author': 'https://inst.com/alice',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/ui%7E3Areply-alice-fake%7E3Apost')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assertEqual('https://ap.brid.gy/convert/ap/ui:reply-alice-fake:post',
                         resp.json['uri'])

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_favourite_not_bridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()

        resp = self.post('/api/v1/statuses/fake~3Apost/favourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertTrue(resp.json['favourited'])

        id = 'ui:like-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'id': id,
            'object': 'fake:post',
            'actor': 'did:plc:user',
        })

    @patch.object(util.session, 'post')
    def test_statuses_favourite_unbridged_activitypub_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })
        self.store_object(id='https://mas.to/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'https://mas.to/users/bob',
                          })

        resp = self.post('/api/v1/statuses/https~3A~2F~2Fmas.to~2Fpost/favourite',
                         user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Like',
            'id': 'https://bsky.brid.gy/convert/ap/ui:like-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': 'https://mas.to/post',
            'cc': ['https://mas.to/users/bob'],
        }, ignore=['@context', 'to', 'url'])

    @patch.object(util.session, 'post')
    @patch.object(util.session, 'get', return_value=requests_response({
        **ACTOR,
        'id': 'https://mas.to/users/bob',
        'inbox': 'https://mas.to/users/bob/inbox',
    }, content_type=as2.CONTENT_TYPE))
    def test_statuses_favourite_activitypub_author_not_stored(self, _, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        self.store_object(id='https://mas.to/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'https://mas.to/users/bob',
                          })

        resp = self.post('/api/v1/statuses/https~3A~2F~2Fmas.to~2Fpost/favourite',
                         user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Like',
            'id': 'https://bsky.brid.gy/convert/ap/ui:like-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': 'https://mas.to/post',
            'cc': ['https://mas.to/users/bob'],
        }, ignore=['@context', 'to', 'url'])

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_reblog_not_bridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()

        resp = self.post('/api/v1/statuses/fake~3Apost/reblog', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])
        self.assertTrue(resp.json['reblogged'])

        id = 'ui:share-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'id': id,
            'object': 'fake:post',
            'actor': 'did:plc:user',
        })

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_unfavourite_unbridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.store_object(id='fake:post', users=[self.user.key],
                          source_protocol='fake',
                          our_as1={'objectType': 'note', 'content': 'hello'})
        self.store_object(id='ui:like-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'activity',
                              'verb': 'like',
                              'actor': 'did:plc:user',
                              'object': 'fake:post',
                          })

        resp = self.post('/api/v1/statuses/fake~3Apost/unfavourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(resp.json['favourited'])

        id = 'ui:undo-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'undo',
            'id': id,
            'actor': 'did:plc:user',
            'object': {
                'objectType': 'activity',
                'verb': 'like',
                'id': 'ui:like-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'actor': 'did:plc:user',
                'object': 'fake:post',
            },
        })

    @patch.object(util.session, 'post')
    def test_statuses_unfavourite_unbridged_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })
        self.store_object(id='https://mas.to/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'https://mas.to/users/bob',
                          })
        self.store_object(id='ui:like-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'activity',
                              'verb': 'like',
                              'actor': 'did:plc:user',
                              'object': 'https://mas.to/post',
                          })

        resp = self.post(
            '/api/v1/statuses/https~3A~2F~2Fmas.to~2Fpost/unfavourite', user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Undo',
            'id': 'https://bsky.brid.gy/convert/ap/ui:undo-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': {
                'type': 'Like',
                'id': 'https://bsky.brid.gy/convert/ap/ui:like-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'actor': 'https://bsky.brid.gy/ap/did:plc:user',
                'object': 'https://mas.to/post',
            },
        }, ignore=['@context', 'to', 'cc', 'url'])

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_create_reply_not_bridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.store_object(
            id='fake:post', users=[self.user.key], source_protocol='fake',
            our_as1={'objectType': 'note', 'content': 'orig'})

        resp = self.post('/api/v1/statuses', user=user,
                         data={'status': 'a reply', 'in_reply_to_id': 'fake~3Apost'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('a reply', resp.json['content'])
        self.assertEqual('fake~3Apost', resp.json['in_reply_to_id'])

        id = 'ui:comment-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'comment',
            'id': id,
            'inReplyTo': 'fake:post',
            'content': 'a reply',
            'author': 'did:plc:user',
        })

    @patch.object(util.session, 'post')
    def test_statuses_create_reply_unbridged_activitypub_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })
        self.store_object(id='https://mas.to/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'https://mas.to/users/bob',
                          })

        resp = self.post('/api/v1/statuses', user=user, data={
            'status': 'a reply',
            'in_reply_to_id': 'https~3A~2F~2Fmas.to~2Fpost',
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        id = 'https://bsky.brid.gy/convert/ap/ui:comment-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Create',
            'id': f'{id}#bridgy-fed-create-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'published': '2022-01-02T03:04:05+00:00',
            'cc': ['https://mas.to/users/bob'],
            'object': {
                'type': 'Note',
                'id': id,
                'attributedTo': 'https://bsky.brid.gy/ap/did:plc:user',
                'inReplyTo': 'https://mas.to/post',
                'content': '<p>a reply</p>',
                'cc': ['https://mas.to/users/bob'],
                'tag': [{
                    'type': 'Mention',
                    'href': 'https://mas.to/users/bob',
                }],
            },
        }, ignore=['@context', 'to', 'url', 'contentMap'])

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_update_ui(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.store_object(id='ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'comment',
                              'author': 'did:plc:user',
                              'content': 'a reply',
                              'inReplyTo': 'https://mas.to/post',
                          })

        resp = self.put(
            '/api/v1/statuses/ui~3Acomment-atproto-han.dull-2022-01-02T03~3A04~3A04+00~3A00',
            user=user, data={'status': 'edited'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('edited', resp.json['content'])

        id = 'ui:update-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': 'did:plc:user',
            'object': {
                'objectType': 'comment',
                'id': 'ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
                'author': 'did:plc:user',
                'content': 'edited',
                'inReplyTo': 'https://mas.to/post',
            },
        })

    @patch.object(util.session, 'post')
    def test_statuses_update_ui_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        self.make_user('https://mas.to/users/bob', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/bob',
            'inbox': 'https://mas.to/users/bob/inbox',
        })
        self.store_object(id='https://mas.to/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'https://mas.to/users/bob',
                          })
        self.store_object(id='ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'comment',
                              'author': 'did:plc:user',
                              'content': 'a reply',
                              'inReplyTo': 'https://mas.to/post',
                          })

        resp = self.put(
            '/api/v1/statuses/ui~3Acomment-atproto-han.dull-2022-01-02T03~3A04~3A04+00~3A00',
            user=user, data={'status': 'edited'})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        id = 'https://bsky.brid.gy/convert/ap/ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00'
        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/bob/inbox'],
                                  from_user=user, data={
            'type': 'Update',
            'id': 'https://bsky.brid.gy/convert/ap/ui:update-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': {
                'type': 'Note',
                'id': id,
                'attributedTo': 'https://bsky.brid.gy/ap/did:plc:user',
                'inReplyTo': 'https://mas.to/post',
                'content': '<p>edited</p>',
                'contentMap': {'en': '<p>edited</p>'},
                'cc': ['https://mas.to/users/bob'],
                'tag': [{
                    'type': 'Mention',
                    'href': 'https://mas.to/users/bob',
                }],
            },
        }, ignore=['@context', 'to', 'cc', 'url'])

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

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_statuses_delete_unbridged(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_atproto_user()
        self.store_object(id='ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'comment',
                              'author': 'did:plc:user',
                              'content': 'a reply',
                              'inReplyTo': 'https://mas.to/post',
                          })

        resp = self.delete(
            '/api/v1/statuses/ui~3Acomment-atproto-han.dull-2022-01-02T03~3A04~3A04+00~3A00',
            user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('a reply', resp.json['content'])

        id = 'ui:delete-atproto-han.dull-2022-01-02T03:04:05+00:00'
        self.assert_task(mock_create_task, 'receive', source_protocol='ui',
                         authed_as='did:plc:user', id=id,
                         users=[user.key.urlsafe().decode()], our_as1={
            'objectType': 'activity',
            'verb': 'delete',
            'id': id,
            'object': 'ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
            'actor': 'did:plc:user',
        })

    @patch.object(util.session, 'post')
    def test_statuses_delete_unbridged_delivers(self, mock_post):
        user = self.make_atproto_user(obj_bsky=test_atproto.ACTOR_PROFILE_BSKY)
        eve = self.make_user('https://mas.to/users/eve', cls=ActivityPub, obj_as2={
            **ACTOR,
            'id': 'https://mas.to/users/eve',
            'inbox': 'https://mas.to/users/eve/inbox',
        })
        Follower.get_or_create(to=user, from_=eve)
        self.store_object(id='ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
                          source_protocol='ui', users=[user.key], our_as1={
                              'objectType': 'comment',
                              'author': 'did:plc:user',
                              'content': 'a reply',
                          })

        resp = self.delete(
            '/api/v1/statuses/ui~3Acomment-atproto-han.dull-2022-01-02T03~3A04~3A04+00~3A00',
            user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_ap_deliveries(mock_post, ['https://mas.to/users/eve/inbox'],
                                  from_user=user, data={
            'type': 'Delete',
            'id': 'https://bsky.brid.gy/convert/ap/ui:delete-atproto-han.dull-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/ap/did:plc:user',
            'object': 'https://bsky.brid.gy/convert/ap/ui:comment-atproto-han.dull-2022-01-02T03:04:04+00:00',
        }, ignore=['@context', 'to', 'cc', 'url'])

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

        Object(id='fake:child', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'child',
            'inReplyTo': 'fake:reply',
        }).put()
        Object(id='fake:grandchild', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'grandchild',
            'inReplyTo': 'fake:child',
        }).put()
        # not part of this thread
        Object(id='fake:other', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'other',
            'inReplyTo': 'fake:root',
        }).put()

        resp = self.get('/api/v1/statuses/fake:reply/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json['ancestors']))
        self.assertEqual('root', resp.json['ancestors'][0]['content'])
        self.assertEqual(['child', 'grandchild'],
                         [d['content'] for d in resp.json['descendants']])

    def test_statuses_context_descendants_deleted_and_non_public(self):
        Object(id='fake:root', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'root',
        }).put()
        Object(id='fake:deleted', deleted=True, our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'deleted',
            'inReplyTo': 'fake:root',
        }).put()
        Object(id='fake:private', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'private',
            'inReplyTo': 'fake:root',
            'to': [{'objectType': 'group', 'alias': '@private'}],
        }).put()

        resp = self.get('/api/v1/statuses/fake:root/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json['descendants'])

    def test_statuses_context_descendants_max_depth(self):
        Object(id='fake:0', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': '0',
        }).put()
        for i in range(1, MAX_DESCENDANT_DEPTH + 3):
            Object(id=f'fake:{i}', our_as1={
                'objectType': 'note',
                'author': 'fake:alice',
                'content': str(i),
                'inReplyTo': f'fake:{i - 1}',
            }).put()

        resp = self.get('/api/v1/statuses/fake:0/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([str(i) for i in range(1, MAX_DESCENDANT_DEPTH + 1)],
                         [d['content'] for d in resp.json['descendants']])

    def test_statuses_context_descendants_max_total(self):
        Object(id='fake:root', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'root',
        }).put()
        for i in range(MAX_DESCENDANTS + 5):
            Object(id=f'fake:{i}', our_as1={
                'objectType': 'note',
                'author': 'fake:alice',
                'content': str(i),
                'inReplyTo': 'fake:root',
            }).put()

        resp = self.get('/api/v1/statuses/fake:root/context')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(MAX_DESCENDANTS, len(resp.json['descendants']))

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

    def test_timelines_public_min_id_returns_newest_first(self):
        for i in range(1, 4):
            Object(id=f'fake:post{i}', our_as1={
                'objectType': 'note',
                'author': 'fake:alice',
                'content': f'post {i}',
            }).put()

        # the oldest posts newer than it, but returned newest first
        resp = self.get('/api/v1/timelines/public?min_id=fake:post1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['post 3', 'post 2'], [s['content'] for s in resp.json])

    def test_timelines_public_cached_without_query_params(self):
        Object(id='fake:first', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'first',
        }).put()

        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['first'], [s['content'] for s in resp.json])

        Object(id='fake:second', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'second',
        }).put()

        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['first'], [s['content'] for s in resp.json])

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
        bob = self.make_followee('other:bob')
        eve = self.make_user('other:eve', cls=OtherFake)
        dormant = self.make_followee('other:dave', status='inactive')

        self.store_post(bob, 'in my feed')
        self.store_post(eve, 'not followed')
        self.store_post(dormant, 'not active')

        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['in my feed'], [s['content'] for s in resp.json])

    def test_timelines_home_merges_followees_in_created_order(self):
        for i, id in enumerate(('other:bob', 'other:carol', 'other:dave')):
            followee = self.make_followee(id)
            self.store_post(followee, f'hi from {id}',
                            created=datetime(2024, 1, 1 + i))

        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([
            'hi from other:dave',
            'hi from other:carol',
            'hi from other:bob',
        ], [s['content'] for s in resp.json])

        pickle_memcache.clear()
        resp = self.get('/api/v1/timelines/home?limit=2')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([
            'hi from other:dave',
            'hi from other:carol',
        ], [s['content'] for s in resp.json])

    def test_timelines_home_no_followees(self):
        eve = self.make_user('other:eve', cls=OtherFake)
        self.store_post(eve, 'not followed')

        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_home_cache_is_per_page(self):
        bob = self.make_followee('other:bob')
        self.store_post(bob, 'one', created=datetime(2024, 1, 1))
        self.store_post(bob, 'two', created=datetime(2024, 1, 2))
        self.store_post(bob, 'three', created=datetime(2024, 1, 3))

        resp = self.get('/api/v1/timelines/home?limit=2')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['three', 'two'], [s['content'] for s in resp.json])

        # the cached first page shouldn't be served for a later page
        resp = self.get('/api/v1/timelines/home?limit=2&max_id=other~3Atwo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['one'], [s['content'] for s in resp.json])

    def test_timelines_home_min_id_returns_oldest_after_it(self):
        bob = self.make_followee('other:bob')
        carol = self.make_followee('other:carol')
        anchor = self.store_post(bob, 'anchor', created=datetime(2024, 1, 1))
        self.store_post(bob, 'bob-2', created=datetime(2024, 1, 2))
        self.store_post(bob, 'bob-3', created=datetime(2024, 1, 3))
        self.store_post(carol, 'carol-10', created=datetime(2024, 1, 10))
        self.store_post(carol, 'carol-11', created=datetime(2024, 1, 11))

        # the two oldest posts newer than the anchor, but returned newest first
        resp = self.get(
            f'/api/v1/timelines/home?limit=2&min_id={encode_id(anchor.key.id())}')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['bob-3', 'bob-2'], [s['content'] for s in resp.json])

    def test_timelines_home_max_id(self):
        bob = self.make_followee('other:bob')
        older = self.store_post(bob, 'older', created=datetime(2024, 1, 1))
        newer = self.store_post(bob, 'newer', created=datetime(2024, 1, 2))

        resp = self.get(f'/api/v1/timelines/home?max_id={encode_id(newer.key.id())}')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['older'], [s['content'] for s in resp.json])

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

    def test_to_status_share_target_not_stored(self):
        obj = Object(id='fake:share', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:alice',
            'object': 'fake:not-stored',
        })
        self.assertIsNone(to_status(obj))

    def test_to_status_share_target_owner_unresolvable(self):
        self.store_object(id='fake:post', our_as1={
            'objectType': 'note',
            'content': 'hi',
        })
        obj = Object(id='fake:share', source_protocol='fake', our_as1={
            'objectType': 'activity',
            'verb': 'share',
            'actor': 'fake:alice',
            'object': 'fake:post',
        })
        self.assertIsNone(to_status(obj))

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
        bob = self.make_followee('other:bob')
        self.store_object(id='other:deleted', users=[bob.key], deleted=True, our_as1={
            'objectType': 'note',
            'content': 'deleted',
        })
        self.store_object(id='other:private', users=[bob.key], our_as1={
            'objectType': 'note',
            'content': 'private',
            'to': [{'alias': '@private'}],
        })
        resp = self.get('/api/v1/timelines/home')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_timelines_home_excludes_unsupported_type(self):
        bob = self.make_followee('other:bob')
        self.store_object(id='other:page', users=[bob.key], our_as1={
            'objectType': 'page',
            'content': 'a page',
            'author': 'other:bob',
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

    @patch.object(util.session, 'get', side_effect=[
        TestCase.as2_resp({
            **NOTE_OBJECT,
            'attributedTo': 'https://mas.to/users/foo',
        }),
        TestCase.as2_resp(ACTOR),
        TestCase.as2_resp(ACTOR),
        WEBFINGER,
        WEBFINGER,
    ])
    def test_search_status_fediverse_resolve(self, _):
        resp = self.get('/api/v2/search?type=statuses&resolve=true&q=http://mas.to/note/id')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [],
            'hashtags': [],
            'statuses': [{
                'id': 'http~3A~2F~2Fmas.to~2Fnote~2Fid',
                'uri': 'http://mas.to/note/id',
                'url': 'http://mas.to/note',
                'content': '☕ just a normal post',
                'visibility': 'public',
                'account': {
                    'id': 'https~3A~2F~2Fmas.to~2Fusers~2Ffoo',
                    'acct': 'foo@mas.to',
                    'uri': 'https://mas.to/users/foo',
                    'username': 'foo',
                    'display_name': 'Mrs. ☕ Foo',
                    'url': '',
                },
            }],
        }, resp.json, ignore=[
            'avatar', 'avatar_static', 'bot', 'created_at', 'emojis',
            'favourites_count', 'followers_count', 'following_count', 'header',
            'header_static', 'in_reply_to_account_id', 'in_reply_to_id', 'locked',
            'media_attachments', 'mentions', 'note', 'pinned', 'reblog',
            'reblogs_count', 'replies_count', 'sensitive', 'spoiler_text',
            'statuses_count', 'tags'])

    def test_search_status_fediverse_no_resolve(self):
        resp = self.get('/api/v2/search?type=statuses&q=http://mas.to/note/id')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'accounts': [],
            'hashtags': [],
            'statuses': [],
        }, resp.json)

    @patch.object(util.session, 'get', return_value=requests_response('nope', status=404))
    def test_search_status_fediverse_resolve_fetch_fails(self, _):
        resp = self.get('/api/v2/search?type=statuses&resolve=true&q=http://mas.to/note/id')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'accounts': [],
            'hashtags': [],
            'statuses': [],
        }, resp.json)

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

    def test_notifications_two_favourites_same_post(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        eve = self.make_user('other:eve', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my post',
        }).put()
        for id, user in (('fake:like-bob', bob), ('fake:like-eve', eve)):
            Object(id=id, users=[user.key], notify=[self.user.key], our_as1={
                'objectType': 'activity',
                'verb': 'like',
                'object': 'fake:post',
            }).put()

        resp = self.get('/api/v1/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['other~3Aeve', 'other~3Abob'],
                         [n['account']['id'] for n in resp.json])
        self.assertEqual(['my post', 'my post'],
                         [n['status']['content'] for n in resp.json])

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

    def test_notifications_max_since_min_id(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for i in range(1, 4):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
            }).put()
            Object(id=f'fake:like{i}', users=[bob.key], notify=[self.user.key],
                   created=datetime(2024, 1, i), our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': f'fake:post{i}',
                   }).put()

        resp = self.get('/api/v1/notifications?max_id=fake~3Alike3')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['fake~3Alike2', 'fake~3Alike1'],
                         [n['id'] for n in resp.json])

        resp = self.get('/api/v1/notifications?since_id=fake~3Alike1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['fake~3Alike3', 'fake~3Alike2'],
                         [n['id'] for n in resp.json])

        # the oldest notifications newer than it, but returned newest first
        resp = self.get('/api/v1/notifications?min_id=fake~3Alike1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['fake~3Alike3', 'fake~3Alike2'],
                         [n['id'] for n in resp.json])

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

    def test_grouped_notifications_group_favourites(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        eve = self.make_user('other:eve', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my post',
        }).put()
        Object(id='fake:like-bob', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
            'published': '2026-07-20T01:02:03Z',
        }).put()
        Object(id='fake:like-eve', users=[eve.key], notify=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:post',
            'published': '2026-07-21T01:02:03Z',
        }).put()

        resp = self.get('/api/v2/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([{
            'group_key': 'favourite-fake~3Apost',
            'type': 'favourite',
            'notifications_count': 2,
            'most_recent_notification_id': 'fake~3Alike-eve',
            'page_max_id': 'fake~3Alike-eve',
            'page_min_id': 'fake~3Alike-bob',
            'latest_page_notification_at': '2026-07-21T01:02:03Z',
            'sample_account_ids': ['other~3Aeve', 'other~3Abob'],
            'status_id': 'fake~3Apost',
        }], resp.json['notification_groups'])
        self.assertEqual(['other~3Aeve', 'other~3Abob'],
                         [a['id'] for a in resp.json['accounts']])
        self.assertEqual(['fake~3Apost'], [s['id'] for s in resp.json['statuses']])

    def test_grouped_notifications_group_follows(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        eve = self.make_user('other:eve', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:follow-bob', users=[bob.key], notify=[self.user.key],
               our_as1={
                   'objectType': 'activity',
                   'verb': 'follow',
                   'object': 'fake:alice',
               }).put()
        Object(id='fake:follow-eve', users=[eve.key], notify=[self.user.key],
               our_as1={
                   'objectType': 'activity',
                   'verb': 'follow',
                   'object': 'fake:alice',
               }).put()

        resp = self.get('/api/v2/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        groups = resp.json['notification_groups']
        self.assertEqual(1, len(groups), groups)
        self.assertEqual('follow', groups[0]['group_key'])
        self.assertEqual(2, groups[0]['notifications_count'])
        self.assertIsNone(groups[0]['status_id'])
        self.assertEqual(['other~3Aeve', 'other~3Abob'],
                         groups[0]['sample_account_ids'])
        self.assertEqual([], resp.json['statuses'])

    def test_grouped_notifications_mentions_not_grouped(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:reply-a', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'note',
            'content': '@alice hi',
            'inReplyTo': 'fake:post',
        }).put()
        Object(id='fake:reply-b', users=[bob.key], notify=[self.user.key], our_as1={
            'objectType': 'note',
            'content': '@alice hi again',
            'inReplyTo': 'fake:post',
        }).put()

        resp = self.get('/api/v2/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['ungrouped-fake~3Areply-b', 'ungrouped-fake~3Areply-a'],
                         [g['group_key'] for g in resp.json['notification_groups']])
        self.assertEqual([1, 1], [g['notifications_count']
                                  for g in resp.json['notification_groups']])
        self.assertEqual(['fake~3Areply-b', 'fake~3Areply-a'],
                         [s['id'] for s in resp.json['statuses']])

    def test_grouped_notifications_grouped_types_param(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        eve = self.make_user('other:eve', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for id, user in (('fake:follow-bob', bob), ('fake:follow-eve', eve)):
            Object(id=id, users=[user.key], notify=[self.user.key], our_as1={
                'objectType': 'activity',
                'verb': 'follow',
                'object': 'fake:alice',
            }).put()

        resp = self.get('/api/v2/notifications?grouped_types[]=favourite')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(
            ['ungrouped-fake~3Afollow-eve', 'ungrouped-fake~3Afollow-bob'],
            [g['group_key'] for g in resp.json['notification_groups']])

    def test_grouped_notifications_limit_counts_groups(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for i in range(3):
            Object(id=f'fake:post-{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'my post {i}',
            }).put()
            Object(id=f'fake:like-{i}', users=[bob.key], notify=[self.user.key],
                   our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': f'fake:post-{i}',
                   }).put()

        resp = self.get('/api/v2/notifications?limit=2')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost-2', 'favourite-fake~3Apost-1'],
                         [g['group_key'] for g in resp.json['notification_groups']])
        self.assertEqual(['fake~3Apost-2', 'fake~3Apost-1'],
                         [s['id'] for s in resp.json['statuses']])

    def test_grouped_notifications_max_since_min_id(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for i in range(1, 4):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
            }).put()
            Object(id=f'fake:like{i}', users=[bob.key], notify=[self.user.key],
                   created=datetime(2024, 1, i), our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': f'fake:post{i}',
                   }).put()

        resp = self.get('/api/v2/notifications?max_id=fake~3Alike3')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost2', 'favourite-fake~3Apost1'],
                         [g['group_key'] for g in resp.json['notification_groups']])

        resp = self.get('/api/v2/notifications?since_id=fake~3Alike1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost3', 'favourite-fake~3Apost2'],
                         [g['group_key'] for g in resp.json['notification_groups']])

        resp = self.get('/api/v2/notifications?min_id=fake~3Alike1&limit=1')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost2'],
                         [g['group_key'] for g in resp.json['notification_groups']])

    def test_grouped_notifications_min_id_groups_newest_first(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        eve = self.make_user('other:eve', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Object(id='fake:anchor', users=[bob.key], notify=[self.user.key],
               created=datetime(2024, 1, 1), our_as1={
                   'objectType': 'activity',
                   'verb': 'follow',
                   'object': 'fake:alice',
               }).put()
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'my post',
        }).put()
        for id, user, day in (('fake:like-bob', bob, 2), ('fake:like-eve', eve, 3)):
            Object(id=id, users=[user.key], notify=[self.user.key],
                   created=datetime(2024, 1, day), our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': 'fake:post',
                   }).put()

        # min_id fetches oldest first, but each group is still newest first inside
        resp = self.get('/api/v2/notifications?min_id=fake~3Aanchor')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([{
            'group_key': 'favourite-fake~3Apost',
            'type': 'favourite',
            'notifications_count': 2,
            'most_recent_notification_id': 'fake~3Alike-eve',
            'page_max_id': 'fake~3Alike-eve',
            'page_min_id': 'fake~3Alike-bob',
            'latest_page_notification_at': '2024-01-03T00:00:00+00:00',
            'sample_account_ids': ['other~3Aeve', 'other~3Abob'],
            'status_id': 'fake~3Apost',
        }], resp.json['notification_groups'])

    def test_grouped_notifications_link_header(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for i in range(1, 4):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
            }).put()
            Object(id=f'fake:like{i}', users=[bob.key], notify=[self.user.key],
                   created=datetime(2024, 1, i), our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': f'fake:post{i}',
                   }).put()

        resp = self.get('/api/v2/notifications?limit=2&grouped_types[]=favourite')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost3', 'favourite-fake~3Apost2'],
                         [g['group_key'] for g in resp.json['notification_groups']])

        base = 'http://localhost/api/v2/notifications?limit=2&grouped_types%5B%5D=favourite'
        self.assertEqual(
            f'<{base}&max_id=fake~3Alike2>; rel="next", '
            f'<{base}&min_id=fake~3Alike3>; rel="prev"',
            resp.headers['Link'])

    def test_grouped_notifications_link_header_oldest_in_earlier_group(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        for i in (1, 2):
            Object(id=f'fake:post{i}', users=[self.user.key], our_as1={
                'objectType': 'note',
                'content': f'post {i}',
            }).put()

        # the oldest notification is in the *first* group, not the last one
        for id, post, day in (('fake:like-new', 'fake:post1', 4),
                              ('fake:like-mid', 'fake:post2', 3),
                              ('fake:like-old', 'fake:post1', 1)):
            Object(id=id, users=[bob.key], notify=[self.user.key],
                   created=datetime(2024, 1, day), our_as1={
                       'objectType': 'activity',
                       'verb': 'like',
                       'object': post,
                   }).put()

        resp = self.get('/api/v2/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['favourite-fake~3Apost1', 'favourite-fake~3Apost2'],
                         [g['group_key'] for g in resp.json['notification_groups']])

        base = 'http://localhost/api/v2/notifications'
        self.assertEqual(
            f'<{base}?max_id=fake~3Alike-old>; rel="next", '
            f'<{base}?min_id=fake~3Alike-new>; rel="prev"',
            resp.headers['Link'])

    def test_grouped_notifications_link_header_empty(self):
        resp = self.get('/api/v2/notifications')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json['notification_groups'])
        self.assertNotIn('Link', resp.headers)

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
            '/api/v2/notifications',
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
