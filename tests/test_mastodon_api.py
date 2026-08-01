"""Unit tests for mastodon_api.py."""
from unittest.mock import patch

from webutil import util
from webutil.testutil import requests_response

import mastodon_api, mastodon_oauth
from mastodon_api import to_account, to_status, to_notification
from models import Follower, Object
from web import Web

from activitypub import ActivityPub
from .test_activitypub import ACTOR
from .testutil import Fake, OtherFake, TestCase

WEBFINGER = requests_response({
    'subject': 'acct:foo@mas.to',
    'links': [{
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'https://mas.to/users/foo',
    }],
}, content_type='application/jrd+json')


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

    def token(self):
        return mastodon_oauth.encode_jwt({
            'typ': mastodon_oauth.TOKEN_TYP,
            'user_key': self.user.key.urlsafe().decode(),
            'client_id_hash': 'test',
            'scope': '',
        })

    def get(self, path, base_url=None, **kwargs):
        auth_header = {'Authorization': f'Bearer {self.token()}'}
        return self.client.get(path, base_url=base_url, headers=auth_header,
                               **kwargs)

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
            'id': 'fake%3Aalice',
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
                self.assertEqual('fake%3Aalice', resp.json['id'])
                self.assertEqual('hi im alice', resp.json['note'])

    def test_accounts_lookup_fediverse(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)

        for acct in 'foo@mas.to', '@foo@mas.to':
            with self.subTest(acct=acct):
                resp = self.get(f'/api/v1/accounts/lookup?acct={acct}')
                self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
                self.assertEqual('https%3A%2F%2Fmas.to%2Fusers%2Ffoo', resp.json['id'])
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
            'id': 'other%3Abob',
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

    def test_accounts_relationships_double_encoded_id(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/relationships?id[]=other%253Abob')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('other%3Abob', resp.json[0]['id'])

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

    def test_follow_requests(self):
        resp = self.get('/api/v1/follow_requests')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts(self):
        resp = self.get('/api/v1/accounts/fake:alice')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('fake%3Aalice', resp.json['id'])
        self.assertEqual('https://fa.brid.gy/ap/fake:alice', resp.json['uri'])

    def test_accounts_double_encoded_id(self):
        resp = self.get('/api/v1/accounts/fake%253Aalice')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('fake%3Aalice', resp.json['id'])

    def test_accounts_activitypub_actor_id(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)
        resp = self.get('/api/v1/accounts/https://mas.to/users/foo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('https%3A%2F%2Fmas.to%2Fusers%2Ffoo', resp.json['id'])
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
        self.assertEqual('other%3Abob', resp.json[0]['id'])

    def test_accounts_following(self):
        bob = self.make_user('other:bob', cls=OtherFake)
        Follower.get_or_create(from_=self.user, to=bob)
        resp = self.get('/api/v1/accounts/fake:alice/following')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('other%3Abob', resp.json[0]['id'])

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

    def test_statuses_multiple_double_encoded_id(self):
        Object(id='fake:post1', our_as1={
            'objectType': 'note',
            'author': 'fake:alice',
            'content': 'one',
        }).put()

        resp = self.get('/api/v1/statuses?id[]=fake%253Apost1')
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
            'id': 'fake%3Apost',
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

    def test_statuses_reblog(self):
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

    def test_statuses_single_double_encoded_id(self):
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/fake%253Apost')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('hello', resp.json['content'])

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
        self.assertEqual('fake%3Abob', status['account']['id'])

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
                        'id': 'fake%3Aalice',
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
                    'id': 'https%3A%2F%2Fmas.to%2Fusers%2Ffoo',
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
                'id': 'https%3A%2F%2Fmas.to%2Fusers%2Ffoo',
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

        for q in ('fake%3Apost',
                  'fake%253Apost',
                  # Phanpy search format: [domain]/s/[id]
                  'fed.brid.gy/s/fake%3Apost',
                  'fed.brid.gy/s/fake%253Apost',
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
        self.assertEqual('fake%3Alike', notif['id'])
        self.assertEqual('favourite', notif['type'])
        self.assertEqual('2026-07-20T01:02:03Z', notif['created_at'])
        self.assertEqual('other%3Abob', notif['account']['id'])
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
        self.assertEqual('other%3Abob',
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
        self.assertEqual('fake%3Abob', notif['account']['id'])

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
