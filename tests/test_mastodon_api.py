"""Unit tests for mastodon_api.py."""
from unittest.mock import patch

from webutil import util
from webutil.testutil import requests_response

import mastodon_api, mastodon_oauth
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
            'id': '@fake-handle-alice@fa.brid.gy',
            'acct': '@fake-handle-alice@fa.brid.gy',
            'uri': 'https://fa.brid.gy/ap/fake:alice',
            'url': '',
            'created_at': '2026-07-20T01:02:03Z',
            'display_name': 'Alice',
            'username': 'fake:handle:alice',
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

    def test_accounts_lookup(self):
        resp = self.get('/api/v1/accounts/lookup?acct=fake-handle-alice@fa.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('@fake-handle-alice@fa.brid.gy', resp.json['id'])
        self.assertEqual('hi im alice', resp.json['note'])

    def test_accounts_lookup_not_found(self):
        resp = self.get('/api/v1/accounts/lookup?acct=nope@fa.brid.gy')
        self.assertEqual(404, resp.status_code)

    def test_accounts_relationships(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        resp = self.get('/api/v1/accounts/relationships?id[]=@other-handle-bob@other.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([{
            'id': '@other-handle-bob@other.brid.gy',
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

    def test_accounts_relationships_unknown_id(self):
        resp = self.get('/api/v1/accounts/relationships?id[]=@nope@fake.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_accounts_relationships_following(self):
        bob = self.make_user('other:bob', cls=OtherFake,
                             enabled_protocols=['activitypub'])
        Follower.get_or_create(from_=self.user, to=bob)
        resp = self.get('/api/v1/accounts/relationships?id[]=@other-handle-bob@other.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertTrue(resp.json[0]['following'])
        self.assertFalse(resp.json[0]['followed_by'])

    def test_accounts(self):
        resp = self.get('/api/v1/accounts/@fake-handle-alice@fa.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('@fake-handle-alice@fa.brid.gy', resp.json['id'])
        self.assertEqual('https://fa.brid.gy/ap/fake:alice', resp.json['uri'])

    def test_accounts_not_found(self):
        resp = self.get('/api/v1/accounts/nope:nope')
        self.assertEqual(404, resp.status_code)

    def test_accounts_statuses(self):
        Object(id='fake:post', users=[self.user.key], our_as1={
            'objectType': 'note',
            'content': 'hello world',
            'published': '2022-01-02T03:04:05',
        }).put()
        resp = self.get('/api/v1/accounts/@fake-handle-alice@fa.brid.gy/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

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
        resp = self.get('/api/v1/accounts/@fake-handle-alice@fa.brid.gy/statuses')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('hello world', resp.json[0]['content'])

    def test_accounts_followers(self):
        bob = self.make_user('other:bob', cls=OtherFake)
        Follower.get_or_create(from_=bob, to=self.user)
        resp = self.get('/api/v1/accounts/@fake-handle-alice@fa.brid.gy/followers')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('@other-handle-bob@other.brid.gy', resp.json[0]['id'])

    def test_accounts_following(self):
        bob = self.make_user('other:bob', cls=OtherFake)
        Follower.get_or_create(from_=self.user, to=bob)
        resp = self.get('/api/v1/accounts/@fake-handle-alice@fa.brid.gy/following')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('@other-handle-bob@other.brid.gy', resp.json[0]['id'])

    def test_blocks(self):
        resp = self.get('/api/v1/blocks')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_favourites(self):
        Object(id='fake:liked', our_as1={
            'objectType': 'note',
            'content': 'liked post',
        }).put()
        Object(id='fake:like', users=[self.user.key], our_as1={
            'objectType': 'activity',
            'verb': 'like',
            'object': 'fake:liked',
        }).put()

        resp = self.get('/api/v1/favourites')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('liked post', resp.json[0]['content'])

    def test_statuses_multiple(self):
        Object(id='fake:post1', our_as1={
            'objectType': 'note',
            'content': 'one',
        }).put()
        Object(id='fake:post2', our_as1={
            'objectType': 'note',
            'content': 'two',
        }).put()
        Object(id='fake:deleted', deleted=True, our_as1={
            'objectType': 'note',
            'content': 'deleted',
        }).put()

        resp = self.get('/api/v1/statuses?id[]=fake:post1&id[]=fake:post2&id[]=fake:deleted&id[]=fake:nope')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(['one', 'two'], [s['content'] for s in resp.json])

    def test_statuses_single(self):
        Object(id='fake:post', users=[self.user.key], source_protocol='fake',
               our_as1={
                   'objectType': 'note',
                   'content': 'hello',
               }).put()
        resp = self.get('/api/v1/statuses/fake:post')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_equals({
            'id': 'fake:post',
            'uri': 'https://fa.brid.gy/convert/ap/fake:post',
            'url': '',
            'account': mastodon_api.account(self.user),
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

    def test_statuses_single_not_found(self):
        resp = self.get('/api/v1/statuses/nope')
        self.assertEqual(404, resp.status_code)

    def test_statuses_context(self):
        Object(id='fake:root', our_as1={
            'objectType': 'note',
            'content': 'root',
        }).put()
        Object(id='fake:reply', our_as1={
            'objectType': 'note',
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
            'content': 'not in my feed',
        }).put()
        resp = self.get('/api/v1/timelines/public')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json))
        self.assertEqual('not in my feed', resp.json[0]['content'])

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

    def test_timelines_tag(self):
        resp = self.get('/api/v1/timelines/tag/foo')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json)

    def test_search_accounts(self):
        resp = self.get('/api/v2/search?type=accounts&q=@fake-handle-alice@fa.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(1, len(resp.json['accounts']))
        self.assertEqual('@fake-handle-alice@fa.brid.gy',
                         resp.json['accounts'][0]['id'])
        self.assertEqual([], resp.json['statuses'])
        self.assertEqual([], resp.json['hashtags'])

    def test_search_accounts_not_found(self):
        resp = self.get('/api/v2/search?type=accounts&q=@nope@fa.brid.gy')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual([], resp.json['accounts'])

    def test_search_accounts_web_bare_domain(self):
        self.make_user('user.com', cls=Web, enabled_protocols=['activitypub'])
        resp = self.get('/api/v2/search?type=accounts&q=user.com')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [{
                'acct': '@user.com@web.brid.gy',
                'display_name': 'user.com',
                'id': '@user.com@web.brid.gy',
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
                'acct': '@user.com@web.brid.gy',
                'display_name': 'user.com',
                'id': '@user.com@web.brid.gy',
                'uri': 'http://localhost/user.com',
                'username': 'user.com',
            }],
            'hashtags': [],
            'statuses': [],
        }, resp.json, ignore=['created_at'])

    def test_search_accounts_fediverse(self):
        self.make_user('https://mas.to/users/foo', cls=ActivityPub,
                       enabled_protocols=[], obj_as2=ACTOR)
        resp = self.get('/api/v2/search?type=accounts&q=@foo@mas.to')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assert_equals({
            'accounts': [{
                'id': '@foo@mas.to',
                'acct': '@foo@mas.to',
                'uri': 'https://mas.to/users/foo',
                'username': '@foo@mas.to',
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
                'id': '@foo@mas.to',
                'acct': '@foo@mas.to',
                'uri': 'https://mas.to/users/foo',
                'username': '@foo@mas.to',
                'display_name': 'Mrs. ☕ Foo',
            }],
            'hashtags': [],
            'statuses': [],
        }, resp.json, ignore=[
            'avatar', 'avatar_static', 'bot', 'created_at', 'followers_count',
            'following_count', 'header', 'header_static', 'locked', 'note',
            'statuses_count', 'url'])

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
        self.assertEqual('fake:like', notif['id'])
        self.assertEqual('favourite', notif['type'])
        self.assertEqual('2026-07-20T01:02:03Z', notif['created_at'])
        self.assertEqual('@other-handle-bob@other.brid.gy', notif['account']['id'])
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
        self.assertNotIn('status', resp.json[0])
        self.assertEqual('@other-handle-bob@other.brid.gy',
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

    def test_stub_endpoints_require_auth(self):
        for path in (
            '/api/v1/accounts/lookup',
            '/api/v1/accounts/relationships',
            '/api/v1/accounts/@fake-handle-alice@fa.brid.gy',
            '/api/v1/accounts/@fake-handle-alice@fa.brid.gy/statuses',
            '/api/v1/accounts/@fake-handle-alice@fa.brid.gy/followers',
            '/api/v1/accounts/@fake-handle-alice@fa.brid.gy/following',
            '/api/v1/blocks',
            '/api/v1/domain_blocks',
            '/api/v1/favourites',
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
