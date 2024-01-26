"""Unit tests for follow.py.
"""
import copy
from unittest.mock import patch

from flask import get_flashed_messages, session
from granary import as2
from oauth_dropins import indieauth
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from activitypub import ActivityPub
from common import unwrap
from models import Follower, Object
from web import Web

WEBFINGER = requests_response({
    'subject': 'acct:foo@ba.r',
    'aliases': [
        'https://ba.r/foo',
    ],
    'links': [{
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'https://ba.r/follow?uri={uri}'
    }, {
        'rel': 'self',
        'type': as2.CONTENT_TYPE,
        'href': 'https://ba.r/actor'
    }],
})
FOLLOWEE = {
    'type': 'Person',
    'id': 'https://ba.r/id',
    'url': 'https://ba.r/url',
    'inbox': 'http://ba.r/inbox',
    'outbox': 'http://ba.r/outbox',
}
FOLLOW_ADDRESS = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Follow',
    'id': f'http://localhost/r/alice.com/following#2022-01-02T03:04:05-@foo@ba.r',
    'actor': 'http://localhost/alice.com',
    'object': FOLLOWEE['id'],
    'to': [as2.PUBLIC_AUDIENCE],
}
FOLLOW_URL = copy.deepcopy(FOLLOW_ADDRESS)
FOLLOW_URL['id'] = f'http://localhost/r/alice.com/following#2022-01-02T03:04:05-https://ba.r/actor'
UNDO_FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Undo',
    'id': f'http://localhost/r/alice.com/following#undo-2022-01-02T03:04:05-https://ba.r/id',
    'actor': 'http://localhost/alice.com',
    'object': copy.deepcopy(FOLLOW_ADDRESS),
}
del UNDO_FOLLOW['object']['id']


@patch('requests.get')
class RemoteFollowTest(TestCase):

    def setUp(self):
        super().setUp()
        self.make_user('user.com', cls=Web, has_redirects=True)

    def test_no_domain(self, _):
        got = self.client.post('/remote-follow?address=@foo@ba.r&protocol=web')
        self.assertEqual(400, got.status_code)

    def test_no_address(self, _):
        got = self.client.post('/remote-follow?domain=baz.com&protocol=web')
        self.assertEqual(400, got.status_code)

    def test_no_protocol(self, _):
        got = self.client.post('/remote-follow?address=@foo@ba.r&domain=user.com')
        self.assertEqual(400, got.status_code)

    def test_unknown_protocol(self, _):
        got = self.client.post('/remote-follow?address=@foo@ba.r&domain=user.com&protocol=foo')
        self.assertEqual(400, got.status_code)

    def test_no_user(self, _):
        got = self.client.post('/remote-follow?address=@foo@ba.r&domain=baz.com')
        self.assertEqual(400, got.status_code)

    def test_addr(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/remote-follow?address=@foo@ba.r&domain=user.com&protocol=web')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://ba.r/follow?uri=@user.com@user.com',
                         got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://ba.r/.well-known/webfinger?resource=acct:foo@ba.r'),
        ))

    def test_url(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/remote-follow?address=https://ba.r/foo&domain=user.com&protocol=web')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://ba.r/follow?uri=@user.com@user.com', got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://ba.r/.well-known/webfinger?resource=https://ba.r/foo'),
        ))

    def test_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response({
            'subject': 'acct:foo@ba.r',
            'links': [{'rel': 'other', 'template': 'meh'}],
        })

        got = self.client.post('/remote-follow?address=https://ba.r/foo&domain=user.com&protocol=web')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/web/user.com', got.headers['Location'])

    def test_webfinger_error(self, mock_get):
        mock_get.return_value = requests_response(status=500)

        got = self.client.post('/remote-follow?address=https://ba.r/foo&domain=user.com&protocol=web')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/web/user.com', got.headers['Location'])

    def test_webfinger_returns_not_json(self, mock_get):
        mock_get.return_value = requests_response('<html>not json</html>')

        got = self.client.post('/remote-follow?address=https://ba.r/foo&domain=user.com&protocol=web')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/web/user.com', got.headers['Location'])


@patch('requests.post')
@patch('requests.get')
class FollowTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web, obj_id='https://alice.com/')
        self.state = {
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': '@foo@ba.r',
        }

    def test_start(self, mock_get, _):
        mock_get.return_value = requests_response('')  # IndieAuth endpoint discovery

        resp = self.client.post('/follow/start', data={
            'me': 'https://alice.com',
            'address': '@foo@ba.r',
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_callback_address(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(''),  # indieauth https://alice.com fetch for user json
            WEBFINGER,
            self.as2_resp(FOLLOWEE),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.check('@foo@ba.r', resp, FOLLOW_ADDRESS, mock_get, mock_post)
        mock_get.assert_has_calls((
            self.req('https://ba.r/.well-known/webfinger?resource=acct:foo@ba.r'),
        ))

    def test_callback_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(''),  # indieauth https://alice.com fetch for user json
            self.as2_resp(FOLLOWEE),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/actor'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.check('https://ba.r/actor', resp, FOLLOW_URL, mock_get, mock_post)

    def test_callback_stored_followee_with_our_as1(self, mock_get, mock_post):
        self.store_object(id='https://ba.r/id', our_as1=as2.to_as1(FOLLOWEE),
                          source_protocol='activitypub')

        mock_get.side_effect = (
            requests_response(''),  # indieauth https://alice.com fetch for user json
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/id'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        follow_with_profile_link = {
            **FOLLOW_URL,
            'id': f'http://localhost/r/alice.com/following#2022-01-02T03:04:05-https://ba.r/id',
            'object': 'https://ba.r/id',
        }
        self.check('https://ba.r/id', resp, follow_with_profile_link, mock_get,
                   mock_post, fetched_followee=False)

    def test_callback_user_with_custom_username(self, mock_get, mock_post):
        self.user.obj.clear()
        self.user.obj.as2 = {
            'type': 'Person',
            'url': ['acct:eve@alice.com'],
        }
        self.user.obj.put()

        mock_get.side_effect = (
            requests_response(''),  # indieauth https://alice.com fetch for user json
            self.as2_resp(FOLLOWEE),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/actor'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        self.check('https://ba.r/actor', resp, FOLLOW_URL, mock_get, mock_post,
                   expected_follow_as1={
            **as2.to_as1(unwrap(FOLLOW_URL)),
            'actor': {
                'objectType': 'person',
                'id': 'https://alice.com/',
                'url': 'acct:eve@alice.com',
            },
        })

    def test_callback_composite_url_field(self, mock_get, mock_post):
        """https://console.cloud.google.com/errors/detail/CKmLytj-nPv9RQ;time=P30D?project=bridgy-federated"""
        followee = {
            **FOLLOWEE,
            # this turns into a composite value for url in AS1:
            # {'displayName': 'foo bar', 'value': 'https://ba.r/url'}
            'attachment': [{
                'type': 'PropertyValue',
                'name': 'foo bar',
                'value': '<a href="https://ba.r/url">@ba.r</a>'
            }],
        }
        mock_get.side_effect = (
            requests_response(''),  # indieauth https://alice.com fetch for user json
            self.as2_resp(followee),
            self.as2_resp(followee),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/actor'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        self.check('https://ba.r/actor', resp, FOLLOW_URL, mock_get, mock_post)

    def test_callback_bridged_account_error(self, mock_get, mock_post):
        mock_post.return_value = requests_response('me=https://alice.com')
        mock_get.side_effect = [
            requests_response(''),  # indieauth https://alice.com fetch for user json
            requests_response({     # webfinger
                'subject': 'acct:bob.com@web.brid.gy',
                'aliases': ['https://bob.com/'],
                'links': [{
                    'rel': 'self',
                    'type': as2.CONTENT_TYPE,
                    'href': 'https://web.brid.gy/bob.com',
                }],
            }),
        ]

        self.state['state'] = '@bob.com@web.brid.gy'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following', resp.headers['Location'])
        self.assertEqual(
            ["@bob.com@web.brid.gy is a bridged account. Try following them on the web!"],
            get_flashed_messages())

    def test_callback_upgraded_bridged_account_error(self, mock_get, mock_post):
        mock_post.return_value = requests_response('me=https://alice.com')
        mock_get.side_effect = [
            requests_response(''),  # indieauth https://alice.com fetch for user json
            requests_response({     # webfinger
                'subject': 'acct:bob.com@bob.com',
                'aliases': ['https://bob.com/'],
                'links': [{
                    'rel': 'self',
                    'type': as2.CONTENT_TYPE,
                    'href': 'https://web.brid.gy/bob.com',
                }],
            }),
        ]

        bob = self.make_user('bob.com', cls=Web, obj_id='https://bob.com/')

        self.state['state'] = '@bob.com@bob.com'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following', resp.headers['Location'])
        self.assertEqual(
            ["@bob.com@bob.com is a bridged account. Try following them on the web!"],
            get_flashed_messages())

    def check(self, input, resp, expected_follow, mock_get, mock_post,
              fetched_followee=True, expected_follow_as1=None):
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following', resp.headers['Location'])
        self.assertEqual([f'Followed <a href="https://ba.r/url">{input}</a>.'],
                         get_flashed_messages())

        if fetched_followee:
            mock_get.assert_has_calls((
                self.as2_req('https://ba.r/actor'),
            ))

        inbox_args, inbox_kwargs = mock_post.call_args
        self.assertEqual(('http://ba.r/inbox',), inbox_args)
        self.assert_equals(expected_follow, json_loads(inbox_kwargs['data']))

        # check that we signed with the follower's key
        sig_template = inbox_kwargs['auth'].header_signer.signature_template
        self.assertTrue(
            sig_template.startswith('keyId="http://localhost/alice.com#key"'),
            sig_template)

        follow_id = f'http://localhost/web/alice.com/following#2022-01-02T03:04:05-{input}'

        followers = Follower.query().fetch()
        followee = ActivityPub(id='https://ba.r/id').key
        self.assert_entities_equal(
            Follower(from_=self.user.key, to=followee,
                     follow=Object(id=follow_id).key, status='active'),
            followers,
            ignore=['created', 'updated'])

        if not expected_follow_as1:
            expected_follow_as1 = as2.to_as1(unwrap(expected_follow))
        del expected_follow_as1['to']
        self.assert_object(follow_id,
                           users=[self.user.key],
                           notify=[followee],
                           labels=['user', 'activity'],
                           status='complete',
                           source_protocol='ui',
                           our_as1=expected_follow_as1,
                           delivered=['http://ba.r/inbox'],
                           delivered_protocol='activitypub')

        self.assertEqual('https://alice.com', session['indieauthed-me'])

    def test_callback_missing_user(self, mock_get, mock_post):
        self.user.key.delete()
        mock_post.return_value = requests_response('me=https://alice.com')
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.assertEqual(400, resp.status_code)

    def test_callback_user_use_instead(self, mock_get, mock_post):
        user = self.make_user('www.alice.com', cls=Web,
                              obj_id='https://www.alice.com/')
        self.user.use_instead = user.key
        self.user.put()

        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(FOLLOWEE),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/actor'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/www.alice.com/following', resp.headers['Location'])

        id = 'www.alice.com/following#2022-01-02T03:04:05-https://ba.r/actor'
        expected_follow_as1 = as2.to_as1({
            **FOLLOW_URL,
            'id': id,
            'actor': 'https://www.alice.com/',
        })
        del expected_follow_as1['to']
        followee = ActivityPub(id='https://ba.r/id').key
        follow_obj = self.assert_object(
            f'http://localhost/web/{id}',
            users=[user.key],
            notify=[followee],
            status='complete',
            labels=['user', 'activity'],
            source_protocol='ui',
            our_as1=expected_follow_as1,
            delivered=['http://ba.r/inbox'],
            delivered_protocol='activitypub')

        followers = Follower.query().fetch()
        self.assert_entities_equal(
            Follower(from_=user.key, to=followee, follow=follow_obj.key, status='active'),
            followers,
            ignore=['created', 'updated'])

    def test_callback_url_composite_url(self, mock_get, mock_post):
        followee = {
            **FOLLOWEE,
            'attachments': [{
                'type': 'PropertyValue',
                'name': 'Link',
                'value': '<a href="https://ba.r/actor"></a>',
            }],
        }
        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(followee),
            self.as2_resp(followee),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        self.state['state'] = 'https://ba.r/actor'
        state = util.encode_oauth_state(self.state)
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')

        self.check('https://ba.r/actor', resp, FOLLOW_URL, mock_get, mock_post)
        self.assertEqual(
            [f'Followed <a href="https://ba.r/url">https://ba.r/actor</a>.'],
            get_flashed_messages())

    def test_indieauthed_session(self, mock_get, mock_post):
        mock_get.side_effect = (
            self.as2_resp(FOLLOWEE),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('OK'),  # AP Follow to inbox
        )

        with self.client.session_transaction() as ctx_session:
            ctx_session['indieauthed-me'] = 'https://alice.com'

        resp = self.client.post('/follow/start', data={
            'me': 'https://alice.com',
            'address': 'https://ba.r/actor',
        })
        self.check('https://ba.r/actor', resp, FOLLOW_URL, mock_get, mock_post)

    def test_indieauthed_session_wrong_me(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(''),  # IndieAuth endpoint discovery
        )

        with self.client.session_transaction() as ctx_session:
            ctx_session['indieauthed-me'] = 'https://eve.com'

        resp = self.client.post('/follow/start', data={
            'me': 'https://alice.com',
            'address': 'https://ba.r/actor',
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_start_homepage_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = requests.ConnectionError('foo')

        resp = self.client.post('/follow/start', data={
            'me': 'https://alice.com',
            'address': 'https://ba.r/actor',
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following?address=https://ba.r/actor',
                         resp.headers['Location'])
        self.assertEqual(["Couldn't fetch your web site: foo"],
                         get_flashed_messages())


@patch('requests.post')
@patch('requests.get')
class UnfollowTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user('alice.com', cls=Web)
        self.follower = Follower.get_or_create(
            from_=self.user,
            to=self.make_user('https://ba.r/id', cls=ActivityPub, obj_as2=FOLLOWEE),
            follow=Object(id=FOLLOW_ADDRESS['id'], as2=FOLLOW_ADDRESS).put(),
            status='active',
        )

        self.state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': self.follower.key.id(),
        })

    def test_start(self, mock_get, _):
        mock_get.return_value = requests_response('')  # IndieAuth endpoint discovery

        resp = self.client.post('/unfollow/start', data={
            'me': 'https://alice.com',
            'key': self.follower.key.id(),
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_callback(self, mock_get, mock_post):
        # oauth-dropins indieauth https://alice.com fetch for user json
        mock_get.return_value = requests_response('')
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        resp = self.client.get(f'/unfollow/callback?code=my_code&state={self.state}')
        self.check(resp, UNDO_FOLLOW, mock_get, mock_post)

    def test_callback_last_follow_object_str(self, mock_get, mock_post):
        to = self.follower.to.get()
        to.obj = None
        to.put()

        obj = self.follower.follow.get()
        obj.as2['object'] = FOLLOWEE['id']
        obj.put()

        mock_get.side_effect = (
            # oauth-dropins indieauth https://alice.com fetch for user json
            requests_response(''),
            # actor fetch to discover inbox
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        undo = copy.deepcopy(UNDO_FOLLOW)
        undo['object']['object'] = FOLLOWEE['id']

        resp = self.client.get(f'/unfollow/callback?code=my_code&state={self.state}')
        self.check(resp, undo, mock_get, mock_post)

    def check(self, resp, expected_undo, mock_get, mock_post):
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following', resp.headers['Location'])
        self.assertEqual([f'Unfollowed <a href="https://ba.r/url">ba.r/url</a>.'],
                         get_flashed_messages())

        inbox_args, inbox_kwargs = mock_post.call_args
        self.assertEqual(('http://ba.r/inbox',), inbox_args)
        self.assert_equals({
            **expected_undo,
            'to': [as2.PUBLIC_AUDIENCE],
        }, json_loads(inbox_kwargs['data']))

        # check that we signed with the follower's key
        sig_template = inbox_kwargs['auth'].header_signer.signature_template
        self.assertTrue(
            sig_template.startswith('keyId="http://localhost/alice.com#key"'),
            sig_template)

        follower = Follower.query().get()
        self.assertEqual('inactive', follower.status)

        self.assert_object(
            'http://localhost/web/alice.com/following#undo-2022-01-02T03:04:05-https://ba.r/id',
            users=[self.user.key],
            notify=[ActivityPub(id='https://ba.r/id').key],
            status='complete',
            source_protocol='ui',
            labels=['user', 'activity'],
            our_as1=unwrap(as2.to_as1(expected_undo)),
            delivered=['http://ba.r/inbox'],
            delivered_protocol='activitypub')

        self.assertEqual('https://alice.com', session['indieauthed-me'])

    def test_callback_user_use_instead(self, mock_get, mock_post):
        user = self.make_user('www.alice.com', cls=Web)
        self.user.use_instead = user.key
        self.user.put()

        Follower.get_or_create(
            from_=self.user,
            to=self.make_user('https://ba.r/id', cls=ActivityPub, obj_as2=FOLLOWEE),
            follow=Object(id=FOLLOW_ADDRESS['id'], as2=FOLLOW_ADDRESS).put(),
            status='active')

        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': self.follower.key.id(),
        })
        resp = self.client.get(f'/unfollow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/www.alice.com/following', resp.headers['Location'])

        id = 'http://localhost/r/www.alice.com/following#undo-2022-01-02T03:04:05-https://ba.r/id'
        expected_undo = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Undo',
            'id': id,
            'actor': 'http://localhost/www.alice.com',
            'object': {
                **FOLLOW_ADDRESS,
                'actor': 'http://localhost/www.alice.com',
            },
        }
        del expected_undo['object']['id']

        inbox_args, inbox_kwargs = mock_post.call_args_list[1]
        self.assertEqual(('http://ba.r/inbox',), inbox_args)
        self.assert_equals({
            **expected_undo,
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        }, json_loads(inbox_kwargs['data']))

        follower = Follower.query().get()
        self.assertEqual('inactive', follower.status)

        self.assert_object(
            'http://localhost/web/www.alice.com/following#undo-2022-01-02T03:04:05-https://ba.r/id',
            users=[user.key],
            notify=[ActivityPub(id='https://ba.r/id').key],
            status='complete',
            source_protocol='ui',
            labels=['user', 'activity'],
            our_as1=unwrap(as2.to_as1(expected_undo)),
            delivered=['http://ba.r/inbox'],
            delivered_protocol='activitypub')

    def test_callback_composite_url(self, mock_get, mock_post):
        follower = self.follower.to.get().obj
        follower.our_as1 = {
            **as2.to_as1(FOLLOWEE),
            'url': {
                'value': 'https://ba.r/url',
                'displayName': 'something',
            },
        }
        follower.put()

        # oauth-dropins indieauth https://alice.com fetch for user json
        mock_get.return_value = requests_response('')
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        resp = self.client.get(f'/unfollow/callback?code=my_code&state={self.state}')
        self.assertEqual([f'Unfollowed <a href="https://ba.r/url">ba.r/url</a>.'],
                         get_flashed_messages())
        self.check(resp, UNDO_FOLLOW, mock_get, mock_post)

    def test_indieauthed_session(self, mock_get, mock_post):
        # oauth-dropins indieauth https://alice.com fetch for user json
        mock_get.return_value = requests_response('')
        mock_post.side_effect = (
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        with self.client.session_transaction() as ctx_session:
            ctx_session['indieauthed-me'] = 'https://alice.com'

        resp = self.client.post('/unfollow/start', data={
            'me': 'https://alice.com',
            'key': self.follower.key.id(),
        })
        self.check(resp, UNDO_FOLLOW, mock_get, mock_post)

    def test_indieauthed_session_wrong_me(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(''),  # IndieAuth endpoint discovery
        )

        with self.client.session_transaction() as ctx_session:
            ctx_session['indieauthed-me'] = 'https://eve.com'

        resp = self.client.post('/unfollow/start', data={
            'me': 'https://alice.com',
            'key': self.follower.key.id(),
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_start_homepage_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = requests.ConnectionError('foo')

        resp = self.client.post('/unfollow/start', data={
            'me': 'https://alice.com',
            'key': self.follower.key.id(),
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/web/alice.com/following', resp.headers['Location'])
        self.assertEqual(["Couldn't fetch your web site: foo"],
                         get_flashed_messages())
