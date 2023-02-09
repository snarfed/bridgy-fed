"""Unit tests for follow.py.
"""
import copy
from unittest.mock import patch

from flask import get_flashed_messages
from granary import as2
from oauth_dropins import indieauth
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from models import Follower, Object, User
from . import testutil

WEBFINGER = requests_response({
    'subject': 'acct:foo@bar',
    'aliases': [
        'https://bar/foo',
    ],
    'links': [{
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'https://bar/follow?uri={uri}'
    }, {
        'rel': 'self',
        'type': as2.CONTENT_TYPE,
        'href': 'https://bar/actor'
    }],
})
FOLLOWEE = {
    'type': 'Person',
    'id': 'https://bar/id',
    'url': 'https://bar/url',
    'inbox': 'http://bar/inbox',
}
FOLLOW_ADDRESS = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Follow',
    'id': f'http://localhost/user/alice.com/following#2022-01-02T03:04:05-@foo@bar',
    'actor': 'http://localhost/alice.com',
    'object': FOLLOWEE,
    'to': [as2.PUBLIC_AUDIENCE],
}
FOLLOW_URL = copy.deepcopy(FOLLOW_ADDRESS)
FOLLOW_URL['id'] = f'http://localhost/user/alice.com/following#2022-01-02T03:04:05-https://bar/actor'
UNDO_FOLLOW = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Undo',
    'id': f'http://localhost/user/alice.com/following#undo-2022-01-02T03:04:05-https://bar/id',
    'actor': 'http://localhost/alice.com',
    'object': FOLLOW_ADDRESS,
}


@patch('requests.get')
class RemoteFollowTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        User.get_or_create('me')

    def test_follow_no_domain(self, mock_get):
        got = self.client.post('/remote-follow?address=@foo@bar')
        self.assertEqual(400, got.status_code)

    def test_follow_no_address(self, mock_get):
        got = self.client.post('/remote-follow?domain=baz.com')
        self.assertEqual(400, got.status_code)

    def test_follow_no_user(self, mock_get):
        got = self.client.post('/remote-follow?address=@foo@bar&domain=baz.com')
        self.assertEqual(400, got.status_code)

    def test_follow(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/remote-follow?address=@foo@bar&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://bar/follow?uri=@me@me',
                         got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=acct:foo@bar'),
        ))

    def test_follow_url(self, mock_get):
        mock_get.return_value = WEBFINGER
        got = self.client.post('/remote-follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('https://bar/follow?uri=@me@me', got.headers['Location'])

        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=https://bar/foo'),
        ))

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response({
            'subject': 'acct:foo@bar',
            'links': [{'rel': 'other', 'template': 'meh'}],
        })

        got = self.client.post('/remote-follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response(status_code=500)

        got = self.client.post('/remote-follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])

    def test_follow_no_webfinger_subscribe_link(self, mock_get):
        mock_get.return_value = requests_response('<html>not json</html>')

        got = self.client.post('/remote-follow?address=https://bar/foo&domain=me')
        self.assertEqual(302, got.status_code)
        self.assertEqual('/user/me', got.headers['Location'])


@patch('requests.post')
@patch('requests.get')
class FollowTest(testutil.TestCase):

    def test_start(self, mock_get, _):
        mock_get.return_value = requests_response('')  # IndieAuth endpoint discovery

        resp = self.client.post('/follow/start', data={
            'me': 'https://alice.com',
            'address': '@foo@bar',
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_callback_address(self, mock_get, mock_post):
        mock_get.side_effect = (
            # oauth-dropins indieauth https://alice.com fetch for user json
            requests_response(''),
            WEBFINGER,
            self.as2_resp(FOLLOWEE),
        )
        self._test_callback('@foo@bar', FOLLOW_ADDRESS, mock_get, mock_post)
        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=acct:foo@bar'),
        ))

    def test_callback_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(FOLLOWEE),
        )
        self._test_callback('https://bar/actor', FOLLOW_URL, mock_get, mock_post)

    def _test_callback(self, input, expected_follow, mock_get, mock_post):
        User.get_or_create('alice.com')

        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': input,
        })
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/user/alice.com/following',resp.headers['Location'])
        self.assertEqual([f'Followed <a href="https://bar/url">{input}</a>.'],
                         get_flashed_messages())

        mock_get.assert_has_calls((
            self.as2_req('https://bar/actor'),
        ))
        self.assertEqual(input, mock_post.call_args_list[0][1]['data']['state'])
        inbox_args, inbox_kwargs = mock_post.call_args_list[1]
        self.assertEqual(('http://bar/inbox',), inbox_args)
        self.assert_equals(expected_follow, json_loads(inbox_kwargs['data']))

        # check that we signed with the follower's key
        sig_template = inbox_kwargs['auth'].header_signer.signature_template
        self.assertTrue(sig_template.startswith('keyId="http://localhost/alice.com"'),
                        sig_template)

        followers = Follower.query().fetch()
        self.assert_entities_equal(
            Follower(id='https://bar/id alice.com',
                     last_follow=json_dumps(expected_follow, sort_keys=True),
                     src='alice.com', dest='https://bar/id', status='active'),
            followers,
            ignore=['created', 'updated'])

        id = f'http://localhost/user/alice.com/following#2022-01-02T03:04:05-{input}'
        self.assert_object(id, domains=['alice.com'], status='complete',
                           labels=['user', 'activity'], source_protocol='ui',
                           as2=expected_follow, as1=as2.to_as1(expected_follow))

    def test_callback_missing_user(self, mock_get, mock_post):
        mock_post.return_value = requests_response('me=https://alice.com')

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': '@foo@bar',
        })
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.assertEqual(400, resp.status_code)

    def test_callback_user_use_instead(self, mock_get, mock_post):
        user = User.get_or_create('www.alice.com')
        User.get_or_create('alice.com', use_instead=user.key)

        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(FOLLOWEE),
        )
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Follow to inbox
        )

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': 'https://bar/actor',
        })
        resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/user/www.alice.com/following', resp.headers['Location'])

        id = 'http://localhost/user/www.alice.com/following#2022-01-02T03:04:05-https://bar/actor'
        expected_follow = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': id,
            'actor': 'http://localhost/www.alice.com',
            'object': FOLLOWEE,
            'to': [as2.PUBLIC_AUDIENCE],
        }
        followers = Follower.query().fetch()
        self.assert_entities_equal(
            Follower(id='https://bar/id www.alice.com',
                     last_follow=json_dumps(expected_follow, sort_keys=True),
                     src='www.alice.com', dest='https://bar/id', status='active'),
            followers,
            ignore=['created', 'updated'])

        self.assert_object(id, domains=['www.alice.com'], status='complete',
                           labels=['user', 'activity'], source_protocol='ui',
                           as2=expected_follow, as1=as2.to_as1(expected_follow))


@patch('requests.post')
@patch('requests.get')
class UnfollowTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.follower = Follower(
            id='https://bar/id alice.com', last_follow=json_dumps(FOLLOW_ADDRESS),
            src='alice.com', dest='https://bar/id', status='active',
        ).put()

    def test_start(self, mock_get, _):
        mock_get.return_value = requests_response('')  # IndieAuth endpoint discovery

        resp = self.client.post('/unfollow/start', data={
            'me': 'https://alice.com',
            'key': self.follower.id(),
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_callback(self, mock_get, mock_post):
        mock_get.return_value = requests_response('')
        self._test_callback(UNDO_FOLLOW, mock_get, mock_post)

    def test_callback_last_follow_object_str(self, mock_get, mock_post):
        follower = self.follower.get()
        follower.last_follow = json_dumps({
            **FOLLOW_ADDRESS,
            'object': FOLLOWEE['id'],
        })
        follower.put()

        # oauth-dropins indieauth https://alice.com fetch for user json
        mock_get.side_effect = (
            requests_response(''),
            self.as2_resp(FOLLOWEE),  # fetch to discover inbox
        )

        undo = copy.deepcopy(UNDO_FOLLOW)
        undo['object']['object'] = FOLLOWEE['id']

        self._test_callback(undo, mock_get, mock_post)

    def _test_callback(self, expected_undo, mock_get, mock_post):
        User.get_or_create('alice.com')
        mock_post.side_effect = (
            requests_response('me=https://alice.com'),
            requests_response('OK'),  # AP Undo Follow to inbox
        )

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://alice.com',
            'state': self.follower.id(),
        })
        resp = self.client.get(f'/unfollow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/user/alice.com/following', resp.headers['Location'])
        self.assertEqual([f'Unfollowed <a href="https://bar/url">bar/url</a>.'],
                         get_flashed_messages())

        inbox_args, inbox_kwargs = mock_post.call_args_list[1]
        self.assertEqual(('http://bar/inbox',), inbox_args)
        self.assert_equals(expected_undo, json_loads(inbox_kwargs['data']))

        # check that we signed with the follower's key
        sig_template = inbox_kwargs['auth'].header_signer.signature_template
        self.assertTrue(sig_template.startswith('keyId="http://localhost/alice.com"'),
                        sig_template)

        follower = Follower.get_by_id('https://bar/id alice.com')
        self.assertEqual('inactive', follower.status)

        self.assert_object(
            'http://localhost/user/alice.com/following#undo-2022-01-02T03:04:05-https://bar/id',
            domains=['alice.com'], status='complete',
            source_protocol='ui', labels=['user', 'activity'],
            as2=expected_undo, as1=as2.to_as1(expected_undo))

    def test_callback_user_use_instead(self, mock_get, mock_post):
        user = User.get_or_create('www.alice.com')
        User.get_or_create('alice.com', use_instead=user.key)

        self.follower = Follower(
            id='https://bar/id www.alice.com', last_follow=json_dumps(FOLLOW_ADDRESS),
            src='www.alice.com', dest='https://bar/id', status='active',
        ).put()

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
            'state': self.follower.id(),
        })
        resp = self.client.get(f'/unfollow/callback?code=my_code&state={state}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/user/www.alice.com/following', resp.headers['Location'])

        id = 'http://localhost/user/www.alice.com/following#undo-2022-01-02T03:04:05-https://bar/id'
        expected_undo = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Undo',
            'id': id,
            'actor': 'http://localhost/www.alice.com',
            'object': FOLLOW_ADDRESS,
        }

        inbox_args, inbox_kwargs = mock_post.call_args_list[1]
        self.assertEqual(('http://bar/inbox',), inbox_args)
        self.assert_equals(expected_undo, json_loads(inbox_kwargs['data']))

        follower = Follower.get_by_id('https://bar/id www.alice.com')
        self.assertEqual('inactive', follower.status)

        self.assert_object(id, domains=['www.alice.com'], status='complete',
                           source_protocol='ui', labels=['user', 'activity'],
                           as2=expected_undo, as1=as2.to_as1(expected_undo))
