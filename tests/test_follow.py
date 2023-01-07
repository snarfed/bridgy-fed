"""Unit tests for follow.py.
"""
from unittest.mock import patch

from flask import get_flashed_messages
from granary import as2
from oauth_dropins import indieauth
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads

import common
from models import Follower, User
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
class AddFollowerTest(testutil.TestCase):

    def test_start(self, mock_get, _):
        resp = self.client.post('/follow/start', data={
            'me': 'https://snarfed.org',
            'address': '@foo@bar',
        })
        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].startswith(indieauth.INDIEAUTH_URL),
                        resp.headers['Location'])

    def test_callback(self, mock_get, mock_post):
        mock_post.side_effect = (
            requests_response('me=https://snarfed.org'),
            requests_response('OK'),  # AP Follow to inbox
        )
        mock_get.side_effect = (
            # oauth-dropins indieauth https://snarfed.org fetch for user json
            requests_response(''),
            WEBFINGER,
            self.as2_resp({
                'type': 'Person',
                'id': 'https://bar/id',
                'inbox': 'http://bar/inbox',
            }),
        )
        User.get_or_create('snarfed.org')

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://snarfed.org',
            'state': '@foo@bar',
        })
        with self.client:
            resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
            self.assertEqual(302, resp.status_code)
            self.assertEqual('/user/snarfed.org/following',resp.headers['Location'])
            self.assertEqual(['Followed @foo@bar.'], get_flashed_messages())

        mock_get.assert_has_calls((
            self.req('https://bar/.well-known/webfinger?resource=acct:foo@bar'),
            self.as2_req('https://bar/actor'),
        ))
        mock_post.assert_has_calls((
            self.req('http://auth/endpoint', data={
                'me': 'https://snarfed.org',
                'state': '@foo@bar',
                'code': 'my_code',
                'client_id': indieauth.INDIEAUTH_CLIENT_ID,
                'redirect_uri': 'http://localhost/follow/callback',
            }),
        ))
        inbox_args, inbox_kwargs = mock_post.call_args_list[-1]
        self.assertEqual(('http://bar/inbox',), inbox_args)
        self.assert_equals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': 'TODO',
            'actor': 'http://localhost/snarfed.org',
            'object': 'https://bar/id',
            'to': [as2.PUBLIC_AUDIENCE],
        }, json_loads(inbox_kwargs['data']))

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual('https://bar/id snarfed.org', followers[0].key.id())

    def test_callback_missing_user(self, mock_get, mock_post):
        mock_post.return_value = requests_response('me=https://snarfed.org')

        state = util.encode_oauth_state({
            'endpoint': 'http://auth/endpoint',
            'me': 'https://snarfed.org',
            'state': '@foo@bar',
        })
        with self.client:
            resp = self.client.get(f'/follow/callback?code=my_code&state={state}')
            self.assertEqual(400, resp.status_code)
