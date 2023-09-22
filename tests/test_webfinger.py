# coding=utf-8
"""Unit tests for webfinger.py."""
import copy
from unittest.mock import patch
import urllib.parse

from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from .testutil import Fake, TestCase

from web import Web
from webfinger import fetch, fetch_actor_url

from .test_web import ACTOR_HTML

WEBFINGER = {
    'subject': 'acct:user.com@user.com',
    'aliases': [
        'https://user.com/about-me',
        'https://user.com/',
    ],
    'links': [{
        'rel': 'http://webfinger.net/rel/profile-page',
        'type': 'text/html',
        'href': 'https://user.com/about-me',
    }, {
        'rel': 'http://webfinger.net/rel/profile-page',
        'type': 'text/html',
        'href': 'https://user.com/',
    }, {
        'rel': 'http://webfinger.net/rel/avatar',
        'href': 'https://user.com/me.jpg',
    }, {
        'rel': 'canonical_uri',
        'type': 'text/html',
        'href': 'https://user.com/about-me',
    }, {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com',
    }, {
        'rel': 'inbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com/inbox'
    }, {
        'rel': 'sharedInbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'http://localhost/web/user.com?url={uri}',
    }],
}
WEBFINGER_NO_HCARD = {
    'subject': 'acct:user.com@user.com',
    'aliases': ['https://user.com/'],
    'links': [{
        'rel': 'http://webfinger.net/rel/profile-page',
        'type': 'text/html',
        'href': 'https://user.com/',
    }, {
        'rel': 'canonical_uri',
        'type': 'text/html',
        'href': 'https://user.com/',
    }, {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com',
    }, {
        'rel': 'inbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/user.com/inbox',
    }, {
        'rel': 'sharedInbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'http://localhost/web/user.com?url={uri}',
    }],
}
WEBFINGER_FAKE = {
    'subject': 'acct:fake:user@fake',
    'aliases': ['fake:user'],
    'links': [{
        'rel': 'canonical_uri',
        'type': 'text/html',
        'href': 'fake:user',
    }, {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': 'http://bf/fake/fake:user/ap',
    }, {
        'rel': 'inbox',
        'type': 'application/activity+json',
        'href': 'http://bf/fake/fake:user/ap/inbox',
    }, {
        'rel': 'sharedInbox',
        'type': 'application/activity+json',
        'href': 'http://localhost/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'http://localhost/fa/fake:user?url={uri}',
    }],
}
WEBFINGER_FAKE_FED_BRID_GY = copy.deepcopy(WEBFINGER_FAKE)
WEBFINGER_FAKE_FED_BRID_GY['links'][3]['href'] = 'https://fed.brid.gy/ap/sharedInbox'
WEBFINGER_FAKE_FED_BRID_GY['links'][4]['template'] = 'https://fed.brid.gy/fa/fake:user?url={uri}'


class HostMetaTest(TestCase):
    def test_host_meta_xrd(self):
        got = self.client.get('/.well-known/host-meta')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/xrd+xml; charset=utf-8',
                         got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('<?xml'), body)

    def test_host_meta_xrds(self):
        got = self.client.get('/.well-known/host-meta.xrds')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/xrds+xml', got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('<XRDS'), body)

    def test_host_meta_jrd(self):
        got = self.client.get('/.well-known/host-meta.json')
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        body = got.get_data(as_text=True)
        self.assertTrue(body.startswith('{'), body)


class WebfingerTest(TestCase):

    def setUp(self):
        super().setUp()

        self.user = self.make_user('user.com', has_hcard=True, obj_as2={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'url': 'https://user.com/about-me',
            'name': 'Mrs. ☕ Foo',
            'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
        })

    def test_webfinger(self):
        for resource in ('user.com@user.com', 'acct:user.com@user.com', 'xyz@user.com',
                         'user.com', 'http://user.com/', 'https://user.com/',
                         'http://localhost/user.com'):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assert_equals(WEBFINGER, got.json)

    def test_user_infer_protocol_from_resource_subdomain(self):
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:fake:user@fake.brid.gy',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE, got.json)

    def test_user_infer_protocol_from_request_subdomain(self):
        self.make_user('fake:user', cls=Fake)
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:user@fake:user',
            base_url='https://fake.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE_FED_BRID_GY, got.json)

    def test_user_infer_protocol_resource_overrides_request(self):
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:fake:user@fake.brid.gy',
            base_url='https://ap.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE_FED_BRID_GY, got.json)

    def test_urlencoded(self):
        """https://github.com/snarfed/bridgy-fed/issues/535"""
        got = self.client.get(
            '/.well-known/webfinger?resource=acct%3Auser.com%40user.com',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER, got.json)

    def test_custom_username(self):
        self.user.obj.as2['url'] = [
            'https://user.com/about-me',
            'acct:notthisuser@boop.org',
            'acct:customuser@user.com',
        ]
        self.user.obj.put()
        self.user.put()

        for resource in (
                'customuser@user.com',
                'acct:customuser@user.com',
                'user.com',
                'user.com@user.com',
                'http://user.com/',
                'https://user.com/',
                'acct:user.com@user.com',
                'acct:@user.com@user.com',
                # Mastodon requires this as of 3.3.0
                # https://github.com/snarfed/bridgy-fed/issues/73
                'acct:user.com@fed.brid.gy',
                'acct:user.com@localhost',
        ):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assert_equals({
                    **WEBFINGER,
                    'subject': 'acct:customuser@user.com',
                    'aliases': [
                        'https://user.com/about-me',
                        'acct:notthisuser@boop.org',
                        'acct:customuser@user.com',
                        'https://user.com/',
                    ],
                }, got.json)

    def test_missing_user(self):
        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope.com@nope.com')
        self.assertEqual(404, got.status_code)

        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope.com')
        self.assertEqual(400, got.status_code)

    def test_indirect_user_not_on_bridgy_fed_subdomain(self):
        self.user.direct = False
        self.user.put()
        got = self.client.get(f'/.well-known/webfinger?resource=acct:user.com@user.com')
        self.assertEqual(404, got.status_code)

    def test_bad_id(self):
        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope@fa.brid.gy')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope@nope',
                              base_url='https://fa.brid.gy/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

    def test_bad_tld(self):
        self.make_user('user.json')
        got = self.client.get(f'/.well-known/webfinger?resource=acct:user.json@user.json',
                              base_url='https://web.brid.gy/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

    @patch('requests.get')
    def test_serve_create_user(self, mock_get):
        self.user.key.delete()
        mock_get.return_value = requests_response(ACTOR_HTML)

        expected = copy.deepcopy(WEBFINGER_NO_HCARD)
        expected['subject'] = 'acct:user.com@localhost'

        got = self.client.get('/.well-known/webfinger?resource=acct:user.com@fed.brid.gy',
                              headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual(expected, got.json)

        user = Web.get_by_id('user.com')
        assert not user.direct

    def test_fed_brid_gy(self):
        got = self.client.get('/.well-known/webfinger?resource=http://localhost/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get('/.well-known/webfinger?resource=acct%3A%40localhost')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

    @patch('requests.get', return_value=requests_response(
        WEBFINGER, content_type='application/jrd+json'))
    def test_fetch(self, mock_get):
        self.assertEqual(WEBFINGER, fetch('@foo@bar'))
        self.assert_req(mock_get,
                        'https://bar/.well-known/webfinger?resource=acct:foo@bar')

    @patch('requests.get', return_value=requests_response(WEBFINGER))
    def test_fetch_actor_url(self, mock_get):
        self.assertEqual('http://localhost/user.com', fetch_actor_url('@foo@bar'))
        self.assert_req(mock_get,
                        'https://bar/.well-known/webfinger?resource=acct:foo@bar')

    @patch('requests.get', return_value=requests_response({'links': []}))
    def test_fetch_actor_url_not_found(self, mock_get):
        self.assertIsNone(fetch_actor_url('@foo@bar'))
        self.assert_req(mock_get,
                        'https://bar/.well-known/webfinger?resource=acct:foo@bar')
