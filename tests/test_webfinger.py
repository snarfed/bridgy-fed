"""Unit tests for webfinger.py."""
import copy
from unittest.mock import patch
import urllib.parse

from granary.as2 import CONTENT_TYPE, CONTENT_TYPE_LD_PROFILE
from oauth_dropins.webutil import util
from oauth_dropins.webutil.testutil import requests_response

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitEnableFake, Fake, TestCase

from models import PROTOCOLS
import protocol
from web import Web
from webfinger import fetch, fetch_actor_url

from . import test_web


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
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'http://localhost/user.com',
    }, {
        'rel': 'self',
        'type': CONTENT_TYPE,
        'href': 'http://localhost/user.com',
    }, {
        'rel': 'inbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'http://localhost/user.com/inbox'
    }, {
        'rel': 'sharedInbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'https://web.brid.gy/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        # TODO: genericize
        'template': 'https://fed.brid.gy/web/user.com?url={uri}',
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
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'https://web.brid.gy/user.com',
    }, {
        'rel': 'self',
        'type': CONTENT_TYPE,
        'href': 'https://web.brid.gy/user.com',
    }, {
        'rel': 'inbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'https://web.brid.gy/user.com/inbox',
    }, {
        'rel': 'sharedInbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'https://web.brid.gy/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'https://fed.brid.gy/web/user.com?url={uri}',
    }],
}
WEBFINGER_FAKE = {
    'subject': 'acct:fake:handle:user@fa.brid.gy',
    'aliases': ['web:fake:user'],
    'links': [{
        'rel': 'canonical_uri',
        'type': 'text/html',
        'href': 'web:fake:user',
    }, {
        'rel': 'self',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'http://localhost/ap/fa/fake:user',
    }, {
        'rel': 'self',
        'type': CONTENT_TYPE,
        'href': 'http://localhost/ap/fa/fake:user',
    }, {
        'rel': 'inbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'http://localhost/ap/fa/fake:user/inbox',
    }, {
        'rel': 'sharedInbox',
        'type': CONTENT_TYPE_LD_PROFILE,
        'href': 'https://web.brid.gy/ap/sharedInbox',
    }, {
        'rel': 'http://ostatus.org/schema/1.0/subscribe',
        'template': 'https://fed.brid.gy/fa/fake:handle:user?url={uri}',
    }],
}
WEBFINGER_FAKE_FA_BRID_GY = copy.deepcopy(WEBFINGER_FAKE)
for link in WEBFINGER_FAKE_FA_BRID_GY['links']:
    if 'href' in link:
        link['href'] = link['href'].replace('http://localhost/ap/fa', 'https://fa.brid.gy/ap')
WEBFINGER_FAKE_FA_BRID_GY['links'][4]['href'] = 'https://fa.brid.gy/ap/sharedInbox'
WEBFINGER_FAKE_FA_BRID_GY['links'][5]['template'] = 'https://fed.brid.gy/fa/fake:handle:user?url={uri}'


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

        self.user = self.make_user('user.com', cls=Web, has_hcard=True,
                                   has_redirects=True, obj_as2={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Person',
            'url': 'https://user.com/about-me',
            'name': 'Mrs. ☕ Foo',
            'icon': {'type': 'Image', 'url': 'https://user.com/me.jpg'},
        })

    def test_webfinger(self):
        for resource in ('user.com@user.com', 'acct:user.com@user.com',
                         'user.com', 'http://user.com/', 'https://user.com/',
                         'http://localhost/user.com'):
            with self.subTest(resource=resource):
                url = (f'/.well-known/webfinger?' +
                       urllib.parse.urlencode({'resource': resource}))
                got = self.client.get(url, headers={'Accept': 'application/json'})
                self.assertEqual(200, got.status_code, got.get_data(as_text=True))
                self.assertEqual('application/jrd+json', got.headers['Content-Type'])
                self.assert_equals(WEBFINGER, got.json)

    def test_webfinger_web_subdomain_redirects(self):
        path = '/.well-known/webfinger?resource=user.com@user.com'

        self.user.ap_subdomain = 'web'
        self.user.put()
        got = self.client.get(path, base_url='https://fed.brid.gy/')
        self.assertEqual(302, got.status_code)
        self.assertEqual(f'https://web.brid.gy{path}', got.headers['Location'])

        self.user.ap_subdomain = 'fed'
        self.user.put()
        got = self.client.get(path, base_url='https://web.brid.gy/')
        self.assertEqual(302, got.status_code)
        self.assertEqual(f'https://fed.brid.gy{path}', got.headers['Location'])

    def test_user_infer_protocol_from_resource_subdomain(self):
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:fake:handle:user@fake.brid.gy',
            base_url='https://fed.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE_FA_BRID_GY, got.json)

    def test_user_unknown_protocol_subdomain(self):
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:user@nope.brid.gy',
            headers={'Accept': 'application/json'})
        self.assertEqual(404, got.status_code)

    def test_user_unusable_protocol_subdomain(self):
        from models import PROTOCOLS
        for base_url in None, 'https://bsky.brid.gy/':
            got = self.client.get(
                '/.well-known/webfinger?resource=acct:user.handle@bsky.brid.gy',
                base_url=base_url, headers={'Accept': 'application/json'})
            self.assertEqual(400, got.status_code)

    def test_user_infer_protocol_from_request_subdomain(self):
        self.make_user('fake:user', cls=Fake)
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:user@fake:user',
            base_url='https://fake.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE_FA_BRID_GY, got.json)

    def test_user_infer_protocol_resource_overrides_request(self):
        got = self.client.get(
            '/.well-known/webfinger?resource=acct:fake:handle:user@fake.brid.gy',
            base_url='https://ap.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code)
        self.assertEqual('application/jrd+json', got.headers['Content-Type'])
        self.assert_equals(WEBFINGER_FAKE_FA_BRID_GY, got.json)

    def test_handle_new_user(self):
        self.assertIsNone(Fake.get_by_id('fake:user'))

        got = self.client.get(
            '/.well-known/webfinger?resource=acct:fake:handle:user@fake.brid.gy',
            base_url='https://fed.brid.gy/',
            headers={'Accept': 'application/json'})
        self.assertEqual(200, got.status_code, got.get_data(as_text=True))
        self.assert_equals(WEBFINGER_FAKE_FA_BRID_GY, got.json)

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

    def test_user_not_custom_username(self):
        for base_url in (None, 'https://web.brid.gy/', 'https://fed.brid.gy/'):
            with self.subTest(base_url=base_url):
                got = self.client.get(
                    f'/.well-known/webfinger?resource=acct:foo@user.com',
                    base_url=base_url)
                self.assertEqual(404, got.status_code)

    def test_missing_user_web_subdomain(self):
        self.user.direct = False
        self.user.put()
        got = self.client.get(f'/.well-known/webfinger?resource=acct:foo@bar.com')
        self.assertEqual(404, got.status_code)

    def test_protocol_not_enabled(self):
        self.make_user('eefake:user', cls=ExplicitEnableFake)
        got = self.client.get(f'/.well-known/webfinger?resource=acct:eefake:user@eefake.brid.gy')
        self.assertEqual(404, got.status_code)

    def test_protocol_enabled(self):
        self.make_user('eefake:user', cls=ExplicitEnableFake,
                       enabled_protocols=['activitypub'])
        got = self.client.get(f'/.well-known/webfinger?resource=acct:eefake:user@eefake.brid.gy')
        self.assertEqual(200, got.status_code)

    def test_bad_id(self):
        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope@fa.brid.gy')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get(f'/.well-known/webfinger?resource=acct:nope@nope',
                              base_url='https://fa.brid.gy/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

    def test_bad_tld(self):
        got = self.client.get(
            f'/.well-known/webfinger?resource=acct:user.json@user.json',
            base_url='https://web.brid.gy/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

    def test_no_handle(self):
        class NoHandle(Fake):
            ABBREV = 'nohandle'
            handle = None

        try:
            got = self.client.get(
                '/.well-known/webfinger?resource=acct:nohandle:user@nohandle.brid.gy')
            self.assertEqual(404, got.status_code)
        finally:
            PROTOCOLS.pop('nohandle')

    @patch('requests.get')
    def test_create_user(self, mock_get):
        self.user.key.delete()
        self.user.obj_key.delete()
        protocol.objects_cache.clear()

        mock_get.return_value = requests_response(test_web.ACTOR_HTML)
        expected = copy.deepcopy(WEBFINGER_NO_HCARD)
        expected['subject'] = 'acct:user.com@web.brid.gy'

        got = self.client.get(
            '/.well-known/webfinger?resource=acct:user.com@web.brid.gy',
            headers={'Accept': 'application/json'},
            base_url='https://web.brid.gy/')
        self.assertEqual(200, got.status_code)
        self.assertEqual(expected, got.json)

        user = Web.get_by_id('user.com')
        assert not user.direct

    # skip _pre_put_hook since it doesn't allow internal domains
    @patch.object(Web, '_pre_put_hook', new=lambda self: None)
    def test_protocol_bot_user(self):
        self.make_user('bsky.brid.gy', cls=Web, obj_id='https://bsky.brid.gy/',
                       ap_subdomain='bsky')

        for id in ('acct:bsky.brid.gy@bsky.brid.gy',
                   'https://bsky.brid.gy/bsky.brid.gy'):
            got = self.client.get(f'/.well-known/webfinger?resource={id}')
            self.assertEqual(200, got.status_code, got.get_data(as_text=True))
            self.assertEqual('acct:bsky.brid.gy@bsky.brid.gy', got.json['subject'])
            self.assertEqual(['https://bsky.brid.gy/'], got.json['aliases'])
            self.assertIn({
                'href': 'https://bsky.brid.gy/bsky.brid.gy',
                'rel': 'self',
                'type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
            }, got.json['links'])

    def test_internal_domain_error(self):
        got = self.client.get('/.well-known/webfinger?resource=http://localhost/')
        self.assertEqual(400, got.status_code, got.get_data(as_text=True))

        got = self.client.get('/.well-known/webfinger?resource=acct:@localhost')
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
