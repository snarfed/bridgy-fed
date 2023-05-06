# coding=utf-8
"""Unit tests for models.py."""
from unittest import mock

from arroba.mst import dag_cbor_cid
from Crypto.PublicKey import ECC
from flask import g, get_flashed_messages
from granary import as2
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY
from multiformats import CID
from oauth_dropins.webutil.testutil import NOW, requests_response

from app import app
import common
from models import AtpNode, Follower, Object, OBJECT_EXPIRE_AGE, User
import protocol
from . import testutil

from .test_activitypub import ACTOR

class UserTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.app_context = app.test_request_context('/')
        self.app_context.push()
        g.user = self.make_user('y.z')

        self.full_redir = requests_response(
            status=302,
            redirected_url='http://localhost/.well-known/webfinger?resource=acct:y.z@y.z')

    def tearDown(self):
        self.app_context.pop()
        super().tearDown()

    def test_get_or_create(self):
        user = User.get_or_create('a.b')

        assert user.mod
        assert user.public_exponent
        assert user.private_exponent
        assert user.p256_key

        # check that we can load the keys
        assert user.public_pem()
        assert user.private_pem()

        p256_key = ECC.import_key(user.p256_key)
        assert isinstance(p256_key, ECC.EccKey)
        self.assertEqual('NIST P-256', p256_key.curve)

        same = User.get_or_create('a.b')
        self.assertEqual(same, user)

    def test_get_or_create_use_instead(self):
        user = User.get_or_create('a.b')
        user.use_instead = g.user.key
        user.put()

        self.assertEqual('y.z', User.get_or_create('a.b').key.id())

    def test_href(self):
        href = g.user.href()
        self.assertTrue(href.startswith('data:application/magic-public-key,RSA.'), href)
        self.assertIn(g.user.mod, href)
        self.assertIn(g.user.public_exponent, href)

    def test_public_pem(self):
        pem = g.user.public_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN PUBLIC KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END PUBLIC KEY-----'), pem)

    def test_private_pem(self):
        pem = g.user.private_pem()
        self.assertTrue(pem.decode().startswith('-----BEGIN RSA PRIVATE KEY-----\n'), pem)
        self.assertTrue(pem.decode().endswith('-----END RSA PRIVATE KEY-----'), pem)

    def test_address(self):
        self.assertEqual('@y.z@y.z', g.user.address())

        g.user.actor_as2 = {'type': 'Person'}
        self.assertEqual('@y.z@y.z', g.user.address())

        g.user.actor_as2 = {'url': 'http://foo'}
        self.assertEqual('@y.z@y.z', g.user.address())

        g.user.actor_as2 = {'url': ['http://foo', 'acct:bar@foo', 'acct:baz@y.z']}
        self.assertEqual('@baz@y.z', g.user.address())

    def test_actor_id(self):
        self.assertEqual('http://localhost/y.z', g.user.actor_id())

    def _test_verify(self, redirects, hcard, actor, redirects_error=None):
        got = g.user.verify()
        self.assertEqual(g.user.key, got.key)

        with self.subTest(redirects=redirects, hcard=hcard, actor=actor,
                          redirects_error=redirects_error):
            self.assert_equals(redirects, bool(g.user.has_redirects))
            self.assert_equals(hcard, bool(g.user.has_hcard))
            if actor is None:
                self.assertIsNone(g.user.actor_as2)
            else:
                got = {k: v for k, v in g.user.actor_as2.items()
                       if k in actor}
                self.assert_equals(actor, got)
            self.assert_equals(redirects_error, g.user.redirects_error)

    @mock.patch('requests.get')
    def test_verify_neither(self, mock_get):
        empty = requests_response('')
        mock_get.side_effect = [empty, empty]
        self._test_verify(False, False, None)

    @mock.patch('requests.get')
    def test_verify_redirect_strips_query_params(self, mock_get):
        half_redir = requests_response(
            status=302, redirected_url='http://localhost/.well-known/webfinger')
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [half_redir, no_hcard]
        self._test_verify(False, False, None, """\
Current vs expected:<pre>- http://localhost/.well-known/webfinger
+ https://fed.brid.gy/.well-known/webfinger?resource=acct:y.z@y.z</pre>""")

    @mock.patch('requests.get')
    def test_verify_multiple_redirects(self, mock_get):
        two_redirs = requests_response(
            status=302, redirected_url=[
                'https://www.y.z/.well-known/webfinger?resource=acct:y.z@y.z',
                'http://localhost/.well-known/webfinger?resource=acct:y.z@y.z',
            ])
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [two_redirs, no_hcard]
        self._test_verify(True, False, None)

    @mock.patch('requests.get')
    def test_verify_redirect_404(self, mock_get):
        redir_404 = requests_response(status=404, redirected_url='http://this/404s')
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [redir_404, no_hcard]
        self._test_verify(False, False, None, """\
<pre>https://y.z/.well-known/webfinger?resource=acct:y.z@y.z
  redirected to:
http://this/404s
  returned HTTP 404</pre>""")

    @mock.patch('requests.get')
    def test_verify_no_hcard(self, mock_get):
        mock_get.side_effect = [
            self.full_redir,
            requests_response("""
<body>
<div class="h-entry">
  <p class="e-content">foo bar</p>
</div>
</body>
"""),
        ]
        self._test_verify(True, False, None)

    @mock.patch('requests.get')
    def test_verify_non_representative_hcard(self, mock_get):
        bad_hcard = requests_response(
            '<html><body><a class="h-card u-url" href="https://a.b/">acct:me@y.z</a></body></html>',
            url='https://y.z/',
        )
        mock_get.side_effect = [self.full_redir, bad_hcard]
        self._test_verify(True, False, None)

    @mock.patch('requests.get')
    def test_verify_both_work(self, mock_get):
        hcard = requests_response("""
<html><body class="h-card">
  <a class="u-url p-name" href="/">me</a>
  <a class="u-url" href="acct:myself@y.z">Masto</a>
</body></html>""",
            url='https://y.z/',
        )
        mock_get.side_effect = [self.full_redir, hcard]
        self._test_verify(True, True, {
            'type': 'Person',
            'name': 'me',
            'url': ['http://localhost/r/https://y.z/', 'acct:myself@y.z'],
            'preferredUsername': 'y.z',
        })

    @mock.patch('requests.get')
    def test_verify_www_redirect(self, mock_get):
        www_user = self.make_user('www.y.z')

        empty = requests_response('')
        mock_get.side_effect = [
            requests_response(status=302, redirected_url='https://www.y.z/'),
            empty, empty,
        ]

        got = www_user.verify()
        self.assertEqual('y.z', got.key.id())

        root_user = User.get_by_id('y.z')
        self.assertEqual(root_user.key, www_user.key.get().use_instead)
        self.assertEqual(root_user.key, User.get_or_create('www.y.z').key)

    @mock.patch('requests.get')
    def test_verify_actor_rel_me_links(self, mock_get):
        mock_get.side_effect = [
            self.full_redir,
            requests_response("""
<body>
<div class="h-card">
<a class="u-url" rel="me" href="/about-me">Mrs. ☕ Foo</a>
<a class="u-url" rel="me" href="/">should be ignored</a>
<a class="u-url" rel="me" href="http://one" title="one title">
  one text
</a>
<a class="u-url" rel="me" href="https://two" title=" two title "> </a>
</div>
</body>
""", url='https://y.z/'),
        ]
        self._test_verify(True, True, {
            'attachment': [{
            'type': 'PropertyValue',
            'name': 'Mrs. ☕ Foo',
            'value': '<a rel="me" href="https://y.z/about-me">y.z/about-me</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'Web site',
            'value': '<a rel="me" href="https://y.z/">y.z</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'one text',
            'value': '<a rel="me" href="http://one">one</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'two title',
            'value': '<a rel="me" href="https://two">two</a>',
        }]})

    @mock.patch('requests.get')
    def test_verify_override_preferredUsername(self, mock_get):
        mock_get.side_effect = [
            self.full_redir,
            requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">
  <span class="p-nickname">Nick</span>
</a>
</body>
""", url='https://y.z/'),
        ]
        self._test_verify(True, True, {
            # stays y.z despite user's username. since Mastodon queries Webfinger
            # for preferredUsername@fed.brid.gy
            # https://github.com/snarfed/bridgy-fed/issues/77#issuecomment-949955109
            'preferredUsername': 'y.z',
        })

    def test_homepage(self):
        self.assertEqual('https://y.z/', g.user.homepage)

    def test_is_homepage(self):
        for url in 'y.z', '//y.z', 'http://y.z', 'https://y.z':
            self.assertTrue(g.user.is_homepage(url), url)

        for url in None, '', 'y', 'z', 'z.z', 'ftp://y.z', 'http://y', '://y.z':
            self.assertFalse(g.user.is_homepage(url), url)


class ObjectTest(testutil.TestCase):
    def setUp(self):
        super().setUp()
        self.app_context = app.test_request_context('/')
        self.app_context.push()
        g.user = None

    def tearDown(self):
        self.app_context.pop()
        super().tearDown()

    def test_proxy_url(self):
        obj = Object(id='abc', as2={})
        self.assertEqual('http://localhost/render?id=abc', obj.proxy_url())

        obj = Object(id='ab#c', as2={})
        self.assertEqual('http://localhost/render?id=ab%5E%5Ec', obj.proxy_url())

    def test_put(self):
        with self.assertRaises(AssertionError):
            Object(id='x^^y').put()

    def test_get_by_id(self):
        self.assertIsNone(Object.get_by_id('abc'))
        self.assertIsNone(Object.get_by_id('ab^^c'))

        obj = Object(id='abc')
        obj.put()
        self.assertIsNotNone(obj, Object.get_by_id('abc'))

        obj = Object(id='ab#c')
        obj.put()
        self.assert_entities_equal(obj, Object.get_by_id('ab^^c'))

    def test_actor_link(self):
        for expected, as2 in (
                ('href="">', {}),
                ('href="http://foo">foo', {'actor': 'http://foo'}),
                ('href="">Alice', {'actor': {'name': 'Alice'}}),
                ('href="http://foo/">Alice', {'actor': {
                    'name': 'Alice',
                    'url': 'http://foo',
                }}),
                ("""\
        title="Alice">
          <img class="profile" src="http://pic/" />
          Alice""", {'actor': {
            'name': 'Alice',
            'icon': {'type': 'Image', 'url': 'http://pic'},
        }}),
        ):
            obj = Object(id='x', as2=as2)
            self.assert_multiline_in(expected, obj.actor_link())

    def test_actor_link_user(self):
        g.user = User(id='user.com', actor_as2={"name": "Alice"})
        obj = Object(id='x', source_protocol='ui', domains=['user.com'])
        self.assertIn(
            'href="/user/user.com"><img src="" class="profile"> Alice</a>',
            obj.actor_link())

    def test_put_updates_load_cache(self):
        obj = Object(id='x', as2={})
        obj.put()
        self.assert_entities_equal(obj, protocol.objects_cache['x'])

    def test_put_fragment_id_doesnt_update_load_cache(self):
        obj = Object(id='x#y', as2={})
        obj.put()
        self.assertNotIn('x#y', protocol.objects_cache)
        self.assertNotIn('x', protocol.objects_cache)

    def test_computed_properties_without_as1(self):
        Object(id='a').put()

    def test_expire(self):
        obj = Object(id='a', our_as1={'objectType': 'activity', 'verb': 'update'})
        self.assertEqual(NOW + OBJECT_EXPIRE_AGE, obj.expire)

    def test_put_adds_removes_activity_label(self):
        obj = Object(id='x#y', our_as1={})
        obj.put()
        self.assertEqual([], obj.labels)

        obj.our_as1 = {'objectType': 'activity'}
        obj.put()
        self.assertEqual(['activity'], obj.labels)

        obj.labels = ['user']
        obj.put()
        self.assertEqual(['user', 'activity'], obj.labels)

        obj.labels = ['activity', 'user']
        obj.put()
        self.assertEqual(['activity', 'user'], obj.labels)

        obj.our_as1 = {'foo': 'bar'}
        obj.put()
        self.assertEqual(['user'], obj.labels)


class FollowerTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.inbound = Follower(dest='user.com', src='http://mas.to/@baz',
                                last_follow={'actor': ACTOR})
        self.outbound = Follower(dest='http://mas.to/@baz', src='user.com',
                                 last_follow={'object': ACTOR})

    def test_to_as1(self):
        self.assertEqual({}, Follower().to_as1())

        as1_actor = as2.to_as1(ACTOR)
        self.assertEqual(as1_actor, self.inbound.to_as1())
        self.assertEqual(as1_actor, self.outbound.to_as1())

    def test_to_as2(self):
        self.assertIsNone(Follower().to_as2())
        self.assertEqual(ACTOR, self.inbound.to_as2())
        self.assertEqual(ACTOR, self.outbound.to_as2())


class AtpNodeTest(testutil.TestCase):

    def test_create(self):
        AtpNode.create(ACTOR_PROFILE_BSKY)
        stored = AtpNode.get_by_id(dag_cbor_cid(ACTOR_PROFILE_BSKY).encode('base32'))
        self.assertEqual(ACTOR_PROFILE_BSKY, stored.data)
