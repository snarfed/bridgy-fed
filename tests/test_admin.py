"""Unit tests for admin.py."""
import arroba.server
from google.cloud.ndb import Key

import admin
import config
import memcache
import models
from .testutil import Fake, OtherFake, TestCase


class AdminTest(TestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user('fake:user', cls=Fake)

    def test_memcache_evict_key(self):
        self.user.key.get()
        self.assertIsNotNone(self.user.key.get(use_cache=False, use_datastore=False,
                                               use_global_cache=True))

        resp = self.client.post('/admin/memcache/evict',
                                data={'key': self.user.key.urlsafe().decode()},
                                headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertIsNone(self.user.key.get(use_cache=False, use_datastore=False,
                                            use_global_cache=True))

    def test_memcache_evict_raw(self):

        resp = self.client.post('/admin/memcache/evict', data={'raw': 'foo'},
                                headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('not found', resp.get_data(as_text=True))

        memcache.memcache.add('foo', 'bar')
        self.assertEqual('bar', memcache.memcache.get('foo'))

        resp = self.client.post('/admin/memcache/evict', data={'raw': 'foo'},
                                headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('deleted', resp.get_data(as_text=True))
        self.assertIsNone(memcache.memcache.get('foo'))

    def test_memcache_evict_bad_auth(self):
        self.user.key.get()
        self.assertIsNotNone(self.user.key.get(use_cache=False, use_datastore=False,
                                               use_global_cache=True))

        resp = self.client.post('/admin/memcache/evict', data={
            'key': self.user.key.urlsafe().decode(),
        })
        self.assertEqual(401, resp.status_code)
        self.assertIsNotNone(self.user.key.get(use_cache=False, use_datastore=False,
                                               use_global_cache=True))

    def test_memcache_get_key(self):
        self.user.key.get()
        self.assertIsNotNone(self.user.key.get(use_cache=False, use_datastore=False,
                                               use_global_cache=True))

        resp = self.client.get(
            f'/admin/memcache/get?key={self.user.key.urlsafe().decode()}',
            headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual(repr(self.user.key.get()), resp.get_data(as_text=True))

    def test_memcache_get_raw(self):
        resp = self.client.get('/admin/memcache/get?raw=foo',
                               headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('None', resp.get_data(as_text=True))

        memcache.memcache.set('foo', 'bar')
        resp = self.client.get('/admin/memcache/get?raw=foo',
                               headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual("'bar'", resp.get_data(as_text=True))

    def test_sequences_alloc(self):
        resp = self.client.post('/admin/sequences/alloc', data={'nsid': 'foo.bar'},
                                headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('1', resp.get_data(as_text=True))

        resp = self.client.post('/admin/sequences/alloc', data={'nsid': 'foo.bar'},
                                headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('2', resp.get_data(as_text=True))

    def test_sequences_alloc_bad_auth(self):
        resp = self.client.post('/admin/sequences/alloc', data={'nsid': 'foo.bar'})
        self.assertEqual(401, resp.status_code)

    def test_sequences_last(self):
        resp = self.client.get('/admin/sequences/last?nsid=foo.bar',
                               headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('None', resp.get_data(as_text=True))

        got = arroba.server.storage.sequences.allocate('foo.bar')
        resp = self.client.get('/admin/sequences/last?nsid=foo.bar',
                               headers={'Authorization': config.SECRET_KEY})
        self.assertEqual(200, resp.status_code)
        self.assertEqual(str(got), resp.get_data(as_text=True))

    def test_sequences_last_bad_auth(self):
        resp = self.client.get('/admin/sequences/last', data={'nsid': 'foo.bar'})
        self.assertEqual(401, resp.status_code)

    def test_admin_home(self):
        resp = self.client.get('/admin/')
        self.assertEqual(200, resp.status_code)
        self.assertIn('<form', resp.get_data(as_text=True))

    def test_admin_user_redirect(self):
        resp = self.client.post('/admin/user', data={'id': 'fake:user'})
        self.assertEqual(302, resp.status_code)
        key = self.user.key.urlsafe().decode()
        self.assertIn(f'/admin/user/{key}', resp.headers['Location'])

    def test_admin_user_redirect_not_found(self):
        resp = self.client.post('/admin/user', data={'id': 'fake:nope'})
        self.assertEqual(200, resp.status_code)
        self.assertIn('class="message', resp.get_data(as_text=True))

    def test_admin_user(self):
        self.user = self.make_user('fake:user', cls=Fake, obj_as1={
            'objectType': 'person',
            'displayName': 'Alice',
            'summary': 'hi there',
            'image': [{'url': 'https://example.com/pic.jpg'}],
        })
        key = self.user.key.urlsafe().decode()
        resp = self.client.get(f'/admin/user/{key}')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('fake:user', body)
        self.assertIn('Alice', body)
        # self.assertIn('hi there', body)

    def test_admin_user_not_found(self):
        bad_key = Key('Fake', 'fake:nonexistent').urlsafe().decode()
        resp = self.client.get(f'/admin/user/{bad_key}')
        self.assertEqual(404, resp.status_code)
