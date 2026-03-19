"""Unit tests for admin.py."""
import arroba.server

import admin
import config
import memcache
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
