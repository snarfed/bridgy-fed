"""Unit tests for admin.py."""
from unittest.mock import patch

import arroba.server
from google.cloud.ndb import Key

from google.cloud.tasks_v2.types import Task
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil import util

import admin
import common
import config
import filters
import memcache
import models
from models import Object
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

    def test_admin_users_by_id(self):
        resp = self.client.get('/admin/user?query=fake:user')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('fake:user', body)
        self.assertIn('Created', body)
        self.assertIn('/admin/user?query=fake%3Auser', body)

    def test_admin_users_by_handle(self):
        resp = self.client.get('/admin/user?query=fake:handle:user')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('fake:user', body)

    def test_admin_users_by_handle_as_domain(self):
        resp = self.client.get('/admin/user?query=fake-handle-user')
        self.assertEqual(200, resp.status_code)
        self.assertIn('fake:user', resp.get_data(as_text=True))

    def test_admin_users_not_found(self):
        resp = self.client.get('/admin/user?query=fake:nope')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertNotIn('fake:user', body)
        self.assertIn('No users found', body)

    def test_admin_users_multiple(self):
        # OtherFake('fake:handle:user').handle = 'fake:handle:user'
        # (replace('other:', ...) is noop) so both Fake('fake:user') and
        # OtherFake('fake:handle:user') match this handle
        self.make_user('fake:handle:user', cls=OtherFake, obj_key=self.user.obj_key)

        resp = self.client.get('/admin/user?query=fake:handle:user')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('fake:user', body)
        self.assertIn('fake:handle:user', body)
        # TOC with fragment links
        self.assertIn('href="#', body)

    def test_admin_users_strip_brid_gy(self):
        resp = self.client.get('/admin/user?query=fake-handle-user.fa.brid.gy')
        self.assertEqual(200, resp.status_code)
        self.assertIn('fake:user', resp.get_data(as_text=True))

    def test_admin_users_ap_brid_gy(self):
        # .ap.brid.gy suffix triggers translate_user_id (ATProto → AP)
        # for Fake protocol, translate_user_id(id=..., from_=ATProto, to=ActivityPub)
        # goes through the _, 'activitypub' case: subdomain_wrap(ATProto, '/ap/ID')
        # which gives https://atproto.brid.gy/ap/ID. That ID won't match anything,
        # so users list is empty — just verify the endpoint doesn't crash.
        resp = self.client.get('/admin/user?query=alice.ap.brid.gy')
        self.assertEqual(200, resp.status_code)

    def test_admin_user(self):
        key = self.user.key.urlsafe().decode()
        resp = self.client.get(f'/admin/user/{key}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/admin/user?query=fake%3Auser', resp.headers['Location'])

    def test_admin_user_not_found(self):
        bad_key = Key('Fake', 'fake:nonexistent').urlsafe().decode()
        resp = self.client.get(f'/admin/user/{bad_key}')
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/admin/', resp.headers['Location'])

    def test_admin_home_blocklists(self):
        Object(id='internal:content-blocklist', raw=['bad word', 'another']).put()
        resp = self.client.get('/admin/')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('content-blocklist', body)
        self.assertIn('bad word', body)
        self.assertIn('another', body)

    def test_admin_save_blocklist(self):
        resp = self.client.post('/admin/blocklist', data={
            'id': 'internal:content-blocklist',
            'values': 'foo\nbar\n\nbaz\n',
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual(['foo', 'bar', 'baz'],
                         Object.get_by_id('internal:content-blocklist').raw)
        self.assertEqual(['foo', 'bar', 'baz'], filters.CONTENT_BLOCKLIST.obj.raw)

    @patch('requests.get')
    def test_admin_object_lookup(self, mock_get):
        mock_get.return_value = self.as2_resp({'id': 'http://in.st/second'})

        resp = self.client.post('/admin/object', data={'id': 'http://in.st/first'})
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/admin/object/http://in.st/second', resp.headers['Location'])

    def test_admin_object(self):
        obj = self.store_object(id='fake:obj', source_protocol='fake',
                                our_as1={'objectType': 'note', 'content': 'hi'})
        resp = self.client.get('/admin/object/fake:obj')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('fake:obj', body)
        self.assertIn('note', body)

    def test_admin_object_not_found(self):
        resp = self.client.get('/admin/object/nonexistent')
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/admin/', resp.headers['Location'])

    def test_admin_object_crud_verb_redirect(self):
        inner = self.store_object(id='fake:inner')
        activity = self.store_object(id='fake:activity', our_as1={
            'objectType': 'activity',
            'verb': 'post',
            'object': {'id': 'fake:inner'},
        })
        resp = self.client.get('/admin/object/fake:activity')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/admin/object/fake:inner', resp.headers['Location'])

    def test_enable(self):
        key = self.user.key.urlsafe().decode()
        resp = self.client.post('/admin/enable', data={
            'key': key,
            'protocol': 'activitypub',
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/admin/user/{key}', resp.headers['Location'])
        self.assertEqual(['activitypub'], self.user.key.get().enabled_protocols)

    def test_disable(self):
        self.user.enabled_protocols = ['activitypub']
        self.user.put()
        key = self.user.key.urlsafe().decode()
        resp = self.client.post('/admin/disable', data={
            'key': key,
            'protocol': 'activitypub',
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/admin/user/{key}', resp.headers['Location'])
        self.assertEqual([], self.user.key.get().enabled_protocols)

    @patch.object(tasks_client, 'create_task', return_value=Task(name='my task'))
    def test_admin_receive(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        obj_key = Object(id='fake:obj').key.urlsafe()
        resp = self.client.post('/admin/receive', data={
            'obj_key': obj_key,
            'user_key': self.user.key.urlsafe().decode(),
        })
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/admin/object/fake:obj', resp.headers['Location'])
        self.assert_task(mock_create_task, 'receive', obj_id='fake:obj',
                         authed_as='fake:user', force='true')
