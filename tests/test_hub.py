"""Unit tests for hub.py."""
from arroba.datastore_storage import AtpRemoteBlob
import hub
from .testutil import TestCase


class HubTest(TestCase):

    def test_xrpc_get_blob_not_redirected_from_atproto(self):
        cid = 'bafkreicqpqncshdd27sgztqgzocd3zhhqnnsv6slvzhs5uz6f57cq6lmtq'
        AtpRemoteBlob(id='https://blob.example.com/foo', cid=cid, size=13).put()
        client = hub.app.test_client()
        resp = client.get(f'/xrpc/com.atproto.sync.getBlob?did=did:web:user.com&cid={cid}',
                          base_url='https://atproto.brid.gy/')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://blob.example.com/foo', resp.headers['Location'])

    def test_xrpc_redirect_atproto_to_bsky(self):
        client = hub.app.test_client()
        resp = client.get('/xrpc/com.atproto.repo.getRecord',
                          base_url='https://atproto.brid.gy/')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://bsky.brid.gy/xrpc/com.atproto.repo.getRecord',
                         resp.headers['Location'])
