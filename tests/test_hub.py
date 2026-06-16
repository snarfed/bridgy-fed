"""Unit tests for hub.py."""
from arroba.datastore_storage import AtpRemoteBlob
import hub
from .testutil import TestCase


class HubTest(TestCase):

    def test_xrpc_redirect_atproto_to_bsky(self):
        client = hub.app.test_client()
        resp = client.get('/xrpc/com.atproto.repo.getRecord',
                          base_url='https://atproto.brid.gy/')
        self.assertEqual(301, resp.status_code)
        self.assertEqual('https://bsky.brid.gy/xrpc/com.atproto.repo.getRecord',
                         resp.headers['Location'])
        self.assertEqual('*', resp.headers['Access-Control-Allow-Origin'])
