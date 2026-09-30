"""Unit tests for atproto_xrpc.py."""
import time
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
from arroba.repo import Repo
import arroba.server
from authlib.oauth2.rfc9449.validator import hash_access_token
from joserfc.jwk import ECKey
from oauth_dropins import indieauth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.pixelfed import PixelfedApp, PixelfedAuth
from webutil import util
from webutil.testutil import NOW, requests_response
from webutil.util import json_dumps

from activitypub import ActivityPub
import atproto_oauth
from models import Target
import oauth_server
from .test_atproto_oauth import dpop_proof
from .testutil import ATPROTO_KEY, OAUTH_ES256_KEY, TestCase
from web import Web

DID = 'did:plc:alice'
CID = 'bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy'
MEDIA_URL = 'https://mas.to/media/foo.png'
UPLOAD_BLOB_URL = 'https://atproto.brid.gy/xrpc/com.atproto.repo.uploadBlob'
MEDIA_ATTACHMENT = {
    'id': '456',
    'type': 'image',
    'url': MEDIA_URL,
    'preview_url': MEDIA_URL,
}


class ATProtoXrpcTest(TestCase):

    def setUp(self):
        super().setUp()
        self.user = self.make_user(
            'https://mas.to/users/alice', cls=ActivityPub,
            webfinger_addr='@alice@mas.to', enabled_protocols=['atproto'],
            copies=[Target(protocol='atproto', uri=DID)])
        MastodonAuth(id='@alice@mas.to', access_token_str='towkin',
                     app=MastodonApp(instance='https://mas.to/', data='{}').put(),
                     user_json=json_dumps({
                         'id': '123',
                         'uri': 'https://mas.to/users/alice',
                     })).put()

    def upload_blob(self, data=b'foo', mime_type='image/png', user=None):
        """Makes an uploadBlob XRPC request, authenticated with a DPoP token."""
        token = oauth_server.encode_jwt({
            'typ': atproto_oauth.TOKEN_TYP,
            'exp': int(time.time()) + 60,
            'jti': 'abc',
            'sub': DID,
            'user_key': (user or self.user).key.urlsafe().decode(),
            'scope': 'atproto transition:generic',
            'cnf': {'jkt': ECKey.import_key(OAUTH_ES256_KEY).thumbprint()},
            'client_id_hash': 'test',
        })
        return self.client.post(UPLOAD_BLOB_URL, data=data, headers={
            'Content-Type': mime_type,
            'Authorization': f'DPoP {token}',
            'DPoP': dpop_proof(
                'POST', UPLOAD_BLOB_URL, ath=hash_access_token(token),
                nonce=atproto_oauth.proof_validator.nonce_generator.next()),
        })

    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob(self, mock_post):
        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'blob': {
                '$type': 'blob',
                'ref': {'$link': CID},
                'mimeType': 'image/png',
                'size': 3,
            },
        }, resp.json)

        self.assertEqual('https://mas.to/api/v1/media', mock_post.call_args.args[0])
        kwargs = mock_post.call_args.kwargs
        self.assertEqual('Bearer towkin', kwargs['headers']['Authorization'])
        self.assertEqual({'file': ('file', b'foo', 'image/png')}, kwargs['files'])

        blob = AtpRemoteBlob.get_by_id(MEDIA_URL)
        self.assertEqual(MEDIA_URL, blob.url)
        self.assertEqual(CID, blob.cid)
        self.assertEqual(3, blob.size)
        self.assertEqual('image/png', blob.mime_type)
        self.assertEqual([AtpRepo(id=DID).key], blob.repos)
        self.assertEqual(NOW, blob.last_fetched)
        self.assertIsNone(blob.status)

    @patch.object(util.session, 'post', return_value=requests_response({
        **MEDIA_ATTACHMENT,
        'url': 'https://pix.fed/storage/foo.png',
    }))
    def test_upload_blob_pixelfed(self, mock_post):
        user = self.make_user(
            'https://pix.fed/users/alice', cls=ActivityPub,
            webfinger_addr='@alice@pix.fed', enabled_protocols=['atproto'],
            copies=[Target(protocol='atproto', uri=DID)])
        PixelfedAuth(id='@alice@pix.fed', access_token_str='towkin',
                     app=PixelfedApp(instance='https://pix.fed/', data='{}').put(),
                     user_json=json_dumps({'id': '123', 'acct': 'alice'})).put()

        resp = self.upload_blob(user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('https://pix.fed/api/v1/media',
                         mock_post.call_args.args[0])

        blob = AtpRemoteBlob.get_by_id('https://pix.fed/storage/foo.png')
        self.assertEqual(CID, blob.cid)

    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob_then_get_blob(self, _):
        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.get(
            f'/xrpc/com.atproto.sync.getBlob?did={DID}&cid={CID}',
            base_url='https://atproto.brid.gy/')
        self.assertEqual(301, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(MEDIA_URL, resp.headers['Location'])

    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob_then_list_blobs(self, _):
        Repo.create(arroba.server.storage, DID, handle='alice.mas.to.ap.brid.gy',
                    signing_key=ATPROTO_KEY, rotation_key=ATPROTO_KEY)

        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.get(f'/xrpc/com.atproto.sync.listBlobs?did={DID}',
                               base_url='https://atproto.brid.gy/')
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({'cids': [CID]}, resp.json)

    @patch.object(util.session, 'post', return_value=requests_response({
        'error': 'Validation failed: File content type is invalid',
    }, status=422))
    def test_upload_blob_native_rejects(self, _):
        resp = self.upload_blob(mime_type='text/plain')
        self.assertEqual(400, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('InvalidRequest', resp.json['error'])
        self.assertIn('File content type is invalid', resp.json['message'])
        self.assertEqual(0, AtpRemoteBlob.query().count())

    @patch.object(util.session, 'post',
                  return_value=requests_response('oops', status=500))
    def test_upload_blob_native_error(self, _):
        resp = self.upload_blob()
        self.assertEqual(502, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(0, AtpRemoteBlob.query().count())

    @patch.object(util, 'requests_get', return_value=requests_response(
        '', url='https://alice.com/',
        headers={'Link': '<https://alice.com/mp>; rel="micropub"'}))
    @patch.object(util.session, 'post')
    def test_upload_blob_web_user(self, mock_post, _):
        user = self.make_user('alice.com', cls=Web, enabled_protocols=['atproto'],
                              copies=[Target(protocol='atproto', uri=DID)])
        indieauth.IndieAuth(id='https://alice.com', user_json='{}',
                            access_token_str='towkin').put()

        resp = self.upload_blob(user=user)
        self.assertEqual(501, resp.status_code, resp.get_data(as_text=True))
        mock_post.assert_not_called()

    @patch.object(util.session, 'post')
    def test_upload_blob_no_auth_entity(self, mock_post):
        MastodonAuth.get_by_id('@alice@mas.to').key.delete()

        resp = self.upload_blob()
        self.assertEqual(501, resp.status_code, resp.get_data(as_text=True))
        mock_post.assert_not_called()

    @patch.object(util.session, 'post')
    def test_upload_blob_unauthenticated(self, mock_post):
        resp = self.client.post(UPLOAD_BLOB_URL, data=b'foo',
                                headers={'Content-Type': 'image/png'})
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))
        mock_post.assert_not_called()
