"""Unit tests for atproto_xrpc.py."""
import time
from unittest.mock import patch

from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
from arroba.repo import Repo
import arroba.server
from authlib.oauth2.rfc9449.validator import hash_access_token
import dag_json
from joserfc.jwk import ECKey
from oauth_dropins import indieauth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.pixelfed import PixelfedApp, PixelfedAuth
from webutil import util
from webutil.testutil import NOW, requests_response
from webutil.util import json_dumps, json_loads

from activitypub import ActivityPub
import atproto_oauth
from models import Target
import oauth_server
from .test_atproto_oauth import dpop_proof
from .testutil import ATPROTO_KEY, OAUTH_ES256_KEY, TestCase
from web import Web

DID = 'did:plc:alice'

# Mastodon re-encodes uploaded media, so it serves different bytes than we upload
CID = 'bafkreicydeh7vp4ydkrzk33e475wym3ldaphcrmvbi37jttnoynid5oqqm'
MEDIA_RESPONSE = requests_response(b'processed', content_type='image/png')
MEDIA_URL = 'https://mas.to/media/foo.png'
MEDIA_ATTACHMENT = {
    'id': '456',
    'type': 'image',
    'url': MEDIA_URL,
    'preview_url': MEDIA_URL,
}

POST_URI = 'at://did:plc:bob/app.bsky.feed.post/123'
POST_URL = 'https://bsky.app/profile/did:plc:bob/post/123'
STRONG_REF = {
    'uri': POST_URI,
    'cid': 'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm',
}
NOW_STR = NOW.isoformat().replace('+00:00', 'Z')
STATUS = {'id': '789', 'url': 'https://mas.to/@alice/789'}


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
        Repo.create(arroba.server.storage, DID, handle='alice.mas.to.ap.brid.gy',
                    signing_key=ATPROTO_KEY, rotation_key=ATPROTO_KEY)

    def auth_headers(self, url, user=None):
        """Returns DPoP auth headers for an XRPC POST request."""
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
        return {
            'Authorization': f'DPoP {token}',
            'DPoP': dpop_proof(
                'POST', url, ath=hash_access_token(token),
                nonce=atproto_oauth.proof_validator.nonce_generator.next()),
        }

    def upload_blob(self, data=b'foo', mime_type='image/png', user=None):
        """Makes an uploadBlob XRPC request, authenticated with a DPoP token."""
        url = 'https://atproto.brid.gy/xrpc/com.atproto.repo.uploadBlob'
        headers = {
            'Content-Type': mime_type,
            **self.auth_headers(url, user=user),
        }
        return self.client.post(url, data=data, headers=headers)

    def xrpc_post(self, nsid, input, user=None):
        """Makes an XRPC procedure request, authenticated with a DPoP token."""
        url = f'https://atproto.brid.gy/xrpc/{nsid}'
        return self.client.post(url, json=input,
                                headers=self.auth_headers(url, user=user))

    def create_record(self, record, user=None):
        """Makes a createRecord XRPC request, authenticated with a DPoP token."""
        return self.xrpc_post('com.atproto.repo.createRecord', {
            'repo': DID,
            'collection': record['$type'],
            'rkey': 'abc',
            'record': record,
        }, user=user)

    @patch.object(util.session, 'get', return_value=MEDIA_RESPONSE)
    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob(self, mock_post, _):
        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual({
            'blob': {
                '$type': 'blob',
                'ref': {'$link': CID},
                'mimeType': 'image/png',
                'size': 9,
            },
        }, resp.json)

        self.assertEqual('https://mas.to/api/v1/media', mock_post.call_args.args[0])
        kwargs = mock_post.call_args.kwargs
        self.assertEqual('Bearer towkin', kwargs['headers']['Authorization'])
        self.assertEqual({'file': ('file', b'foo', 'image/png')}, kwargs['files'])

        blob = AtpRemoteBlob.get_by_id(MEDIA_URL)
        self.assertEqual(MEDIA_URL, blob.url)
        self.assertEqual(CID, blob.cid)
        self.assertEqual(9, blob.size)
        self.assertEqual('image/png', blob.mime_type)
        self.assertEqual([AtpRepo(id=DID).key], blob.repos)
        self.assertEqual('456', blob.remote_id)
        self.assertEqual(NOW, blob.last_fetched)
        self.assertIsNone(blob.status)

    @patch.object(util.session, 'get', return_value=MEDIA_RESPONSE)
    @patch.object(util.session, 'post', return_value=requests_response({
        **MEDIA_ATTACHMENT,
        'url': 'https://pix.fed/storage/foo.png',
    }))
    def test_upload_blob_pixelfed(self, mock_post, _):
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

    @patch.object(util.session, 'get', return_value=MEDIA_RESPONSE)
    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob_then_get_blob(self, *_):
        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        resp = self.client.get(
            f'/xrpc/com.atproto.sync.getBlob?did={DID}&cid={CID}',
            base_url='https://atproto.brid.gy/')
        self.assertEqual(301, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual(MEDIA_URL, resp.headers['Location'])

    @patch.object(util.session, 'get', return_value=MEDIA_RESPONSE)
    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob_then_list_blobs(self, *_):
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

    @patch.object(util.session, 'get',
                  return_value=requests_response('', status=404))
    @patch.object(util.session, 'post',
                  return_value=requests_response(MEDIA_ATTACHMENT))
    def test_upload_blob_fetch_native_media_error(self, *_):
        resp = self.upload_blob()
        self.assertEqual(502, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual('UpstreamFailure', resp.json['error'])

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
        resp = self.client.post('/xrpc/com.atproto.repo.uploadBlob', data=b'foo',
                                headers={'Content-Type': 'image/png'})
        self.assertEqual(401, resp.status_code, resp.get_data(as_text=True))
        mock_post.assert_not_called()

    def assert_create_record(self, mock_post, record, text, media_ids=None):
        """Creates a record, checks it and its self-DM status."""
        resp = self.create_record(record)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        collection = record['$type']
        uri = f'at://{DID}/{collection}/abc'
        self.assertEqual(uri, resp.json['uri'])
        repo = arroba.server.storage.load_repo(DID)
        stored = repo.get_record(collection, 'abc')
        self.assertEqual(record, json_loads(dag_json.encode(stored, dialect='atproto')))

        self.assertEqual('https://mas.to/api/v1/statuses',
                         mock_post.call_args.args[0])
        kwargs = mock_post.call_args.kwargs
        self.assertEqual('Bearer towkin', kwargs['headers']['Authorization'])
        expected = {
            'status': f'{text}\n\n{uri}',
            'visibility': 'direct',
        }
        if media_ids:
            expected['media_ids'] = media_ids
        self.assertEqual(expected, kwargs['json'])

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_post(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        }, 'hello world')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_reply(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.post',
            'text': 'a reply',
            'createdAt': NOW_STR,
            'reply': {'root': STRONG_REF, 'parent': STRONG_REF},
        }, f'replied to {POST_URL} : a reply')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_quote(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.post',
            'text': 'a quote',
            'createdAt': NOW_STR,
            'embed': {'$type': 'app.bsky.embed.record', 'record': STRONG_REF},
        }, f'quoted {POST_URL} : a quote')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_like(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.like',
            'subject': STRONG_REF,
            'createdAt': NOW_STR,
        }, f'liked {POST_URI}')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_repost(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.repost',
            'subject': STRONG_REF,
            'createdAt': NOW_STR,
        }, f'reposted {POST_URI}')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_follow(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:bob',
            'createdAt': NOW_STR,
        }, 'followed did:plc:bob')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_block(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.graph.block',
            'subject': 'did:plc:bob',
            'createdAt': NOW_STR,
        }, 'blocked did:plc:bob')

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_create_record_unknown_collection(self, mock_post):
        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.threadgate',
            'post': POST_URI,
            'createdAt': NOW_STR,
        }, 'app.bsky.feed.threadgate')

    @patch.object(util.session, 'get', return_value=MEDIA_RESPONSE)
    @patch.object(util.session, 'post', side_effect=[
        requests_response(MEDIA_ATTACHMENT),
        requests_response(STATUS),
    ])
    def test_create_record_image(self, mock_post, _):
        resp = self.upload_blob()
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        self.assert_create_record(mock_post, {
            '$type': 'app.bsky.feed.post',
            'text': 'look',
            'createdAt': NOW_STR,
            'embed': {
                '$type': 'app.bsky.embed.images',
                'images': [{'alt': '', 'image': resp.json['blob']}],
            },
        }, 'look', media_ids=['456'])

    @patch.object(util.session, 'post',
                  return_value=requests_response('oops', status=500))
    def test_create_record_native_error(self, mock_post):
        record = {
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        }
        resp = self.create_record(record)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        repo = arroba.server.storage.load_repo(DID)
        self.assertEqual(record, repo.get_record('app.bsky.feed.post', 'abc'))
        mock_post.assert_called_once()

    @patch.object(util.session, 'get')
    @patch.object(util.session, 'post')
    def test_create_record_web_user(self, mock_post, mock_get):
        user = self.make_user('alice.com', cls=Web, enabled_protocols=['atproto'],
                              copies=[Target(protocol='atproto', uri=DID)])
        indieauth.IndieAuth(id='https://alice.com', user_json='{}',
                            access_token_str='towkin').put()

        record = {
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        }
        resp = self.create_record(record, user=user)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        repo = arroba.server.storage.load_repo(DID)
        self.assertEqual(record, repo.get_record('app.bsky.feed.post', 'abc'))
        mock_get.assert_not_called()
        mock_post.assert_not_called()

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_put_record_new(self, mock_post):
        record = {
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        }
        resp = self.xrpc_post('com.atproto.repo.putRecord', {
            'repo': DID,
            'collection': 'app.bsky.feed.post',
            'rkey': 'abc',
            'record': record,
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        uri = f'at://{DID}/app.bsky.feed.post/abc'
        self.assertEqual(uri, resp.json['uri'])
        repo = arroba.server.storage.load_repo(DID)
        self.assertEqual(record, repo.get_record('app.bsky.feed.post', 'abc'))

        self.assertEqual('https://mas.to/api/v1/statuses',
                         mock_post.call_args.args[0])
        self.assertEqual({
            'status': f'hello world\n\n{uri}',
            'visibility': 'direct',
        }, mock_post.call_args.kwargs['json'])

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_put_record_update(self, mock_post):
        resp = self.create_record({
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        record = {
            '$type': 'app.bsky.feed.post',
            'text': 'hello again',
            'createdAt': NOW_STR,
        }
        resp = self.xrpc_post('com.atproto.repo.putRecord', {
            'repo': DID,
            'collection': 'app.bsky.feed.post',
            'rkey': 'abc',
            'record': record,
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        repo = arroba.server.storage.load_repo(DID)
        self.assertEqual(record, repo.get_record('app.bsky.feed.post', 'abc'))

        uri = f'at://{DID}/app.bsky.feed.post/abc'
        self.assertEqual([{
            'status': f'hello world\n\n{uri}',
            'visibility': 'direct',
        }, {
            'status': f'hello again\n\n{uri}',
            'visibility': 'direct',
        }], [call.kwargs['json'] for call in mock_post.call_args_list])

    @patch.object(util.session, 'post', return_value=requests_response(STATUS))
    def test_apply_writes(self, mock_post):
        resp = self.create_record({
            '$type': 'app.bsky.feed.post',
            'text': 'hello world',
            'createdAt': NOW_STR,
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'another post',
            'createdAt': NOW_STR,
        }
        like = {
            '$type': 'app.bsky.feed.like',
            'subject': STRONG_REF,
            'createdAt': NOW_STR,
        }
        resp = self.xrpc_post('com.atproto.repo.applyWrites', {
            'repo': DID,
            'writes': [{
                '$type': 'com.atproto.repo.applyWrites#create',
                'collection': 'app.bsky.feed.post',
                'rkey': 'def',
                'value': post,
            }, {
                '$type': 'com.atproto.repo.applyWrites#create',
                'collection': 'app.bsky.feed.like',
                'rkey': 'ghi',
                'value': like,
            }, {
                '$type': 'com.atproto.repo.applyWrites#delete',
                'collection': 'app.bsky.feed.post',
                'rkey': 'abc',
            }],
        })
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))

        repo = arroba.server.storage.load_repo(DID)
        self.assertEqual(post, repo.get_record('app.bsky.feed.post', 'def'))
        self.assertEqual(like, repo.get_record('app.bsky.feed.like', 'ghi'))
        self.assertIsNone(repo.get_record('app.bsky.feed.post', 'abc'))

        self.assertEqual([{
            'status': f'hello world\n\nat://{DID}/app.bsky.feed.post/abc',
            'visibility': 'direct',
        }, {
            'status': f'another post\n\nat://{DID}/app.bsky.feed.post/def',
            'visibility': 'direct',
        }, {
            'status': f'liked {POST_URI}\n\nat://{DID}/app.bsky.feed.like/ghi',
            'visibility': 'direct',
        }], [call.kwargs['json'] for call in mock_post.call_args_list])
