"""Integration tests."""
import copy
from datetime import datetime
from unittest import skip
from unittest.mock import ANY, patch

from arroba.datastore_storage import DatastoreStorage
from arroba.repo import Repo
from arroba.util import dag_cbor_cid
from dns.resolver import NXDOMAIN
from granary import as2, bluesky
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY, POST_BSKY
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import NOW, requests_response
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

from activitypub import ActivityPub
import app
from atproto import ATProto, Cursor
import atproto_firehose
import common
from models import DM, Follower, Object, Target
import simple_websocket
from web import Web

from .testutil import ATPROTO_KEY, TestCase
from .test_activitypub import ACTOR, add_key, sign
from .test_atproto_firehose import FakeWebsocketClient, setup_firehose
from . import test_atproto
from . import test_web

DID_DOC = {
    **test_atproto.DID_DOC,
    'id': 'did:plc:alice',
    'alsoKnownAs': ['at://alice.com'],
}
PROFILE_GETRECORD = {
    'uri': 'at://did:plc:alice/app.bsky.actor.profile/self',
    'cid': 'alice+sidd',
    'value': test_atproto.ACTOR_PROFILE_BSKY,
}


@patch('ids.COPIES_PROTOCOLS', ['atproto'])
class IntegrationTests(TestCase):

    def setUp(self):
        super().setUp()
        self.storage = DatastoreStorage()

    def make_ap_user(self, ap_id, did=None):
        user = self.make_user(id=ap_id, cls=ActivityPub,
                              obj_as2=add_key({
                                  'type': 'Person',
                                  'id': ap_id,
                                  'name': 'My Name',
                                  'image': 'http://pic',
                                  'inbox': f'{ap_id}/inbox',
                              }))
        if did:
            self.make_atproto_copy(user, did)

        return user

    def make_atproto_user(self, did, enabled_protocols=['activitypub']):
        self.store_object(id=did, raw=DID_DOC)
        user = self.make_user(id=did, cls=ATProto,
                              obj_bsky=test_atproto.ACTOR_PROFILE_BSKY,
                              enabled_protocols=enabled_protocols)
        return user

    def make_web_user(self, domain, did, enabled_protocols=['activitypub']):
        ap_subdomain = (domain.removesuffix('.brid.gy')
                        if domain.endswith('.brid.gy')
                        else None)

        user = self.make_user(id=domain, cls=Web, ap_subdomain=ap_subdomain,
                              enabled_protocols=enabled_protocols, obj_as1={
                                  'objectType': 'person',
                                  'id': f'https://{domain}/',
                              })

        if did:
            self.make_atproto_copy(user, did)

        return user

    def make_atproto_copy(self, user, did):
        user.enabled_protocols = ['atproto']
        user.copies = [Target(uri=did, protocol='atproto')]
        user.put()

        Repo.create(self.storage, did, signing_key=ATPROTO_KEY)

        did_doc = copy.deepcopy(test_atproto.DID_DOC)
        did_doc['service'][0]['serviceEndpoint'] = ATProto.PDS_URL
        did_doc['id'] = did

        self.store_object(id=did, raw=did_doc)
        if user.obj.as1:
            profile_id = f'at://{did}/app.bsky.actor.profile/self'
            self.store_object(id=profile_id, bsky=bluesky.from_as1(user.obj.as1))
            user.obj.copies = [Target(uri=profile_id, protocol='atproto')]
            user.obj.put()

    def firehose(self, limit=1, **op):
        setup_firehose()
        FakeWebsocketClient.setup_receive(atproto_firehose.Op(**op))
        atproto_firehose.load_dids()
        atproto_firehose.subscribe()
        if limit:
            atproto_firehose.handle(limit=limit)
        assert atproto_firehose.commits.empty()

    @patch('requests.post')
    def test_atproto_post_to_activitypub(self, mock_post):
        """ATProto post, from firehose to ActivityPub.

        ATProto original post at://did:plc:alice/app.bsky.feed.post/123
        ActivityPub follower http://inst/bob
        """
        self.store_object(id='did:plc:alice', raw=DID_DOC)
        alice = self.make_user(
            id='did:plc:alice',
            cls=ATProto,
            enabled_protocols=['activitypub'],
            obj_bsky=test_atproto.ACTOR_PROFILE_BSKY,
            # make sure we handle our_as1 with profile id ok
            obj_as1={
                **test_atproto.ACTOR_AS,
                'id': 'at://did:plc:alice/app.bsky.actor.profile/self',
            })

        bob = self.make_ap_user('http://inst/bob')
        Follower.get_or_create(to=alice, from_=bob)

        # need at least one repo for firehose subscriber to load DIDs and run
        Repo.create(self.storage, 'did:unused', signing_key=ATPROTO_KEY)

        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'I hereby post',
        }
        self.firehose(repo='did:plc:alice', action='create', seq=123,
                      path='app.bsky.feed.post/123', record=post)

        self.assert_ap_deliveries(mock_post, ['http://inst/bob/inbox'],
                                  from_user=alice, data={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123#bridgy-fed-create',
            'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
            'published': '2022-01-02T03:04:05+00:00',
            'object': {
                'type': 'Note',
                'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123',
                'url': 'http://localhost/r/https://bsky.app/profile/did:plc:alice/post/123',
                'attributedTo': 'https://bsky.brid.gy/ap/did:plc:alice',
                'content': '<p>I hereby post</p>',
                'contentMap': {'en': '<p>I hereby post</p>'},
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        })

    @patch('requests.post')
    def test_atproto_reply_to_activitypub(self, mock_post):
        """ATProto reply, from firehose to ActivityPub.

        ActivityPub original post http://inst/post by bob
        ATProto reply 123 by alice.com (did:plc:alice)

        https://github.com/snarfed/bridgy-fed/issues/720
        """
        alice = self.make_atproto_user('did:plc:alice')
        bob = self.make_ap_user('http://inst/bob', 'did:plc:bob')

        self.store_object(id='http://inst/post', source_protocol='activitypub',
                          our_as1={
                              'objectType': 'note',
                              'author': 'http://inst/bob',
                          },
                          copies=[
            Target(uri='at://did:plc:bob/app.bsky.feed.post/123', protocol='atproto'),
        ])

        reply = {
            '$type': 'app.bsky.feed.post',
            'text': 'I hereby reply',
            'reply': {
                'root': {
                    'cid': '...',
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                },
                'parent': {
                    'cid': '...',
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                },
            },
        }
        self.firehose(repo='did:plc:alice', action='create', seq=456,
                      path='app.bsky.feed.post/456', record=reply)

        self.assert_ap_deliveries(mock_post, ['http://inst/bob/inbox'],
                                  from_user=alice, data={
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/456#bridgy-fed-create',
            'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
            'published': '2022-01-02T03:04:05+00:00',
            'object': {
                'type': 'Note',
                'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/456',
                'url': 'http://localhost/r/https://bsky.app/profile/did:plc:alice/post/456',
                'attributedTo': 'https://bsky.brid.gy/ap/did:plc:alice',
                'content': '<p>I hereby reply</p>',
                'contentMap': {'en': '<p>I hereby reply</p>'},
                'inReplyTo': 'http://inst/post',
                'tag': [{'type': 'Mention', 'href': 'http://inst/bob'}],
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
                'cc': ['http://inst/bob'],
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
            'cc': ['http://inst/bob'],
        })

    @patch('requests.post')
    def test_atproto_not_bridged_reply_to_activitypub(self, mock_post):
        """ATProto reply from a non-bridged user, from firehose to ActivityPub.

        Shouldn't be delivered.

        ActivityPub original post http://inst/post by bob
        ATProto reply 123 by alice.com (did:plc:alice)
        """
        alice = self.make_atproto_user('did:plc:alice', enabled_protocols=[])
        bob = self.make_ap_user('http://inst/bob', 'did:plc:bob')

        self.store_object(
            id='http://inst/post', source_protocol='activitypub',
            our_as1={'objectType': 'note', 'author': 'http://inst/bob'},
            copies=[Target(uri='at://did:plc:bob/app.bsky.feed.post/123',
                           protocol='atproto')]
        )

        reply = {
            '$type': 'app.bsky.feed.post',
            'text': 'I hereby reply',
            'reply': {
                'root': {
                    'cid': '...',
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                },
                'parent': {
                    'cid': '...',
                    'uri': 'at://did:plc:bob/app.bsky.feed.post/123',
                },
            },
        }
        self.firehose(limit=0, repo='did:plc:alice', action='create', seq=456,
                      path='app.bsky.feed.post/456', record=reply)
        self.assert_ap_deliveries(mock_post, [], data=None)

    @patch('requests.post', return_value=requests_response(''))
    @patch('requests.get', return_value=test_web.WEBMENTION_REL_LINK)
    def test_atproto_follow_of_web(self, mock_get, mock_post):
        """ATProto follow to Web.

        ATProto user alice.com (did:plc:alice)
        ATProto follow at://did:plc:alice/app.bsky.graph.follow/123
        Web user bob.com
        """
        # setup
        alice = self.make_atproto_user('did:plc:alice', enabled_protocols=['web'])

        Repo.create(self.storage, 'did:plc:bob', signing_key=ATPROTO_KEY)
        bob = self.make_user(id='bob.com', cls=Web,
                             copies=[Target(uri='did:plc:bob', protocol='atproto')],
                             enabled_protocols=['atproto'])

        follow = {
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:bob',
            'createdAt': '2022-01-02T03:04:05.000Z',
        }
        self.firehose(repo='did:plc:alice', action='create', seq=123,
                      path='app.bsky.graph.follow/123', record=follow)

        self.assert_req(mock_get, 'https://bob.com/')
        self.assert_req(mock_post, 'https://bob.com/webmention', data={
            'source': 'https://bsky.brid.gy/convert/web/at://did:plc:alice/app.bsky.graph.follow/123',
            'target': 'https://bob.com/',
        }, allow_redirects=False, headers={'Accept': '*/*'})

    @patch('dns.resolver.resolve', side_effect=NXDOMAIN())
    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    @patch('requests.post', side_effect=[
           requests_response('OK'),  # create DID
    ])
    @patch('requests.get', side_effect = [
        # webmention source page, follow HTML
        requests_response("""\
<html>
<body class="h-entry">
<a class="u-url" href="https://bob.com/follow"></a>
<a class="u-follow-of" href="https://bsky.app/profile/alice.com"></a>
<a href="http://localhost/"></a>
</body>
</html>
"""),
        # https://bob.com/ , for authorship
        requests_response("""\
<html>
<body class="h-card">
<a class="p-name u-url" rel="me" href="https://bob.com/">Bob</a>
</body>
</html>
"""),
        # alice.com handle resolution, HTTPS method
        requests_response('did:plc:alice', content_type='text/plain'),
        # alice profile
        requests_response(PROFILE_GETRECORD),
        # alice DID
        requests_response(DID_DOC),
        # alice profile
        requests_response(PROFILE_GETRECORD),
    ])
    def test_web_follow_of_atproto(self, mock_get, mock_post, _, __):
        """Incoming webmention for a web follow of an ATProto bsky.app profile URL.

        Web user bob.com
        ATProto user alice.com (did:plc:alice)
        Follow is HTML with mf2 u-follow-of of https://bsky.app/profile/alice.com
        """
        bob = self.make_user(id='bob.com', cls=Web, enabled_protocols=['atproto'],
                             last_webmention_in=NOW, obj_mf2={
                                 'type': ['h-card'],
                                 'properties': {
                                     'url': ['https://bob.com/'],
                                     'name': ['Bob'],
                                 },
                             })

        # send webmention
        resp = self.post('/webmention', data={
            'source': 'https://bob.com/follow',
            'target': 'http://localhost',
        })
        self.assertEqual(202, resp.status_code)

        # check results
        bob = bob.key.get()
        self.assertTrue(bob.is_enabled(ATProto))
        bob_did = bob.get_copy(ATProto)
        assert bob_did

        self.assertEqual({
            'type': ['h-entry'],
            'properties': {
                'url': ['https://bob.com/follow'],
                'follow-of': ['https://bsky.app/profile/alice.com'],
                'name': [''],
                'author': [{
                    'type': ['h-card'],
                    'properties': {
                        'name': ['Bob'],
                        'url': ['https://bob.com/'],
                    },
                }],
            },
        }, Object.get_by_id('https://bob.com/follow').mf2)

        repo = self.storage.load_repo('bob.com.web.brid.gy')
        self.assertEqual(bob_did, repo.did)

        records = repo.get_contents()
        self.assertEqual(['app.bsky.actor.profile',
                          'app.bsky.graph.follow',
                          'chat.bsky.actor.declaration'],
                         list(records.keys()))
        self.assertEqual(['self'], list(records['app.bsky.actor.profile'].keys()))
        self.assertEqual([{
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:alice',
            'createdAt': '2022-01-02T03:04:05.000Z',
        }], list(records['app.bsky.graph.follow'].values()))

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    @patch('requests.get', side_effect=[
        # getRecord of original post
        # alice profile
        requests_response({
            'uri': 'at://did:plc:alice/app.bsky.feed.post/123',
            'cid': 'sydd',
            'value': POST_BSKY,
        }),
    ])
    def test_activitypub_like_of_atproto(self, mock_get, _):
        """AP inbox delivery of a Like of an ATProto bsky.app profile URL.

        ActivityPub user @bob@inst , https://inst/bob
        ATProto user alice.com (did:plc:alice)
        Like is https://inst/like
        """
        self.make_atproto_user('did:plc:alice')
        self.make_ap_user('https://inst/bob', 'did:plc:bob')

        # existing Object with original post, *without* cid. we should generate.
        Object(id='at://did:plc:alice/app.bsky.feed.post/123', bsky=POST_BSKY).put()

        # inbox delivery
        like = {
            'type': 'Like',
            'id': 'http://inst/like',
            'actor': 'https://inst/bob',
            'object': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123',
        }
        body = json_dumps(like)
        headers = sign('/ap/atproto/did:plc:alice/inbox', body,
                       key_id='https://inst/bob')
        resp = self.client.post('/ap/atproto/did:plc:alice/inbox', data=body,
                                headers=headers)
        self.assertEqual(202, resp.status_code)

        # check results
        self.assertEqual(like, Object.get_by_id('http://inst/like').as2)

        repo = self.storage.load_repo('did:plc:bob')

        records = repo.get_contents()
        self.assertEqual(['app.bsky.feed.like'], list(records.keys()))
        self.assertEqual([{
            '$type': 'app.bsky.feed.like',
            'subject': {
                'uri': 'at://did:plc:alice/app.bsky.feed.post/123',
                'cid': dag_cbor_cid(POST_BSKY).encode('base32'),
            },
            'createdAt': '2022-01-02T03:04:05.000Z',
        }], list(records['app.bsky.feed.like'].values()))

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    @patch('requests.post')  # to receive "you're not bridged" DM
    def test_activitypub_not_bridged_reply_to_atproto(self, mock_get, mock_post):
        """AP inbox delivery of a reply from an unbridged user to an ATProto post.

        ActivityPub user @bob@inst , https://inst/bob
        ATProto user alice.com (did:plc:alice)
        Reply is https://inst/reply
        """
        self.make_atproto_user('did:plc:alice')
        self.make_ap_user('https://inst/bob')
        self.make_user(id='bsky.brid.gy', cls=Web, ap_subdomain='bsky')

        # existing Object with original post, with cid
        Object(id='at://did:plc:alice/app.bsky.feed.post/123', bsky={
            **POST_BSKY,
            'cid': 'bafyfoo',
        }).put()

        # inbox delivery
        reply = {
            'type': 'Note',
            'id': 'http://inst/reply',
            'attributedTo': 'https://inst/bob',
            'inReplyTo': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123',
            'content': 'I hereby reply',
        }
        body = json_dumps(reply)
        headers = sign('/ap/atproto/did:plc:alice/inbox', body,
                       key_id='https://inst/bob')
        resp = self.client.post('/ap/atproto/did:plc:alice/inbox', data=body,
                                headers=headers)
        self.assertEqual(204, resp.status_code)

        # check results
        self.assertEqual([], self.storage.load_repos())

    @patch('requests.post', return_value=requests_response('OK'))  # create DID
    @patch('requests.get')
    def test_activitypub_follow_bsky_bot_user_enables_protocol(self, mock_get, mock_post):
        """AP follow of @bsky.brid.gy@bsky.brid.gy bridges the account into Bluesky.

        ActivityPub user @alice@inst , https://inst/alice
        ATProto bot user bsky.brid.gy (did:plc:bsky)
        Follow is https://inst/follow
        """
        actor = mock_get.return_value = self.as2_resp(add_key({
            'type': 'Person',
            'id': 'https://inst/alice',
            'name': 'Mrs. ☕ Alice',
            'preferredUsername': 'alice',
            'inbox': 'http://inst/inbox',
            'image': 'http://pic',
        }))
        mock_get.side_effect = [
            actor,
            actor,
            actor,
            requests_response('blob', headers={'Content-Type': 'image/jpeg'}),
        ]

        self.make_user(id='bsky.brid.gy', cls=Web, ap_subdomain='bsky')

        # deliver follow
        body = json_dumps({
            'type': 'Follow',
            'id': 'http://inst/follow',
            'actor': 'https://inst/alice',
            'object': 'https://bsky.brid.gy/bsky.brid.gy',
        })
        headers = sign('/bsky.brid.gy/inbox', body, key_id='https://inst/alice')
        resp = self.client.post('/bsky.brid.gy/inbox', data=body, headers=headers)
        self.assertEqual(204, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/alice')
        self.assertTrue(user.is_enabled(ATProto))
        self.assertEqual([DM(protocol='atproto', type='welcome')], user.sent_dms)

        self.assertEqual(1, len(user.copies))
        self.assertEqual('atproto', user.copies[0].protocol)
        did = user.copies[0].uri

        repo = self.storage.load_repo('alice.inst.ap.brid.gy')
        self.assertEqual(did, repo.did)

        records = repo.get_contents()
        self.assertEqual(['app.bsky.actor.profile', 'chat.bsky.actor.declaration'],
                         list(records.keys()))
        self.assertEqual(['self'], list(records['app.bsky.actor.profile'].keys()))

        # bot user DM
        args, kwargs = mock_post.call_args_list[1]
        self.assert_equals(('http://inst/inbox',), args)
        message = """\
<p>Welcome to Bridgy Fed! Your account will soon be bridged to Bluesky at <a class="h-card u-author" rel="me" href="https://bsky.app/profile/alice.inst.ap.brid.gy" title="alice.inst.ap.brid.gy">alice.inst.ap.brid.gy</a>. <a href="https://fed.brid.gy/docs">See the docs</a> and <a href="https://fed.brid.gy/ap/@alice@inst">your user page</a> for more information. To disable this and delete your bridged profile, block this account.</p>"""
        self.assert_equals({
            'type': 'Create',
            'id': 'https://bsky.brid.gy/r/https://bsky.brid.gy/#bridgy-fed-dm-welcome-https://inst/alice-2022-01-02T03:04:05+00:00-create',
            'actor': 'https://bsky.brid.gy/bsky.brid.gy',
            'object': {
                'type': 'Note',
                'id': 'https://bsky.brid.gy/r/https://bsky.brid.gy/#bridgy-fed-dm-welcome-https://inst/alice-2022-01-02T03:04:05+00:00',
                'attributedTo': 'https://bsky.brid.gy/bsky.brid.gy',
                'content': message,
                'contentMap': {'en': message},
                    'tag': [{
                    'type': 'Mention',
                    'href': 'https://inst/alice',
                }],
                'published': '2022-01-02T03:04:05+00:00',
                'to': ['https://inst/alice'],
            },
            'published': '2022-01-02T03:04:05+00:00',
            'to': ['https://inst/alice'],
        }, json_loads(kwargs['data']), ignore=['@context'])

        # bot user follows back
        args, kwargs = mock_post.call_args_list[2]
        self.assert_equals(('http://inst/inbox',), args)
        self.assert_equals({
            'type': 'Follow',
            'id': 'https://bsky.brid.gy/r/https://bsky.brid.gy/#follow-back-https://inst/alice-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/bsky.brid.gy',
            'object': 'https://inst/alice',
        }, json_loads(kwargs['data']), ignore=['to', '@context'])

        # accept user's follow
        args, kwargs = mock_post.call_args_list[3]
        self.assert_equals(('http://inst/inbox',), args)
        self.assert_equals({
            'type': 'Accept',
            'id': 'https://bsky.brid.gy/r/bsky.brid.gy/followers#accept-http://inst/follow',
            'actor': 'https://bsky.brid.gy/bsky.brid.gy',
            'object': {
                'actor': 'https://inst/alice',
                'id': 'http://inst/follow',
                'url': 'https://inst/alice#followed-bsky.brid.gy',
                'type': 'Follow',
                'object': 'https://bsky.brid.gy/bsky.brid.gy',
            },
        }, json_loads(kwargs['data']), ignore=['to', '@context'])

    @patch('requests.get')
    def test_activitypub_follow_bsky_bot_bad_username_error(self, mock_get):
        """AP follow of @bsky.brid.gy@bsky.brid.gy from bad username fails.

        ActivityPub user @_alice_@inst , https://inst/_alice_
        ATProto bot user bsky.brid.gy (did:plc:bsky)
        Follow is https://inst/follow
        """
        mock_get.return_value = self.as2_resp(add_key({
            'type': 'Person',
            'id': 'https://inst/_alice_',
            'name': 'Mrs. ☕ Alice',
            'preferredUsername': '_alice_',
            'image': 'http://pic',
            'inbox': 'http://inst/inbox',
        }))
        self.make_user(id='bsky.brid.gy', cls=Web, ap_subdomain='bsky')

        # deliver follow
        body = json_dumps({
            'type': 'Follow',
            'id': 'http://inst/follow',
            'actor': 'https://inst/_alice_',
            'object': 'https://bsky.brid.gy/bsky.brid.gy',
        })
        headers = sign('/bsky.brid.gy/inbox', body, key_id='https://inst/_alice_')
        resp = self.client.post('/bsky.brid.gy/inbox', data=body, headers=headers)
        self.assertEqual(299, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/_alice_', allow_opt_out=True)
        self.assertFalse(user.is_enabled(ATProto))
        self.assertEqual(0, len(user.copies))

    @patch('requests.post', return_value=requests_response({  # sendMessage
        'id': 'chat456',
        'rev': '22222222tef2d',
        # ...
    }))
    @patch('requests.get', side_effect=[
        requests_response(DID_DOC),  # alice DID
        requests_response(PROFILE_GETRECORD),  # alice profile
        requests_response(PROFILE_GETRECORD),  # alice profile
        requests_response({  # getConvoForMembers
            'convo': {
                'id': 'convo123',
                'rev': '22222222fuozt',
                'members': [],
                'muted': False,
                'unreadCount': 0,
            },
        }),
    ])
    def test_atproto_follow_ap_bot_user_enables_protocol(self, mock_get, mock_post):
        """ATProto follow of @ap.brid.gy enables the ActivityPub protocol.

        ATProto user alice.com, did:plc:alice
        ActivityPub bot user @ap.brid.gy, did:plc:ap
        """
        self.make_web_user('ap.brid.gy', did='did:plc:ap')
        # only needed for atproto_firehose.load_dids
        self.make_atproto_user('did:plc:eve')

        # existing stale stored DID doc for alice, should be reloaded and overwritten
        self.store_object(id='did:plc:alice', raw={'not': 'used'})

        follow = {
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:ap',
        }
        self.firehose(repo='did:plc:alice', action='create', seq=123,
                      path='app.bsky.graph.follow/123', record=follow)

        user = ATProto.get_by_id('did:plc:alice')
        self.assertTrue(user.is_enabled(ActivityPub))
        self.assertEqual([DM(protocol='activitypub', type='welcome')],
                         user.sent_dms)

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': common.USER_AGENT,
            'Authorization': ANY,
        }
        mock_get.assert_any_call(
            'https://chat.local/xrpc/chat.bsky.convo.getConvoForMembers?members=did%3Aplc%3Aalice',
            json=None, data=None, headers=headers)
        mock_post.assert_called_with(
            'https://chat.local/xrpc/chat.bsky.convo.sendMessage',
            json={
                'convoId': 'convo123',
                'message': {
                    '$type': 'chat.bsky.convo.defs#messageInput',
                    'text': 'Welcome to Bridgy Fed! Your account will soon be bridged to the fediverse at @alice.com@bsky.brid.gy. See the docs and your user page for more information. To disable this and delete your bridged profile, block this account.',
                    'facets': [{
                        '$type': 'app.bsky.richtext.facet',
                        'index': {'byteStart': 102, 'byteEnd': 114},
                        'features': [{
                            '$type': 'app.bsky.richtext.facet#link',
                            'uri': 'https://fed.brid.gy/docs',
                        }],
                    }, {
                        '$type': 'app.bsky.richtext.facet',
                        'index': {'byteStart': 119, 'byteEnd': 133},
                        'features': [{
                            '$type': 'app.bsky.richtext.facet#link',
                            'uri': 'https://fed.brid.gy/bsky/alice.com',
                        }],
                    }],
                    'createdAt': '2022-01-02T03:04:05.000Z',
                    'bridgyOriginalText': 'Welcome to Bridgy Fed! Your account will soon be bridged to the fediverse at @alice.com@bsky.brid.gy. <a href="https://fed.brid.gy/docs">See the docs</a> and <a href="https://fed.brid.gy/bsky/alice.com">your user page</a> for more information. To disable this and delete your bridged profile, block this account.',
                    'bridgyOriginalUrl': 'https://ap.brid.gy/#bridgy-fed-dm-welcome-did:plc:alice-2022-01-02T03:04:05+00:00',
                },
            }, data=None, headers=headers)

    @patch('requests.post')
    @patch('requests.get')
    def test_atproto_block_ap_bot_user_disables_protocol_deletes_actor(
            self, mock_get, mock_post):
        """Bluesky user blocks ap.brid.gy: disables protocol, deletes their AP actor.

        ATProto user alice.com, did:plc:alice
        """
        self.make_web_user('ap.brid.gy', did='did:plc:ap')
        alice = self.make_atproto_user('did:plc:alice')
        Follower.get_or_create(to=alice, from_=self.make_ap_user('http://x/bob'))
        Follower.get_or_create(to=alice, from_=self.make_ap_user('http://y/eve'))

        block = {
            '$type': 'app.bsky.graph.block',
            'subject': 'did:plc:ap',
            'createdAt': '2022-01-02T03:04:05.000Z'
        }
        self.firehose(repo='did:plc:alice', action='create', seq=123,
                      path='app.bsky.graph.block/123', record=block)

        self.assertEqual(2, mock_post.call_count)
        args, kwargs = mock_post.call_args_list
        self.assertEqual([('http://x/bob/inbox',), ('http://y/eve/inbox',)],
                         [args for args, _ in mock_post.call_args_list])

        for _, kwargs in mock_post.call_args_list:
            self.assert_equals({
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Delete',
                'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.actor.profile/self#bridgy-fed-delete-user-activitypub-2022-01-02T03:04:05+00:00',
                'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
                'object': 'https://bsky.brid.gy/ap/did:plc:alice',
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
            }, json_loads(kwargs['data']))

    @patch('requests.get', side_effect=[
        requests_response('blob', headers={'Content-Type': 'image/jpeg'}), # http://pic/
    ])
    def test_activitypub_block_bsky_bot_user_deactivates_atproto_repo(self, mock_get):
        """AP Block of @bsky.brid.gy@bsky.brid.gy deactivates the Bluesky repo.

        ActivityPub user @alice@inst , https://inst/alice , did:plc:alice
        Block is https://inst/block
        """
        self.make_ap_user('https://inst/alice', 'did:plc:alice')
        self.make_user(id='bsky.brid.gy', cls=Web, ap_subdomain='bsky')

        # deliver block
        body = json_dumps({
            'type': 'Block',
            'id': 'http://inst/block',
            'actor': 'https://inst/alice',
            'object': 'https://bsky.brid.gy/bsky.brid.gy',
        })
        headers = sign('/bsky.brid.gy/inbox', body, key_id='https://inst/alice')
        resp = self.client.post('/bsky.brid.gy/inbox', data=body, headers=headers)
        self.assertEqual(200, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/alice')
        self.assertFalse(user.is_enabled(ATProto))

        self.assertEqual('deactivated', self.storage.load_repo('did:plc:alice').status)

    @patch('requests.get', side_effect=[
        requests_response('blob', headers={'Content-Type': 'image/jpeg'}), # http://pic/
    ])
    def test_activitypub_delete_user_deactivates_atproto_repo(self, mock_get):
        """AP Delete of user deactivates the Bluesky repo.

        ActivityPub user @alice@inst , https://inst/alice , did:plc:alice
        Delete is https://inst/block
        """
        user = self.make_ap_user('https://inst/alice', 'did:plc:alice')
        self.assertTrue(user.is_enabled(ATProto))

        # deliver delete
        body = json_dumps({
            'type': 'Delete',
            'id': 'http://inst/block',
            'actor': 'https://inst/alice',
            'object': 'https://inst/alice',
        })
        headers = sign('/ap/sharedInbox', body, key_id='https://inst/alice')
        resp = self.client.post('/ap/sharedInbox', data=body, headers=headers)
        self.assertEqual(202, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/alice')
        self.assertFalse(user.is_enabled(ATProto))

        self.assertEqual('deactivated', self.storage.load_repo('did:plc:alice').status)

    @patch('requests.post', return_value=requests_response(''))
    @patch('requests.get', return_value=requests_response("""\
<html>
  <body class="h-card"><a rel="me" href="/">me</a> #nobridge</body>
</html>""", url='https://alice.com/'))
    def test_web_nobridge_update_profile_deletes_user_deactivates_atproto_repo(
            self, mock_get, mock_post):
        """Web user adds #nobridge and updates their profile.

        Should delete their bridged accounts.

        Web user alice.com, did:plc:alice
        ActivityPub user bob@inst, https://inst/bob,
        """
        # users
        alice = self.make_web_user('alice.com', 'did:plc:alice')
        self.assertTrue(alice.is_enabled(ATProto))
        self.assertTrue(alice.is_enabled(ActivityPub))

        bob = self.make_ap_user('https://inst/bob')
        Follower.get_or_create(to=alice, from_=bob)

        # update profile
        resp = self.client.post('/web/alice.com/update-profile')
        self.assertEqual(302, resp.status_code)

        # should be deleted everywhere
        self.assertEqual('nobridge', alice.key.get().status)

        self.assertEqual('deactivated', self.storage.load_repo('did:plc:alice').status)

        self.assertEqual(1, mock_post.call_count)
        args, kwargs = mock_post.call_args
        self.assertEqual((bob.obj.as2['inbox'],), args)
        self.assert_equals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Delete',
            'id': 'http://localhost/r/https://alice.com/#bridgy-fed-delete-user-all-2022-01-02T03:04:05+00:00',
            'actor': 'http://localhost/alice.com',
            'object': 'http://localhost/alice.com',
        }, json_loads(kwargs['data']), ignore=['@context', 'contentMap', 'to', 'cc'])

    @patch('requests.post', return_value=requests_response(''))
    @patch('requests.get', return_value=requests_response("""\
<html><body class="h-card">
  <a class="u-url" href="/"></a>
  <a class="u-url" href="acct:fooey@alice.com"></a>
</body></html>""", url='https://alice.com/'))
    def test_web_acct_url_update_profile_gets_custom_username(
            self, mock_get, mock_post):
        """Web user has an acct: u-url and updates their profile.

        We should see it and use it as a custom username.

        Web user alice.com
        """
        alice = self.make_web_user('alice.com', None)
        alice.has_redirects = True
        alice.put()
        self.assertTrue(alice.is_enabled(ActivityPub))

        bob = self.make_ap_user('https://inst/bob')
        Follower.get_or_create(to=alice, from_=bob)

        # update profile
        resp = self.client.post('/web/alice.com/update-profile')
        self.assertEqual(302, resp.status_code)

        alice = alice.key.get()
        self.assertEqual('fooey', alice.username())
        self.assertEqual('@fooey@alice.com', alice.handle_as(ActivityPub))

    @patch('requests.post')
    @patch('requests.get')
    def test_atproto_mention_activitypub(self, mock_get, mock_post):
        """Bluesky @-mention of *.ap.brid.gy user.

        ATProto user alice.com, did:plc:alice
        ActivityPub user bob@inst, https://inst/bob, bob.inst.ap.brid.gy, did:plc:bob
        """
        alice = self.make_atproto_user('did:plc:alice')
        bob = self.make_ap_user('https://inst/bob', 'did:plc:bob')

        post = {
            '$type': 'app.bsky.feed.post',
            'text': 'maybe if @bob.inst.ap.brid.gy and Alf meet up',
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:plc:bob',
                }],
                'index': {
                    'byteEnd': 29,
                    'byteStart': 9,
                },
            }],
        }
        self.firehose(repo='did:plc:alice', action='create', seq=123,
                      path='app.bsky.feed.post/123', record=post)

        self.assertEqual(1, mock_post.call_count)
        args, kwargs = mock_post.call_args
        self.assertEqual((bob.obj.as2['inbox'],), args)
        self.assert_equals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123#bridgy-fed-create',
            'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
            'published': '2022-01-02T03:04:05+00:00',
            'object': {
                'type': 'Note',
                'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.feed.post/123',
                'url': 'http://localhost/r/https://bsky.app/profile/did:plc:alice/post/123',
                'attributedTo': 'https://bsky.brid.gy/ap/did:plc:alice',
                'content': '<p>maybe if <a class="mention" href="https://inst/bob">@bob.inst.ap.brid.gy</a> and Alf meet up</p>',
                'tag': [{
                    'type': 'Mention',
                    'name': '@bob.inst.ap.brid.gy',
                    'href': 'https://inst/bob',
                }],
            },
        }, json_loads(kwargs['data']), ignore=['@context', 'contentMap', 'to', 'cc'])

    @patch('requests.post')
    @patch('requests.get')
    def test_atproto_undo_block_of_activitypub(self, mock_get, mock_post):
        """Bluesky undo of a block of an AP user.

        ATProto user alice.com, did:plc:alice
        ActivityPub user bob@inst, https://inst/bob, bob.inst.ap.brid.gy, did:plc:bob
        """
        alice = self.make_atproto_user('did:plc:alice')
        bob = self.make_ap_user('https://inst/bob', 'did:plc:bob')

        o = self.store_object(id='at://did:plc:alice/app.bsky.graph.block/123',
                              source_protocol='atproto', our_as1={
                                  'objectType': 'activity',
                                  'verb': 'block',
                                  'id': 'at://did:plc:alice/app.bsky.graph.block/123',
                                  'object': 'https://inst/bob',
                                  'actor': 'did:plc:alice',
                              })

        self.firehose(repo='did:plc:alice', action='delete', seq=123,
                      path='app.bsky.graph.block/123')

        self.assertEqual(1, mock_post.call_count)
        args, kwargs = mock_post.call_args
        self.assertEqual((bob.obj.as2['inbox'],), args)
        self.assert_equals({
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Undo',
            'id': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.graph.block/123#undo',
            'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
            'object': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.graph.block/123',
        }, json_loads(kwargs['data']), ignore=['@context', 'contentMap', 'to', 'cc'])

    @patch('requests.post', side_effect=[
        requests_response('OK'),       # create DID
        requests_response({'id': 3}),  # createReport
    ])
    @patch('requests.get', side_effect=[
        requests_response(PROFILE_GETRECORD),
        requests_response(DID_DOC),
    ])
    def test_activitypub_server_actor_flag_to_atproto_report(
            self, mock_get, mock_post):
        """AP Flag activity from server actor translates to Bluesky report.

        ActivityPub user @actor@inst , https://inst/actor , did:plc:actor
          creates new ATProto repo for them
        """
        self.make_user(id='https://inst/actor', cls=ActivityPub,
                       obj_as2=add_key({
                           'type': 'Person',
                           'id': 'https://inst/actor',
                           'preferredUsername': 'inst',
                       }))

        # deliver flag
        body = json_dumps({
            'type': 'Flag',
            'id': 'http://inst/flag',
            'actor': 'https://inst/actor',
            'object': 'https://bsky.brid.gy/convert/ap/at://did:plc:alice/app.bsky.actor.profile/self',
        })
        headers = sign('/bsky.brid.gy/inbox', body, key_id='https://inst/actor')
        resp = self.client.post('/bsky.brid.gy/inbox', data=body, headers=headers)
        self.assertEqual(202, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/actor')
        self.assertTrue(user.is_enabled(ATProto))

        mock_post.assert_called_with(
            'https://mod.service.local/xrpc/com.atproto.moderation.createReport',
            json={
                '$type': 'com.atproto.moderation.createReport#input',
                'reasonType': 'com.atproto.moderation.defs#reasonOther',
                'reason': '',
                'subject': {
                    '$type': 'com.atproto.repo.strongRef',
                    'uri': 'at://did:plc:alice/app.bsky.actor.profile/self',
                    'cid': 'alice+sidd',
                },
            }, data=None, headers=ANY)

    def test_atproto_convert_hashtag_to_activitypub_preserves_bsky_app_link(self):
        obj = Object(id='at://xyz', bsky={
            '$type': 'app.bsky.feed.post',
            'text': 'My #original post',
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#tag',
                    'tag': 'original',
                }],
                'index': {
                    'byteStart': 3,
                    'byteEnd': 12,
                },
            }],
        })
        self.assert_equals({
            'type': 'Note',
            'id': 'https://bsky.brid.gy/convert/ap/at://xyz',
            'content': '<p>My <a class="hashtag" href="https://bsky.app/search?q=%23original">#original</a> post</p>',
            'contentMap': {
                'en': '<p>My <a class="hashtag" href="https://bsky.app/search?q=%23original">#original</a> post</p>',
            },
            'url': 'http://localhost/r/https://bsky.app/profile/xyz',
            'tag': [{
                'type': 'Hashtag',
                'name': '#original',
                'href': 'https://bsky.app/search?q=%23original',
            }],
        }, ActivityPub.convert(obj), ignore=['@context', 'attributedTo', 'to'])

    def test_convert_with_html_content_from_atproto_to_activitypub(self):
        obj = Object(id='at://xyz', source_protocol='atproto', bsky={
            '$type': 'app.bsky.feed.post',
            'text': '#foo bar @baz',
            'langs': ['en'],
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#tag',
                    'tag': 'foo',
                }],
                'index': {
                    'byteStart': 0,
                    'byteEnd': 4,
                },
            }, {
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#link',
                    'uri': 'http://bar',
                }],
                'index': {
                    'byteStart': 5,
                    'byteEnd': 8,
                },
            }, {
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:plc:baz',
                }],
                'index': {
                    'byteStart': 9,
                    'byteEnd': 13,
                },
            }],
        })

        expected = {
            'type': 'Note',
            'id': 'https://bsky.brid.gy/convert/ap/at://xyz',
            'url': 'http://localhost/r/https://bsky.app/profile/xyz',
            'attributedTo': 'xyz',
            'content': '<p><a class="hashtag" href="https://bsky.app/search?q=%23foo">#foo</a> <a href="http://bar">bar</a> <a class="mention" href="https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:baz">@baz</a></p>',
            'contentMap': {
                'en': '<p><a class="hashtag" href="https://bsky.app/search?q=%23foo">#foo</a> <a href="http://bar">bar</a> <a class="mention" href="https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:baz">@baz</a></p>',
            },
            'tag': [{
                'type': 'Hashtag',
                'name': '#foo',
                'href': 'https://bsky.app/search?q=%23foo',
            }, {
                'type': 'Article',
                'name': 'bar',
                'url': 'http://bar',
            }, {
                'type': 'Mention',
                'name': '@baz',
                'href': 'https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:baz',
            }],
        }
        self.assert_equals(expected, ActivityPub.convert(obj),
                           ignore=['@context', 'to'])

    def test_convert_quote_with_html_content_from_atproto_to_activitypub(self):
        obj = Object(id='at://xyz', source_protocol='atproto', bsky={
            '$type': 'app.bsky.feed.post',
            'text': "a @b c",
            'langs': ['en'],
            'embed': {
                '$type': 'app.bsky.embed.record',
                'record': {
                    'cid': 'bafyfoo',
                    'uri': 'at://did:plc:abc/app.bsky.feed.post/123',
                },
            },
            'facets': [{
                '$type': 'app.bsky.richtext.facet',
                'features': [{
                    '$type': 'app.bsky.richtext.facet#mention',
                    'did': 'did:plc:def',
                }],
                'index': {
                    'byteStart': 2,
                    'byteEnd': 4,
                },
            }],
        })

        expected = {
            'type': 'Note',
            'id': 'https://bsky.brid.gy/convert/ap/at://xyz',
            'url': 'http://localhost/r/https://bsky.app/profile/xyz',
            'attributedTo': 'xyz',
            'content': '<p>a <a class="mention" href="https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:def">@b</a> c<br><br>RE: <a href="https://bsky.app/profile/did:plc:abc/post/123">https://bsky.app/profile/did:plc:abc/post/123</a></p>',
            'contentMap': {
                'en': '<p>a <a class="mention" href="https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:def">@b</a> c<br><br>RE: <a href="https://bsky.app/profile/did:plc:abc/post/123">https://bsky.app/profile/did:plc:abc/post/123</a></p>',
            },
            'quoteUrl': 'https://bsky.brid.gy/convert/ap/at://did:plc:abc/app.bsky.feed.post/123',
            '_misskey_quote': 'https://bsky.brid.gy/convert/ap/at://did:plc:abc/app.bsky.feed.post/123',
            'tag': [{
                'type': 'Mention',
                'name': '@b',
                'href': 'https://bsky.brid.gy/ap/https://bsky.app/profile/did:plc:def',
            }, {
                'type': 'Link',
                'href': 'https://bsky.brid.gy/convert/ap/at://did:plc:abc/app.bsky.feed.post/123',
                'name': 'RE: https://bsky.app/profile/did:plc:abc/post/123',
                'mediaType': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          }],
        }
        self.assert_equals(expected, ActivityPub.convert(obj),
                           ignore=['@context', 'to'])
