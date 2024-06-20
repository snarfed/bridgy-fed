"""Integration tests."""
import copy
from unittest.mock import patch

from arroba.datastore_storage import DatastoreStorage
from arroba.repo import Repo
from arroba.util import dag_cbor_cid
from dns.resolver import NXDOMAIN
from granary import as2, bluesky
from granary.tests.test_bluesky import ACTOR_PROFILE_BSKY, POST_BSKY
from oauth_dropins.webutil.flask_util import NoContent
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

from activitypub import ActivityPub
import app
from atproto import ATProto, Cursor
from atproto_firehose import handle, new_commits, Op
from models import Follower, Object, Target
from web import Web

from .testutil import ATPROTO_KEY, TestCase
from .test_activitypub import ACTOR, add_key, sign
from . import test_atproto
from . import test_web

DID_DOC = {
    **test_atproto.DID_DOC,
    'id': 'did:plc:alice',
    'alsoKnownAs': ['at://alice.com'],
}
PROFILE_GETRECORD = {
    'uri': 'at://did:plc:alice/app.bsky.actor.profile/self',
    'cid': 'alice sidd',
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
                              enabled_protocols=enabled_protocols)
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
            self.store_object(id=f'at://{did}/app.bsky.actor.profile/self',
                              bsky=bluesky.from_as1(user.obj.as1))


    @patch('requests.post')
    def test_atproto_notify_reply_to_activitypub(self, mock_post):
        """ATProto poll notifications, deliver reply to ActivityPub.

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
        new_commits.put(Op(repo='did:plc:alice', action='create', seq=456,
                           path='app.bsky.feed.post/456', record=reply))
        Cursor(id='bgs.local com.atproto.sync.subscribeRepos').put()
        handle(limit=1)

        web_test = test_web.WebTest()
        web_test.user = alice
        web_test.assert_deliveries(mock_post, ['http://inst/bob/inbox'], data={
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
                'content_is_html': True,
                'inReplyTo': 'http://inst/post',
                'tag': [{'type': 'Mention', 'href': 'http://inst/bob'}],
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
                'cc': ['http://inst/bob'],
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        })


    @patch('requests.post', return_value=requests_response(''))
    @patch('requests.get', return_value=test_web.WEBMENTION_REL_LINK)
    def test_atproto_follow_to_web(self, mock_get, mock_post):
        """ATProto poll notifications, deliver follow to Web.

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
        new_commits.put(Op(repo='did:plc:alice', action='create', seq=123,
                           path='app.bsky.graph.follow/123', record=follow))
        Cursor(id='bgs.local com.atproto.sync.subscribeRepos').put()
        handle(limit=1)

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
                             obj_mf2={
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
        self.assertEqual(1, len(bob.copies))
        self.assertEqual('atproto', bob.copies[0].protocol)
        bob_did = bob.copies[0].uri

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
        self.assertEqual({
            **like,
            # TODO: stop normalizing this in the original protocol's data
            'object': 'at://did:plc:alice/app.bsky.feed.post/123',
        }, Object.get_by_id('http://inst/like').as2)

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


    @patch('requests.post', return_value=requests_response('OK'))  # create DID
    @patch('requests.get')
    def test_activitypub_follow_bsky_bot_user_enables_protocol(self, mock_get, mock_post):
        """AP follow of @bsky.brid.gy@bsky.brid.gy bridges the account into BLuesky.

        ActivityPub user @alice@inst , https://inst/alice
        ATProto bot user bsky.brid.gy (did:plc:bsky)
        Follow is https://inst/follow
        """
        mock_get.return_value = self.as2_resp(add_key({
            'type': 'Person',
            'id': 'https://inst/alice',
            'name': 'Mrs. ☕ Alice',
            'preferredUsername': 'alice',
            'inbox': 'http://inst/inbox',
            'image': 'http://pic',
        }))
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

        self.assertEqual(1, len(user.copies))
        self.assertEqual('atproto', user.copies[0].protocol)
        did = user.copies[0].uri

        repo = self.storage.load_repo('alice.inst.ap.brid.gy')
        self.assertEqual(did, repo.did)

        records = repo.get_contents()
        self.assertEqual(['app.bsky.actor.profile', 'chat.bsky.actor.declaration'],
                         list(records.keys()))
        self.assertEqual(['self'], list(records['app.bsky.actor.profile'].keys()))

        # bot user follows back
        args, kwargs = mock_post.call_args_list[1]
        self.assert_equals(('http://inst/inbox',), args)
        self.assert_equals({
            'type': 'Follow',
            'id': 'https://bsky.brid.gy/r/https://bsky.brid.gy/#follow-back-https://inst/alice-2022-01-02T03:04:05+00:00',
            'actor': 'https://bsky.brid.gy/bsky.brid.gy',
            'object': 'https://inst/alice',
        }, json_loads(kwargs['data']), ignore=['to', '@context'])

        # accept user's follow
        args, kwargs = mock_post.call_args_list[2]
        self.assert_equals(('http://inst/inbox',), args)
        self.assert_equals({
            'type': 'Accept',
            'id': 'http://localhost/r/bsky.brid.gy/followers#accept-http://inst/follow',
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
            'inbox': 'http://inst/inbox',
        }))
        self.make_user(id='bsky.brid.gy', cls=Web, ap_subdomain='bsky')

        # deliver follow
        body = json_dumps({
            'type': 'Follow',
            'id': 'http://inst/follow',
            'actor': 'https://inst/_alice_',
            'object': 'https://bsky.brid.gy/bsky.brid.gy',
            'image': 'http://pic',
        })
        headers = sign('/bsky.brid.gy/inbox', body, key_id='https://inst/_alice_')
        resp = self.client.post('/bsky.brid.gy/inbox', data=body, headers=headers)
        self.assertEqual(304, resp.status_code)

        # check results
        user = ActivityPub.get_by_id('https://inst/_alice_', allow_opt_out=True)
        self.assertFalse(user.is_enabled(ATProto))
        self.assertEqual(0, len(user.copies))


    @patch('requests.get', side_effect=[
        requests_response(DID_DOC),  # alice DID
        requests_response(PROFILE_GETRECORD),  # alice profile
        requests_response(PROFILE_GETRECORD),  # ...
    ])
    def test_atproto_follow_ap_bot_user_enables_protocol(self, mock_get):
        """ATProto follow of @ap.brid.gy enables the ActivityPub protocol.

        ATProto user alice.com, did:plc:alice
        ActivityPub bot user @ap.brid.gy, did:plc:ap
        """
        self.make_web_user('ap.brid.gy', did='did:plc:ap')

        follow = {
            '$type': 'app.bsky.graph.follow',
            'subject': 'did:plc:ap',
        }
        new_commits.put(Op(repo='did:plc:alice', action='create', seq=123,
                           path='app.bsky.graph.follow/123', record=follow))
        Cursor(id='bgs.local com.atproto.sync.subscribeRepos').put()
        handle(limit=1)

        user = ATProto.get_by_id('did:plc:alice')
        self.assertTrue(user.is_enabled(ActivityPub))


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
        new_commits.put(Op(repo='did:plc:alice', action='create', seq=123,
                           path='app.bsky.graph.block/123', record=block))
        Cursor(id='bgs.local com.atproto.sync.subscribeRepos').put()

        handle(limit=1)

        self.assertEqual(2, mock_post.call_count)
        args, kwargs = mock_post.call_args_list
        self.assertEqual([('http://x/bob/inbox',), ('http://y/eve/inbox',)],
                         [args for args, _ in mock_post.call_args_list])

        for _, kwargs in mock_post.call_args_list:
            self.assert_equals({
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Delete',
                'id': 'https://bsky.brid.gy/convert/ap/did:plc:alice#delete-copy-activitypub-2022-01-02T03:04:05+00:00',
                'actor': 'https://bsky.brid.gy/ap/did:plc:alice',
                'object': 'https://bsky.brid.gy/ap/did:plc:alice',
                'to': ['https://www.w3.org/ns/activitystreams#Public'],
            }, json_loads(kwargs['data']))


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
        new_commits.put(Op(repo='did:plc:alice', action='create', seq=123,
                           path='app.bsky.feed.post/123', record=post))
        Cursor(id='bgs.local com.atproto.sync.subscribeRepos').put()
        handle(limit=1)

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
                'content': '<p>maybe if <a href="https://inst/bob">@bob.inst.ap.brid.gy</a> and Alf meet up</p>',
                'content_is_html': True,
                'tag': [{
                    'type': 'Mention',
                    'name': '@bob.inst.ap.brid.gy',
                    'href': 'https://inst/bob',
                }],
            },
        }, json_loads(kwargs['data']), ignore=['@context', 'contentMap', 'to', 'cc'])
