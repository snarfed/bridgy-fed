# coding=utf-8
"""Unit tests for webmention.py."""
import copy
from unittest.mock import patch
from urllib.parse import urlencode

import feedparser
from flask import g, get_flashed_messages
from granary import as1, as2, atom, microformats2
from httpsig.sign import HeaderSigner
from oauth_dropins.webutil import appengine_config, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway, BadRequest

# import first so that Fake is defined before URL routes are registered
from . import testutil

import activitypub
from common import (
    CONTENT_TYPE_HTML,
    redirect_unwrap,
)
from models import Follower, Object, Target, User
from web import TASKS_LOCATION, Web
from .test_activitypub import LIKE

ACTOR_HTML = """\
<html>
<body class="h-card">
<a class="p-name u-url" rel="me" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
ACTOR = requests_response(ACTOR_HTML, url='https://user.com/',
                          content_type=CONTENT_TYPE_HTML)
ACTOR_MF2 = {
    'type': ['h-card'],
    'properties': {
        'url': ['https://user.com/'],
        'name': ['Ms. ☕ Baz'],
    },
}
ACTOR_MF2_REL_URLS = {
    **ACTOR_MF2,
    'rel-urls': {'https://user.com/': {'rels': ['me'], 'text': 'Ms. ☕ Baz'}}
}
ACTOR_AS1_UNWRAPPED = {
    'objectType': 'person',
    'displayName': 'Ms. ☕ Baz',
    'url': 'https://user.com/',
    'urls': [{'value': 'https://user.com/', 'displayName': 'Ms. ☕ Baz'}],
}
ACTOR_AS2 = {
    'type': 'Person',
    'id': 'http://localhost/user.com',
    'url': 'http://localhost/r/https://user.com/',
    'name': 'Ms. ☕ Baz',
    'preferredUsername': 'user.com',
}
ACTOR_AS2_FULL = {
    **ACTOR_AS2,
    '@context': [
        'https://www.w3.org/ns/activitystreams',
        'https://w3id.org/security/v1',
    ],
    'preferredUsername': 'user.com',
    'attachment': [{
        'name': 'Web site',
        'type': 'PropertyValue',
        'value': '<a rel="me" href="https://user.com/">user.com</a>',
    }],
    'inbox': 'http://localhost/user.com/inbox',
    'outbox': 'http://localhost/user.com/outbox',
    'following': 'http://localhost/user.com/following',
    'followers': 'http://localhost/user.com/followers',
    'endpoints': {
        'sharedInbox': 'http://localhost/inbox',
    },
}

REPOST_HTML = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/repost"></a>
<a class="u-repost-of p-name" href="https://mas.to/toot/id">reposted!</a>
<a class="u-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
REPOST = requests_response(REPOST_HTML, content_type=CONTENT_TYPE_HTML,
                           url='https://user.com/repost')
REPOST_MF2 = util.parse_mf2(REPOST_HTML)['items'][0]
REPOST_AS2 = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Announce',
    'id': 'http://localhost/r/https://user.com/repost',
    'url': 'http://localhost/r/https://user.com/repost',
    'name': 'reposted!',
    'object': 'https://mas.to/toot/id',
    'to': [as2.PUBLIC_AUDIENCE],
    'cc': [
        'https://mas.to/author',
        'https://mas.to/bystander',
        'https://mas.to/recipient',
        as2.PUBLIC_AUDIENCE,
    ],
    'actor': 'http://localhost/user.com',
}
REPOST_AS1_UNWRAPPED = {
    'objectType': 'activity',
    'verb': 'share',
    'id': 'https://user.com/repost',
    'url': 'https://user.com/repost',
    'displayName': 'reposted!',
    'object': 'https://mas.to/toot/id',
    'actor': ACTOR_AS1_UNWRAPPED,
}

REPOST_HCITE_HTML = """\
<html>
<body class="h-entry">
<a class="u-url p-name" href="https://user.com/repost">reposted!</a>
<div class="u-repost-of h-cite">
  <a class="p-author h-card" href="https://mas.to/@foo">Mr. Foo</a>:</p>
  <a class="u-url" href="https://mas.to/toot/id">a post</a>
</div>
<a class="u-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
REPOST_HCITE = requests_response(REPOST_HTML, content_type=CONTENT_TYPE_HTML,
                                 url='https://user.com/repost')

WEBMENTION_REL_LINK = requests_response(
    '<html><head><link rel="webmention" href="/webmention"></html>')
WEBMENTION_NO_REL_LINK = requests_response('<html></html>')

DELETE_AS1 = {
    'objectType': 'activity',
    'verb': 'delete',
    'id': 'https://user.com/post#bridgy-fed-delete',
    'actor': 'http://localhost/user.com',
    'object': 'https://user.com/post',
}
DELETE_AS2 = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'type': 'Delete',
    'id': 'http://localhost/r/https://user.com/post#bridgy-fed-delete',
    'actor': 'http://localhost/user.com',
    'object': 'http://localhost/r/https://user.com/post',
    'to': [as2.PUBLIC_AUDIENCE],
}

@patch('requests.post')
@patch('requests.get')
class WebTest(testutil.TestCase):
    def setUp(self):
        super().setUp()
        g.user = self.user = self.make_user('user.com')

        self.request_context.push()
        self.full_redir = requests_response(
            status=302,
            redirected_url='http://localhost/.well-known/webfinger?resource=acct:user.com@user.com')

        self.toot_html = requests_response("""\
<html>
<meta>
<link href='https://mas.to/toot/atom' rel='alternate' type='application/atom+xml'>
<link href='https://mas.to/toot/id' rel='alternate' type='application/activity+json'>
</meta>
</html>
""", url='https://mas.to/toot', content_type=CONTENT_TYPE_HTML)
        self.toot_as2_data = {
            '@context': ['https://www.w3.org/ns/activitystreams'],
            'type': 'Article',
            'id': 'https://mas.to/toot/id',
            'content': 'Lots of ☕ words...',
            'actor': {'url': 'https://mas.to/author'},
            'to': ['https://mas.to/recipient', as2.PUBLIC_AUDIENCE],
            'cc': ['https://mas.to/bystander', as2.PUBLIC_AUDIENCE],
        }
        self.toot_as2 = requests_response(
            self.toot_as2_data, url='https://mas.to/toot/id',
            content_type=as2.CONTENT_TYPE + '; charset=utf-8')

        self.reply_html = """\
<html>
<body>
<div class="h-entry">
<a class="u-url" href="https://user.com/reply"></a>
<p class="e-content p-name">
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://mas.to/toot">foo ☕ bar</a>
<a href="http://localhost/"></a>
</p>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
</div>
</body>
</html>
"""
        self.reply = requests_response(self.reply_html, content_type=CONTENT_TYPE_HTML,
                                       url='https://user.com/reply')
        self.reply_mf2 = util.parse_mf2(self.reply_html)['items'][0]
        self.reply_as1 = microformats2.json_to_object(self.reply_mf2)
        self.create_reply_as1 = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'https://user.com/reply#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': self.reply_as1,
        }
        self.reply_as2 = as2.from_as1(self.reply_as1)

        self.like_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/like"></a>
<a class="u-like-of" href="https://mas.to/toot"></a>
<!--<a class="u-like-of p-name" href="https://mas.to/toot">liked!</a>-->
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.like = requests_response(self.like_html, content_type=CONTENT_TYPE_HTML,
                                      url='https://user.com/like')
        self.like_mf2 = util.parse_mf2(self.like_html)['items'][0]

        self.actor = self.as2_resp({
            'objectType' : 'Person',
            'displayName': 'Mrs. ☕ Foo',
            'id': 'https://mas.to/mrs-foo',
            'inbox': 'https://mas.to/inbox',
        })

        self.as2_create = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/https://user.com/reply#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': {
                'type': 'Note',
                'id': 'http://localhost/r/https://user.com/reply',
                'url': 'http://localhost/r/https://user.com/reply',
                'name': 'foo ☕ bar',
                'content': """\
<a class="u-in-reply-to" href="http://not/fediverse"></a>
<a class="u-in-reply-to" href="https://mas.to/toot">foo ☕ bar</a>
<a href="http://localhost/"></a>""",
                'inReplyTo': 'https://mas.to/toot/id',
                'to': [as2.PUBLIC_AUDIENCE],
                'cc': [
                    'https://mas.to/author',
                    'https://mas.to/bystander',
                    'https://mas.to/recipient',
                    as2.PUBLIC_AUDIENCE,
                ],
                'attributedTo': ACTOR_AS2,
                'tag': [{
                    'type': 'Mention',
                    'href': 'https://mas.to/author',
                }],
            },
            'to': [as2.PUBLIC_AUDIENCE],
        }
        self.as2_update = copy.deepcopy(self.as2_create)
        self.as2_update.update({
            'id': 'http://localhost/r/https://user.com/reply#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            'type': 'Update',
        })
        # we should generate this if it's not already in mf2 because Mastodon
        # requires it for updates
        self.as2_update['object']['updated'] = util.now().isoformat()

        self.follow_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/follow"></a>
<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.follow = requests_response(
            self.follow_html, url='https://user.com/follow',
            content_type=CONTENT_TYPE_HTML)
        self.follow_mf2 = util.parse_mf2(self.follow_html)['items'][0]
        self.follow_as1 = microformats2.json_to_object(self.follow_mf2)
        self.follow_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Follow',
            'id': 'http://localhost/r/https://user.com/follow',
            'url': 'http://localhost/r/https://user.com/follow',
            'object': 'https://mas.to/mrs-foo',
            'actor': 'http://localhost/user.com',
            'to': [as2.PUBLIC_AUDIENCE],
        }

        self.follow_fragment_html = """\
<html>
<body>
<article class=h-entry id=1>
<h1>Ignored</h1>
</article>
<article class=h-entry id=2>
<a class="u-url" href="https://user.com/follow#2"></a>
<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</article>
</body>
</html>
"""
        self.follow_fragment = requests_response(
            self.follow_fragment_html, url='https://user.com/follow',
            content_type=CONTENT_TYPE_HTML)
        self.follow_fragment_mf2 = \
            util.parse_mf2(self.follow_fragment_html, id='2')['items'][0]
        self.follow_fragment_as1 = microformats2.json_to_object(self.follow_fragment_mf2)
        self.follow_fragment_as2 = {
            **self.follow_as2,
            'id': 'http://localhost/r/https://user.com/follow#2',
            'url': 'http://localhost/r/https://user.com/follow#2',
        }

        self.note_html = """\
<html>
<body class="h-entry">
<a class="u-url" href="https://user.com/post"></a>
<p class="e-content p-name">hello i am a post</p>
<a class="p-author h-card" href="https://user.com/">
  <p class="p-name">Ms. ☕ <span class="p-nickname">Baz</span></p>
</a>
<a href="http://localhost/"></a>
</body>
</html>
"""
        self.note = requests_response(self.note_html, url='https://user.com/post',
                                        content_type=CONTENT_TYPE_HTML)
        self.note_mf2 = util.parse_mf2(self.note_html)['items'][0]
        self.note_as1 = microformats2.json_to_object(self.note_mf2)
        self.note_as2 = {
            'type': 'Note',
            'id': 'http://localhost/r/https://user.com/post',
            'url': 'http://localhost/r/https://user.com/post',
            'attributedTo': ACTOR_AS2,
            'name': 'hello i am a post',
            'content': 'hello i am a post',
            'to': [as2.PUBLIC_AUDIENCE],
        }
        self.create_as1 = {
            'objectType': 'activity',
            'verb': 'post',
            'id': 'https://user.com/post#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': self.note_as1,
        }
        self.create_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Create',
            'id': 'http://localhost/r/https://user.com/post#bridgy-fed-create',
            'actor': 'http://localhost/user.com',
            'object': self.note_as2,
            'to': [as2.PUBLIC_AUDIENCE],
        }
        self.update_as2 = copy.deepcopy(self.create_as2)
        self.update_as2.update({
            'type': 'Update',
            'id': 'http://localhost/r/https://user.com/post#bridgy-fed-update-2022-01-02T03:04:05+00:00',
        })
        self.update_as2['object']['updated'] = util.now().isoformat()

        self.not_fediverse = requests_response("""\
<html>
<body>foo</body>
</html>
""", url='http://not/fediverse', content_type=CONTENT_TYPE_HTML)
        self.activitypub_gets = [self.reply, self.not_fediverse, self.toot_as2,
                                 self.actor]

    def assert_deliveries(self, mock_post, inboxes, data, ignore=()):
        self.assertEqual(len(inboxes), len(mock_post.call_args_list))

        calls = {}  # maps inbox URL to JSON data
        for args, kwargs in mock_post.call_args_list:
            self.assertEqual(as2.CONTENT_TYPE, kwargs['headers']['Content-Type'])
            rsa_key = kwargs['auth'].header_signer._rsa._key
            self.assertEqual(self.user.private_pem(), rsa_key.exportKey())
            calls[args[0]] = json_loads(kwargs['data'])

        for inbox in inboxes:
            got = calls[inbox]
            as1.get_object(got).pop('publicKey', None)
            self.assert_equals(data, got, inbox, ignore=ignore)

    def assert_object(self, id, **props):
        return super().assert_object(id, delivered_protocol='activitypub', **props)

    def test_bad_source_url(self, mock_get, mock_post):
        got = self.client.post('/webmention', data=b'')
        self.assertEqual(400, got.status_code)

        got = self.client.post('/webmention', data={'source': 'bad'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_make_task(self, mock_create_task, mock_get, mock_post):
        mock_get.side_effect = [self.note, self.actor]

        params = {
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        }
        got = self.client.post('/webmention', data=params)

        self.assertEqual(202, got.status_code)
        mock_create_task.assert_called_with(
            parent=f'projects/{APP_ID}/locations/{TASKS_LOCATION}/queues/webmention',
            task={
                'app_engine_http_request': {
                    'http_method': 'POST',
                    'relative_uri': '/_ah/queue/webmention',
                    'body': urlencode(params).encode(),
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                },
            },
        )

    def test_no_user(self, mock_get, mock_post):
        got = self.client.post('/webmention', data={'source': 'https://nope.com/post'})
        self.assertEqual(400, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_source_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(self.reply_html, status=405,
                              content_type=CONTENT_TYPE_HTML),
        )

        got = self.client.post('/_ah/queue/webmention',
                               data={'source': 'https://user.com/post'})
        self.assertEqual(502, got.status_code)
        self.assertEqual(0, Object.query().count())

    def test_no_source_entry(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body>
<p>nothing to see here except <a href="http://localhost/">link</a></p>
</body>
</html>""", url='https://user.com/post', content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(304, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('https://user.com/post'),))

    def test_no_targets(self, mock_get, mock_post):
        mock_get.return_value = requests_response("""
<html>
<body class="h-entry">
<p class="e-content">no one to send to! <a href="http://localhost/"></a></p>
</body>
</html>""", url='https://user.com/post', content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((self.req('https://user.com/post'),))

    def test_bad_target_url(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(
                self.reply_html.replace('https://mas.to/toot', 'bad'),
                content_type=CONTENT_TYPE_HTML, url='https://user.com/reply'),
            ValueError('foo bar'),
        )

        got = self.client.post('/_ah/queue/webmention',
                               data={'source': 'https://user.com/reply'})
        self.assertEqual(400, got.status_code)

    def test_target_fetch_fails(self, mock_get, mock_post):
        mock_get.side_effect = (
            requests_response(
                self.reply_html.replace('https://mas.to/toot', 'bad'),
                url='https://user.com/post', content_type=CONTENT_TYPE_HTML),
            requests.Timeout('foo bar'))

        got = self.client.post('/_ah/queue/webmention',
                               data={'source': 'https://user.com/reply'})
        self.assertEqual(502, got.status_code)

    def test_target_fetch_has_no_content_type(self, mock_get, mock_post):
        html = self.reply_html.replace(
            '</body>',
            "<link href='http://as2' rel='alternate' type='application/activity+json'></body")
        mock_get.side_effect = (
            requests_response(self.reply_html, url='https://user.com/reply'),
            requests_response(self.reply_html, url='https://user.com/reply',
                              content_type='None'),
        )
        got = self.client.post('/_ah/queue/webmention',
                               data={'source': 'https://user.com/reply'})
        self.assertEqual(502, got.status_code)

    def test_missing_backlink(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>', ''),
            url='https://user.com/reply', content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(304, got.status_code)
        self.assertEqual(0, Object.query().count())

        mock_get.assert_has_calls((self.req('https://user.com/reply'),))

    def test_backlink_without_trailing_slash(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.reply_html.replace('<a href="http://localhost/"></a>',
                                    '<a href="http://localhost"></a>'),
            content_type=CONTENT_TYPE_HTML, url='https://user.com/reply')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

    def test_create_reply(self, mock_get, mock_post):
        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/author'),
        ))

        self.assert_deliveries(mock_post, ['https://mas.to/inbox'], self.as2_create)

        self.assert_object('https://user.com/reply',
                           domains=['user.com'],
                           source_protocol='web',
                           mf2=self.reply_mf2,
                           as1=self.reply_as1,
                           type='comment',
                           )
        self.assert_object('https://user.com/reply#bridgy-fed-create',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=self.reply_mf2,
                           our_as1=self.create_reply_as1,
                           delivered=['https://mas.to/inbox'],
                           type='post',
                           labels=['user', 'activity'],
                           )

    def test_update_reply(self, mock_get, mock_post):
        self.make_followers()

        mf2 = {
            'properties': {
                'content': ['other'],
            },
        }
        with self.request_context:
            Object(id='https://user.com/reply', status='complete', mf2=mf2).put()

        mock_get.side_effect = self.activitypub_gets
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        self.assertEqual(1, mock_post.call_count)
        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_update, json_loads(kwargs['data']))

    def test_redo_repost_isnt_update(self, mock_get, mock_post):
        """Like and Announce shouldn't use Update, they should just resend as is."""
        with self.request_context:
            Object(id='https://user.com/repost', mf2={}, status='complete').put()

        mock_get.side_effect = [REPOST, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        self.assert_deliveries(mock_post, ['https://mas.to/inbox'], REPOST_AS2,
                               ignore=['cc'])

    def test_skip_update_if_content_unchanged(self, mock_get, mock_post):
        """https://github.com/snarfed/bridgy-fed/issues/78"""
        with self.request_context:
            Object(id='https://user.com/reply', mf2=self.reply_mf2).put()

        mock_get.side_effect = self.activitypub_gets

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(204, got.status_code)
        mock_post.assert_not_called()

    def test_create_reply_attributed_to_id_only(self, mock_get, mock_post):
        """Based on PeerTube's AS2.

        https://github.com/snarfed/bridgy-fed/issues/40
        """
        del self.toot_as2_data['actor']
        self.toot_as2_data['attributedTo'] = {
            'type': 'Person',
            'id': 'https://mas.to/author',
        }

        mock_get.side_effect = [self.reply, self.not_fediverse, self.toot_as2,
                                self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_create, json_loads(kwargs['data']))

    def test_announce_repost(self, mock_get, mock_post):
        self._test_announce(REPOST_HTML, REPOST_AS2, mock_get, mock_post)

    def test_announce_repost_composite_hcite(self, mock_get, mock_post):
        self._test_announce(REPOST_HCITE_HTML, REPOST_AS2, mock_get, mock_post)

    def _test_announce(self, html, expected_as2, mock_get, mock_post):
        self.make_followers()

        mock_get.side_effect = [
            requests_response(html, content_type=CONTENT_TYPE_HTML,
                              url='https://user.com/repost'),
            self.toot_as2,
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/repost'),
            self.as2_req('https://mas.to/toot/id'),
            self.as2_req('https://mas.to/author'),
        ))

        inboxes = ('https://inbox', 'https://public/inbox',
                   'https://shared/inbox', 'https://mas.to/inbox')
        self.assert_deliveries(mock_post, inboxes, expected_as2, ignore=['cc'])

        for args, kwargs in mock_get.call_args_list[1:]:
            with self.subTest(url=args[0]):
                rsa_key = kwargs['auth'].header_signer._rsa._key
                self.assertEqual(self.user.private_pem(), rsa_key.exportKey())

        mf2 = util.parse_mf2(html)['items'][0]
        self.assert_object('https://user.com/repost',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=mf2,
                           as1=microformats2.json_to_object(mf2),
                           delivered=inboxes,
                           type='share',
                           object_ids=['https://mas.to/toot/id'],
                           labels=['user', 'activity'],
                           )

    def test_link_rel_alternate_as2(self, mock_get, mock_post):
        mock_get.side_effect = [
            self.reply,
            self.not_fediverse,
            self.toot_html,
            self.toot_as2,
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/reply',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/reply'),
            self.as2_req('http://not/fediverse'),
            self.as2_req('https://mas.to/toot'),
            self.as2_req('https://mas.to/toot/id', headers=as2.CONNEG_HEADERS),
            self.as2_req('https://mas.to/author'),
        ))

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.as2_create, json_loads(kwargs['data']))

    def test_like_stored_object_without_as2(self, mock_get, mock_post):
        Object(id='https://mas.to/toot', mf2=self.note_mf2).put()
        Object(id='https://user.com/', mf2=ACTOR_MF2).put()
        mock_get.side_effect = [
            self.like,
        ]

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/like',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/like'),
        ))
        mock_post.assert_not_called()

        self.assert_object('https://user.com/like',
                           domains=['user.com'],
                           source_protocol='web',
                           mf2=self.like_mf2,
                           as1=microformats2.json_to_object(self.like_mf2),
                           type='like',
                           labels=['user', 'activity'],
                           status='ignored',
                           )

    def test_create_default_url_to_wm_source(self, mock_get, mock_post):
        """Source post has no u-url. AS2 id should default to webmention source."""
        missing_url = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>
<a href="http://localhost/"></a>
</body>
</html>
""", url='https://user.com/repost', content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [missing_url, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=203)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(203, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

    def test_create_author_only_url(self, mock_get, mock_post):
        """Mf2 author property is just a URL. We should run full authorship.

        https://indieweb.org/authorship
        """
        repost = requests_response("""\
<html>
<body class="h-entry">
<a class="u-repost-of p-name" href="https://mas.to/toot">reposted!</a>
<a class="u-author" href="https://user.com/"></a>
<a href="http://localhost/"></a>
</body>
</html>
""", url='https://user.com/repost', content_type=CONTENT_TYPE_HTML)
        mock_get.side_effect = [repost, ACTOR, self.toot_as2, self.actor]
        mock_post.return_value = requests_response('abc xyz', status=201)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(201, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(REPOST_AS2, json_loads(kwargs['data']))

    @staticmethod
    def make_followers():
        Follower.get_or_create('user.com', 'https://mastodon/aaa')
        Follower.get_or_create('user.com', 'https://mastodon/bbb',
                               last_follow={'actor': {
                                   'publicInbox': 'https://public/inbox',
                                   'inbox': 'https://unused',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ccc',
                               last_follow={'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ddd',
                               last_follow={'actor': {
                                   'inbox': 'https://inbox',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ggg',
                               status='inactive',
                               last_follow={'actor': {
                                   'inbox': 'https://unused/2',
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/hhh',
                               last_follow={'actor': {
                                   # dupe of eee; should be de-duped
                                   'inbox': 'https://inbox',
                               }})

    def test_create_post(self, mock_get, mock_post):
        mock_get.side_effect = [self.note, self.actor]
        mock_post.return_value = requests_response('abc xyz')
        self.make_followers()

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/post'),
        ))
        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
        self.assert_deliveries(mock_post, inboxes, self.create_as2)

        self.assert_object('https://user.com/post',
                           domains=['user.com'],
                           mf2=self.note_mf2,
                           type='note',
                           source_protocol='web',
                           )
        self.assert_object('https://user.com/post#bridgy-fed-create',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=self.note_mf2,
                           our_as1=self.create_as1,
                           delivered=inboxes,
                           type='post',
                           labels=['user', 'activity'],
                           )

    def test_update_post(self, mock_get, mock_post):
        mock_get.side_effect = [self.note, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        with self.request_context:
            mf2 = copy.deepcopy(self.note_mf2)
            mf2['properties']['content'] = 'different'
            Object(id='https://user.com/post', domains=['user.com'], mf2=mf2).put()

        self.make_followers()

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/post'),
        ))
        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
        self.assert_deliveries(mock_post, inboxes, self.update_as2)

        update_as1 = {
            'objectType': 'activity',
            'verb': 'update',
            'id': 'https://user.com/post#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            'actor': 'http://localhost/user.com',
            'object': {
                **self.note_as1,
                'updated': '2022-01-02T03:04:05+00:00',
            },
        }
        self.assert_object(
            f'https://user.com/post#bridgy-fed-update-2022-01-02T03:04:05+00:00',
            domains=['user.com'],
            source_protocol='web',
            status='complete',
            mf2=self.note_mf2,
            our_as1=update_as1,
            delivered=inboxes,
            type='update',
            labels=['user', 'activity'],
        )

    def test_create_with_image(self, mock_get, mock_post):
        create_html = self.note_html.replace(
            '</body>', '<img class="u-photo" src="http://im/age" />\n</body>')
        mock_get.side_effect = [
            requests_response(create_html, url='https://user.com/post',
                              content_type=CONTENT_TYPE_HTML),
            self.actor,
        ]
        mock_post.return_value = requests_response('abc xyz ')

        Follower.get_or_create(
            'user.com', 'https://mastodon/aaa',
            last_follow={'actor': {'inbox': 'https://inbox'}})

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        self.assertEqual(('https://inbox',), mock_post.call_args[0])
        create = copy.deepcopy(self.create_as2)
        create['object'].update({
            'image': {'url': 'http://im/age', 'type': 'Image'},
            'attachment': [{'url': 'http://im/age', 'type': 'Image'}],
        })
        self.assert_equals(create, json_loads(mock_post.call_args[1]['data']))

    def test_follow(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        self.assert_deliveries(mock_post, ['https://mas.to/inbox'], self.follow_as2)

        self.assert_object('https://user.com/follow',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=self.follow_mf2,
                           as1=self.follow_as1,
                           delivered=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                           )

        followers = Follower.query().fetch()
        self.assertEqual(1, len(followers))
        self.assertEqual('https://mas.to/mrs-foo user.com', followers[0].key.id())
        self.assertEqual('user.com', followers[0].src)
        self.assertEqual('https://mas.to/mrs-foo', followers[0].dest)
        self.assert_equals(as2.from_as1(self.follow_as1), followers[0].last_follow)

    def test_follow_no_actor(self, mock_get, mock_post):
        self.user.actor_as2 = ACTOR_AS2
        self.user.put()

        html = self.follow_html.replace(
            '<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>', '')
        follow = requests_response(html, url='https://user.com/follow',
                                   content_type=CONTENT_TYPE_HTML)

        mock_get.side_effect = [follow, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        args, kwargs = mock_post.call_args
        self.assertEqual(('https://mas.to/inbox',), args)
        self.assert_equals(self.follow_as2, json_loads(kwargs['data']))

    def test_follow_no_target(self, mock_get, mock_post):
        self.make_followers()

        html = self.follow_html.replace(
            '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>',
            '<a class="u-follow-of"></a>')
        follow = requests_response(html, url='https://user.com/follow',
                                   content_type=CONTENT_TYPE_HTML)

        mock_get.side_effect = [follow, self.actor]

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(400, got.status_code)
        mock_post.assert_not_called()

    def test_follow_fragment(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow_fragment, self.actor]
        mock_post.return_value = requests_response('abc xyz')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow#2',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        self.assert_deliveries(mock_post, ['https://mas.to/inbox'],
                               self.follow_fragment_as2)

        self.assert_object('https://user.com/follow#2',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=self.follow_fragment_mf2,
                           as1=self.follow_fragment_as1,
                           delivered=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                           )

        followers = Follower.query().fetch()
        self.assert_equals(1, len(followers))
        self.assert_equals('https://mas.to/mrs-foo user.com', followers[0].key.id())
        self.assert_equals('user.com', followers[0].src)
        self.assert_equals('https://mas.to/mrs-foo', followers[0].dest)

    def test_follow_multiple(self, mock_get, mock_post):
        html = self.follow_html.replace(
            '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a>',
            '<a class="u-follow-of" href="https://mas.to/mrs-foo"></a> '
            '<a class="u-follow-of" href="https://mas.to/mr-biff"></a>')

        mock_get.side_effect = [
            requests_response(
                html, url='https://user.com/follow',
                content_type=CONTENT_TYPE_HTML),
            self.actor,
            self.as2_resp({
                'objectType' : 'Person',
                'displayName': 'Mr. ☕ Biff',
                'id': 'https://mas.to/mr-biff',
                'inbox': 'https://mas.to/inbox/biff',
            }),
        ]
        mock_post.return_value = requests_response('unused')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
            self.as2_req('https://mas.to/mr-biff'),
        ))

        calls = mock_post.call_args_list
        self.assertEqual('https://mas.to/inbox', calls[0][0][0])
        self.assertEqual(self.follow_as2, json_loads(calls[0][1]['data']))
        self.assertEqual('https://mas.to/inbox/biff', calls[1][0][0])
        self.assertEqual({
            **self.follow_as2,
            'object': 'https://mas.to/mr-biff',
        }, json_loads(calls[1][1]['data']))

        mf2 = util.parse_mf2(html)['items'][0]
        as1 = microformats2.json_to_object(mf2)
        self.assert_object('https://user.com/follow',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           mf2=mf2,
                           as1=as1,
                           delivered=['https://mas.to/inbox',
                                      'https://mas.to/inbox/biff'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo',
                                       'https://mas.to/mr-biff'],
                           labels=['user', 'activity'],
                           )

        followers = Follower.query().fetch()
        self.assertEqual(2, len(followers))

        self.assertEqual('https://mas.to/mr-biff user.com', followers[0].key.id())
        self.assertEqual('user.com', followers[0].src)
        self.assertEqual('https://mas.to/mr-biff', followers[0].dest)
        self.assert_equals(as2.from_as1({
            **self.follow_as1,
            'object': 'https://mas.to/mr-biff',
        }), followers[0].last_follow)

        self.assertEqual('https://mas.to/mrs-foo user.com', followers[1].key.id())
        self.assertEqual('user.com', followers[1].src)
        self.assertEqual('https://mas.to/mrs-foo', followers[1].dest)
        self.assert_equals(as2.from_as1({
            **self.follow_as1,
            'object': 'https://mas.to/mrs-foo',
        }), followers[1].last_follow)

    def test_error_fragment_missing(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            self.follow_fragment_html, url='https://user.com/follow',
            content_type=CONTENT_TYPE_HTML)

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow#3',
            'target': 'https://fed.brid.gy/',
        })
        self.assert_equals(304, got.status_code)
        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
        ))

    def test_delete(self, mock_get, mock_post):
        mock_get.return_value = requests_response('"unused"', status=410,
                                                  url='http://final/delete')
        mock_post.return_value = requests_response('unused', status=200)
        Object(id='https://user.com/post#bridgy-fed-create',
               mf2=self.note_mf2, status='complete').put()

        self.make_followers()

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code, got.text)

        inboxes = ('https://inbox', 'https://public/inbox', 'https://shared/inbox')
        self.assert_deliveries(mock_post, inboxes, DELETE_AS2)

        self.assert_object('https://user.com/post#bridgy-fed-delete',
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           our_as1=DELETE_AS1,
                           delivered=inboxes,
                           type='delete',
                           object_ids=['https://user.com/post'],
                           labels=['user', 'activity'],
                          )

    def test_delete_no_object(self, mock_get, mock_post):
        mock_get.side_effect = [
            requests_response('"unused"', status=410, url='http://final/delete'),
        ]
        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(304, got.status_code, got.text)
        mock_post.assert_not_called()

    def test_delete_incomplete_response(self, mock_get, mock_post):
        mock_get.return_value = requests_response('"unused"', status=410,
                                                  url='http://final/delete')

        with self.request_context:
            Object(id='https://user.com/post#bridgy-fed-create',
                   mf2=self.note_mf2, status='in progress')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/post',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(304, got.status_code, got.text)
        mock_post.assert_not_called()

    def test_error(self, mock_get, mock_post):
        mock_get.side_effect = [self.follow, self.actor]
        mock_post.return_value = requests_response(
            'abc xyz', status=405, url='https://mas.to/inbox')

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/follow',
            'target': 'https://fed.brid.gy/',
        })
        body = got.get_data(as_text=True)
        self.assertEqual(502, got.status_code, body)
        self.assertIn(
            '405 Client Error: None for url: https://mas.to/inbox ; abc xyz',
            body)

        mock_get.assert_has_calls((
            self.req('https://user.com/follow'),
            self.as2_req('https://mas.to/mrs-foo'),
        ))

        self.assert_deliveries(mock_post, ['https://mas.to/inbox'], self.follow_as2)

        self.assert_object('https://user.com/follow',
                           domains=['user.com'],
                           source_protocol='web',
                           status='failed',
                           mf2=self.follow_mf2,
                           as1=self.follow_as1,
                           failed=['https://mas.to/inbox'],
                           type='follow',
                           object_ids=['https://mas.to/mrs-foo'],
                           labels=['user', 'activity'],
                          )

    def test_repost_blocklisted_error(self, mock_get, mock_post):
        """Reposts of non-fediverse (ie blocklisted) sites aren't yet supported."""
        repost_html = REPOST_HTML.replace('https://mas.to/toot', 'https://twitter.com/foo')
        repost_resp = requests_response(repost_html, content_type=CONTENT_TYPE_HTML,
                                        url='https://user.com/repost')
        mock_get.side_effect = [repost_resp]

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/repost',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_post.assert_not_called()

    def test_update_profile(self, mock_get, mock_post):
        mock_get.side_effect = [ACTOR]
        mock_post.return_value = requests_response('abc xyz')
        Follower.get_or_create('user.com', 'https://mastodon/ccc',
                               last_follow={'actor': {
                                   'endpoints': {
                                       'sharedInbox': 'https://shared/inbox',
                                   },
                               }})
        Follower.get_or_create('user.com', 'https://mastodon/ddd',
                               last_follow={'actor': {
                                   'inbox': 'https://inbox',
                               }})

        got = self.client.post('/_ah/queue/webmention', data={
            'source': 'https://user.com/',
            'target': 'https://fed.brid.gy/',
        })
        self.assertEqual(200, got.status_code)
        mock_get.assert_has_calls((
            self.req('https://user.com/'),
        ))

        id = 'https://user.com/#update-2022-01-02T03:04:05+00:00'
        wrapped_id = f'http://localhost/r/{id}'
        expected_as2 = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Update',
            'id': wrapped_id,
            'actor': 'http://localhost/user.com',
            'object': {
                **ACTOR_AS2,
                'attachment': ACTOR_AS2_FULL['attachment'],
                'updated': util.now().isoformat(),
            },
            'to': ['https://www.w3.org/ns/activitystreams#Public'],
        }
        self.assert_deliveries(mock_post, ('https://shared/inbox', 'https://inbox'),
                               expected_as2)

        # homepage object
        self.assert_object('https://user.com/',
                           source_protocol='web',
                           mf2=ACTOR_MF2_REL_URLS,
                           type='person',
                           )

        # update activity
        expected_as1 = {
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': 'http://localhost/user.com',
            'object': {
                'objectType': 'person',
                'id': 'http://localhost/user.com',
                'url': 'https://user.com/',
                'urls': [
                    {'displayName': 'Ms. ☕ Baz', 'value': 'https://user.com/'},
                ],
                'displayName': 'Ms. ☕ Baz',
                'updated': '2022-01-02T03:04:05+00:00',
            },
        }
        self.assert_object(id,
                           domains=['user.com'],
                           source_protocol='web',
                           status='complete',
                           our_as1=expected_as1,
                           delivered=['https://inbox', 'https://shared/inbox'],
                           type='update',
                           object_ids=['https://user.com/'],
                           labels=['user', 'activity'],
                           )

    def _test_verify(self, redirects, hcard, actor, redirects_error=None):
        got = self.user.verify()
        self.assertEqual(self.user.key, got.key)

        with self.subTest(redirects=redirects, hcard=hcard, actor=actor,
                          redirects_error=redirects_error):
            self.assert_equals(redirects, bool(self.user.has_redirects))
            self.assert_equals(hcard, bool(self.user.has_hcard))
            if actor is None:
                self.assertIsNone(self.user.actor_as2)
            else:
                got = {k: v for k, v in self.user.actor_as2.items()
                       if k in actor}
                self.assert_equals(actor, got)
            self.assert_equals(redirects_error, self.user.redirects_error)

    def test_verify_neither(self, mock_get, _):
        empty = requests_response('')
        mock_get.side_effect = [empty, empty]
        self._test_verify(False, False, None)

    def test_verify_redirect_strips_query_params(self, mock_get, _):
        half_redir = requests_response(
            status=302, redirected_url='http://localhost/.well-known/webfinger')
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [half_redir, no_hcard]
        self._test_verify(False, False, None, """\
Current vs expected:<pre>- http://localhost/.well-known/webfinger
+ https://fed.brid.gy/.well-known/webfinger?resource=acct:user.com@user.com</pre>""")

    def test_verify_multiple_redirects(self, mock_get, _):
        two_redirs = requests_response(
            status=302, redirected_url=[
                'https://www.user.com/.well-known/webfinger?resource=acct:user.com@user.com',
                'http://localhost/.well-known/webfinger?resource=acct:user.com@user.com',
            ])
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [two_redirs, no_hcard]
        self._test_verify(True, False, None)

    def test_verify_redirect_404(self, mock_get, _):
        redir_404 = requests_response(status=404, redirected_url='http://this/404s')
        no_hcard = requests_response('<html><body></body></html>')
        mock_get.side_effect = [redir_404, no_hcard]
        self._test_verify(False, False, None, """\
<pre>https://user.com/.well-known/webfinger?resource=acct:user.com@user.com
  redirected to:
http://this/404s
  returned HTTP 404</pre>""")

    def test_verify_no_hcard(self, mock_get, _):
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

    def test_verify_non_representative_hcard(self, mock_get, _):
        bad_hcard = requests_response(
            '<html><body><a class="h-card u-url" href="https://a.b/">acct:me@user.com</a></body></html>',
            url='https://user.com/',
        )
        mock_get.side_effect = [self.full_redir, bad_hcard]
        self._test_verify(True, False, None)

    def test_verify_both_work(self, mock_get, _):
        hcard = requests_response("""
<html><body class="h-card">
  <a class="u-url p-name" href="/">me</a>
  <a class="u-url" href="acct:myself@user.com">Masto</a>
</body></html>""",
            url='https://user.com/',
        )
        mock_get.side_effect = [self.full_redir, hcard]
        self._test_verify(True, True, {
            'type': 'Person',
            'name': 'me',
            'url': ['http://localhost/r/https://user.com/', 'acct:myself@user.com'],
            'preferredUsername': 'user.com',
        })

    def test_verify_www_redirect(self, mock_get, _):
        www_user = self.make_user('www.user.com')

        empty = requests_response('')
        mock_get.side_effect = [
            requests_response(status=302, redirected_url='https://www.user.com/'),
            empty, empty,
        ]

        got = www_user.verify()
        self.assertEqual('user.com', got.key.id())

        root_user = Web.get_by_id('user.com')
        self.assertEqual(root_user.key, www_user.key.get().use_instead)
        self.assertEqual(root_user.key, Web.get_or_create('www.user.com').key)

    def test_verify_actor_rel_me_links(self, mock_get, _):
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
""", url='https://user.com/'),
        ]
        self._test_verify(True, True, {
            'attachment': [{
            'type': 'PropertyValue',
            'name': 'Mrs. ☕ Foo',
            'value': '<a rel="me" href="https://user.com/about-me">user.com/about-me</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'Web site',
            'value': '<a rel="me" href="https://user.com/">user.com</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'one text',
            'value': '<a rel="me" href="http://one">one</a>',
        }, {
            'type': 'PropertyValue',
            'name': 'two title',
            'value': '<a rel="me" href="https://two">two</a>',
        }]})

    def test_verify_override_preferredUsername(self, mock_get, _):
        mock_get.side_effect = [
            self.full_redir,
            requests_response("""
<body>
<a class="h-card u-url" rel="me" href="/about-me">
  <span class="p-nickname">Nick</span>
</a>
</body>
""", url='https://user.com/'),
        ]
        self._test_verify(True, True, {
            # stays y.z despite user's username. since Mastodon queries Webfinger
            # for preferredUsername@fed.brid.gy
            # https://github.com/snarfed/bridgy-fed/issues/77#issuecomment-949955109
            'preferredUsername': 'user.com',
        })

    def test_label_id(self, _, __):
        self.assertEqual('user.com', self.user.label_id())

    def test_web_url(self, _, __):
        self.assertEqual('https://user.com/', self.user.web_url())

    def test_ap_address(self, *_):
        self.assertEqual('@user.com@user.com', g.user.ap_address())

        g.user.actor_as2 = {'type': 'Person'}
        self.assertEqual('@user.com@user.com', g.user.ap_address())

        g.user.actor_as2 = {'url': 'http://foo'}
        self.assertEqual('@user.com@user.com', g.user.ap_address())

        g.user.actor_as2 = {'url': ['http://foo', 'acct:bar@foo', 'acct:baz@user.com']}
        self.assertEqual('@baz@user.com', g.user.ap_address())

        g.user.direct = False
        self.assertEqual('@user.com@localhost', g.user.ap_address())

    def test_ap_actor(self, *_):
        self.assertEqual('http://localhost/user.com', g.user.ap_actor())

        g.user.direct = False
        self.assertEqual('http://localhost/r/https://user.com/', g.user.ap_actor())

        self.assertEqual('http://localhost/user.com/inbox', g.user.ap_actor('inbox'))

    def test_check_web_site(self, mock_get, _):
        redir = 'http://localhost/.well-known/webfinger?resource=acct:user.com@user.com'
        mock_get.side_effect = (
            requests_response('', status=302, redirected_url=redir),
            requests_response(ACTOR_HTML, url='https://user.com/',
                              content_type=CONTENT_TYPE_HTML),
        )

        got = self.client.post('/web-site', data={'url': 'https://user.com/'})
        self.assert_equals(302, got.status_code)
        self.assert_equals('/web/user.com', got.headers['Location'])

        user = Web.get_by_id('user.com')
        self.assertTrue(user.has_hcard)
        self.assertEqual('Person', user.actor_as2['type'])
        self.assertEqual('http://localhost/user.com', user.actor_as2['id'])

    def test_check_web_site_bad_url(self, _, __):
        got = self.client.post('/web-site', data={'url': '!!!'})
        self.assert_equals(200, got.status_code)
        self.assertEqual(['No domain found in !!!'], get_flashed_messages())
        self.assertEqual(1, Web.query().count())

    def test_check_web_site_fetch_fails(self, mock_get, _):
        redir = 'http://localhost/.well-known/webfinger?resource=acct:orig@orig'
        mock_get.side_effect = (
            requests_response('', status=302, redirected_url=redir),
            requests_response('', status=503),
        )

        got = self.client.post('/web-site', data={'url': 'https://orig/'})
        self.assert_equals(200, got.status_code, got.headers)
        self.assertTrue(get_flashed_messages()[0].startswith(
            "Couldn't connect to https://orig/: "))


@patch('requests.post')
@patch('requests.get')
class WebProtocolTest(testutil.TestCase):

    def setUp(self):
        super().setUp()
        self.request_context.__enter__()
        g.user = self.make_user('user.com')

    def tearDown(self):
        self.request_context.__enter__()
        super().tearDown()

    def test_fetch(self, mock_get, __):
        mock_get.return_value = REPOST

        obj = Object(id='https://user.com/post')
        Web.fetch(obj)

        self.assert_equals({**REPOST_MF2, 'url': 'https://user.com/repost'}, obj.mf2)

    def test_fetch_redirect(self, mock_get, __):
        mock_get.return_value =requests_response(
            REPOST_HTML, content_type=CONTENT_TYPE_HTML,
            redirected_url='http://new/url')
        obj = Object(id='https://orig/url')
        Web.fetch(obj)

        self.assert_equals('http://new/url', obj.mf2['url'])
        self.assert_equals({**REPOST_MF2, 'url': 'http://new/url'}, obj.mf2)
        self.assertIsNone(Object.get_by_id('http://new/url'))

    def test_fetch_error(self, mock_get, __):
        mock_get.return_value = requests_response(REPOST_HTML, status=405)
        with self.assertRaises(BadGateway) as e:
            Web.fetch(Object(id='https://foo'), gateway=True)

    def test_fetch_check_backlink_false(self, mock_get, mock_post):
        mock_get.return_value = requests_response(
            REPOST_HTML.replace('<a href="http://localhost/"></a>', ''))

        obj = Object(id='https://foo')
        Web.fetch(obj, check_backlink=False)
        self.assert_equals(REPOST_MF2, obj.mf2)
        mock_get.assert_has_calls((self.req('https://foo'),))

    def test_fetch_run_authorship(self, mock_get, __):
        mock_get.side_effect = [
            # post
            requests_response(
                REPOST_HTML.replace(
                    '<a class="p-author h-card" href="https://user.com/">Ms. ☕ Baz</a>',
                    '<a class="u-author" href="https://user.com/"></a>'),
                content_type=CONTENT_TYPE_HTML, url='https://user.com/repost'),
            # author URL
            ACTOR,
        ]

        obj = Object(id='https://user.com/repost')
        Web.fetch(obj)
        self.assert_equals({**REPOST_MF2, 'url': 'https://user.com/repost'}, obj.mf2)

    def test_fetch_user_homepage(self, mock_get, __):
        mock_get.return_value = ACTOR

        obj = Object(id='https://user.com/')
        Web.fetch(obj)

        self.assert_equals({
            **ACTOR_MF2_REL_URLS,
            'url': 'https://user.com/',
        }, obj.mf2)
        self.assert_equals({**ACTOR_AS1_UNWRAPPED, 'url': 'https://user.com/'},
                           obj.as1)

    def test_fetch_user_homepage_no_hcard(self, mock_get, __):
        mock_get.return_value = REPOST

        obj = Object(id='https://user.com/')
        with self.assertRaises(BadRequest):
            Web.fetch(obj)

    def test_fetch_user_homepage_non_representative_hcard(self, mock_get, __):
        mock_get.return_value = requests_response(
            '<html><body><a class="h-card u-url" href="https://a.b/">acct:me@y.z</a></body></html>',
            content_type=CONTENT_TYPE_HTML)

        obj = Object(id='https://user.com/')
        with self.assertRaises(BadRequest):
            Web.fetch(obj)

    def test_send(self, mock_get, mock_post):
        mock_get.return_value = WEBMENTION_REL_LINK
        mock_post.return_value = requests_response()

        obj = Object(id='http://mas.to/like#ok', as2=LIKE, source_protocol='ui')
        self.assertTrue(Web.send(obj, 'https://user.com/post'))

        self.assert_req(mock_get, 'https://user.com/post')
        args, kwargs = mock_post.call_args
        self.assertEqual(('https://user.com/webmention',), args)
        self.assertEqual({
            'source': 'http://localhost/convert/ui/web/http:/mas.to/like^^ok',
            'target': 'https://user.com/post',
        }, kwargs['data'])

    def test_send_no_endpoint(self, mock_get, mock_post):
        mock_get.return_value = WEBMENTION_NO_REL_LINK
        obj = Object(id='http://mas.to/like#ok', as2=LIKE)

        self.assertFalse(Web.send(obj, 'https://user.com/post'))

        self.assert_req(mock_get, 'https://user.com/post')
        mock_post.assert_not_called()

    def test_serve(self, _, __):
        obj = Object(id='http://orig', mf2=ACTOR_MF2)
        html, headers = Web.serve(obj)
        self.assert_multiline_equals("""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=https://user.com/"></head>
<body class="">
  <span class="h-card">
    <a class="p-name u-url" href="https://user.com/">Ms. ☕ Baz</a>
  </span>
</body>
</html>
""", html, ignore_blanks=True)
        self.assertEqual({'Content-Type': 'text/html; charset=utf-8'}, headers)
