"""Unit tests for common.py."""
from unittest import skip
from unittest.mock import Mock, patch

from arroba.datastore_storage import AtpBlock
import flask
from granary import as2
from oauth_dropins.webutil.appengine_config import error_reporting_client
from oauth_dropins.webutil.testutil import NOW

# import first so that Fake is defined before URL routes are registered
from .testutil import ExplicitFake, Fake, OtherFake, TestCase

from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
from atproto import ATProto
import common
import domains
from memcache import PER_USER_TASK_RATES
from models import Follower, Object, Target
from web import Web


class CommonTest(TestCase):

    def test_pretty_link(self):
        for expected, url, text in (
                ('href="http://foo">bar</a>', 'http://foo', 'bar'),
                ('href="http://x.y/@z">@z@x.y</a>', 'http://x.y/@z', None),
                ('href="http://x.y/@z">foo</a>', 'http://x.y/@z', 'foo'),
                ('href="http://x.y/users/z">@z@x.y</a>', 'http://x.y/users/z', None),
                ('href="http://x.y/users/z">foo</a>', 'http://x.y/users/z', 'foo'),
                ('href="http://x.y/@z/123">x.y/@z/123</a>', 'http://x.y/@z/123', None),
        ):
            self.assertIn(expected, common.pretty_link(url, text=text))

        self.assertEqual('<a href="http://foo">foo</a>',
                         common.pretty_link('http://foo'))

        # current user's homepage gets converted to BF user page
        self.assert_multiline_equals("""\
<span class="logo" title="Web">🌐</span> <a class="h-card u-author mention" rel="me" href="https://user.com/" title="user.com"><span style="unicode-bidi: isolate">user.com</span></a>""", common.pretty_link('https://user.com/', user=Web(id='user.com')),
        ignore_blanks=True)

    def test_cache_policy(self):
        for obj in (
            AtpBlock(id='xyz'),
            Object(id='did:plc:foo'),
            Object(id='https://mastodon.social/users/alice'),
            Object(id='at://did:plc:user/app.bsky.actor.profile/self'),
        ):
            self.assertTrue(common.cache_policy(obj.key))

        for obj in (
            ATProto(id='alice'),
            ActivityPub(id='alice'),
            Web(id='alice'),
            Follower(id='abc'),
        ):
            self.assertFalse(common.cache_policy(obj.key))

    def test_global_cache_timeout_policy(self):
        for obj in (
            ATProto(id='alice'),
            ActivityPub(id='alice'),
            Web(id='alice'),
            Object(id='https://mastodon.social/users/alice'),
            Object(id='https://mastodon.social/users/alice#main-key'),
            Object(id='did:plc:foo'),
            Object(id='did:web:foo.com'),
            Object(id='at://did:plc:user/app.bsky.actor.profile/self'),
        ):
            self.assertEqual(7200, common.global_cache_timeout_policy(obj.key._key))

        for obj in (
            Follower(id='abc'),
            Object(id='abc'),
            Object(id='https://mastodon.social/users/alice/statuses/123'),
            Object(id='at://did:plc:user/app.bsky.feed.post/abc'),
            Object(id='https://web.site/post'),
            AtpBlock(id='abc123'),
        ):
            self.assertEqual(7200, common.global_cache_timeout_policy(obj.key._key))

    @patch('common.DEBUG', new=False)
    @patch('common.error_reporting_client')
    def test_report_error_no_request_context(self, mock_client):
        mock_client.report = Mock(name='report_error')

        self.request_context.pop()
        assert not flask.has_request_context()

        try:
            common.report_error('foo', bar='baz')
        finally:
            self.request_context.push()

        mock_client.report.assert_called_with('foo', http_context=None, bar='baz')

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_create_task_no_request_context(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        self.request_context.pop()
        common.create_task('foo')
        mock_create_task.assert_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_create_task_rate_limited(self, mock_create_task):
        common.RUN_TASKS_INLINE = False

        def assert_eta(expected):
            actual = mock_create_task.call_args[1]['task']['schedule_time']
            self.assertEqual(int(expected.timestamp()), actual.seconds)

        now = NOW
        delay = PER_USER_TASK_RATES['receive']
        common.create_task('receive', authed_as='alice', received_at='foo')

        task = mock_create_task.call_args[1]['task']
        self.assertNotIn('schedule_time', task)
        self.assertIn(b'received_at=foo', task['app_engine_http_request']['body'])

        common.create_task('receive', authed_as='alice', received_at='foo')
        assert_eta(now + delay)
        self.assertNotIn(
            b'received_at=foo',
            mock_create_task.call_args[1]['task']['app_engine_http_request']['body'])

        common.create_task('receive', authed_as='alice')
        assert_eta(now + delay + delay)

        common.create_task('receive', authed_as='bob')
        self.assertNotIn('schedule_time', mock_create_task.call_args[1]['task'])

        common.create_task('receive', authed_as='bob')
        assert_eta(now + delay)

        # no authed_as, skips rate limiting
        common.create_task('receive')
        self.assertNotIn('schedule_time', mock_create_task.call_args[1]['task'])

    def test_bot_user_ids(self):
        self.make_user('fa.brid.gy', cls=Web, ap_subdomain='fa',
                       copies=[Target(protocol='efake', uri='efake:fa-bot'),
                               Target(protocol='other', uri='other:fa-bot')])
        self.make_user('other.brid.gy', cls=Web, ap_subdomain='other')

        self.assert_equals(list(domains.PROTOCOL_DOMAINS) + [
            'efake:fa-bot',
            'other:fa-bot',
            'https://fa.brid.gy/fa.brid.gy',
            'https://other.brid.gy/other.brid.gy',
        ], common.bot_user_ids())
