"""Unit tests for notifications.py."""
from unittest.mock import patch

from oauth_dropins.webutil.testutil import NOW
from oauth_dropins.webutil import util

import common
from memcache import memcache
from models import Object
from notifications import add_notification, get_notifications, NOTIFY_TASK_FREQ
from .testutil import ExplicitFake, Fake, TestCase
from web import Web

from . import test_dms


@patch.object(Fake, 'SUPPORTS_DMS', True)
class NotificationsTest(TestCase):

    def test_get_notifications_empty(self):
        user = self.make_user(id='fake:user', cls=Fake)
        self.assertEqual([], get_notifications(user))

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_new_key(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        add_notification(user, Object(id='http://reply'))

        self.assertEqual(['http://reply'], get_notifications(user))
        self.assertEqual(b'http://reply', memcache.get('notifs-fake:user'))

        delayed_eta = (util.to_utc_timestamp(NOW) +
                       NOTIFY_TASK_FREQ.total_seconds())
        self.assert_task(mock_create_task, 'notify', delayed_eta, user_id='fake:user',
                         protocol='fake')

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_requires_web_url(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        add_notification(user, Object(id='efake:reply'))

        self.assertEqual([], get_notifications(user))
        self.assertIsNone(memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_for_user_with_send_notifs_none_is_noop(
            self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake, send_notifs='none')

        add_notification(user, Object(id='http://reply'))

        self.assertEqual([], get_notifications(user))
        self.assertIsNone(memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_append_to_existing(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        memcache.set('notifs-fake:user', b'http://reply0')
        add_notification(user, Object(id='r1', our_as1={'url': 'http://r1'}))
        add_notification(user, Object(id='http://reply2'))

        self.assertEqual(['http://reply0', 'http://r1', 'http://reply2'],
                         get_notifications(user))
        self.assertEqual(b'http://reply0 http://r1 http://reply2',
                         memcache.get('notifs-fake:user'))
        mock_create_task.assert_not_called()

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_add_notification_deduplicate(self, mock_create_task):
        common.RUN_TASKS_INLINE = False
        user = self.make_user(id='fake:user', cls=Fake)

        add_notification(user, Object(id='http://reply'))
        add_notification(user, Object(id='http://reply'))

        self.assertEqual(['http://reply'], get_notifications(user))
        self.assertEqual(b'http://reply', memcache.get('notifs-fake:user'))

        delayed_eta = (util.to_utc_timestamp(NOW) + NOTIFY_TASK_FREQ.total_seconds())
        self.assert_task(mock_create_task, 'notify', delayed_eta, user_id='fake:user',
                         protocol='fake')

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_notify_task(self, _):
        common.RUN_TASKS_INLINE = False
        self.make_user(id='efake.brid.gy', cls=Web)
        user = self.make_user(id='fake:user', cls=Fake, enabled_protocols=['efake'],
                              obj_as1={'x': 'y'})

        add_notification(user, Object(id='efake:a', our_as1={'url': 'http://notif/a'}))
        add_notification(user, Object(id='http://notif/b'))

        common.RUN_TASKS_INLINE = True
        resp = self.post('/queue/notify', data={
            'user_id': 'fake:user',
            'protocol': 'fake',
        })
        self.assertEqual(200, resp.status_code)
        test_dms.DmsTest().assert_sent(ExplicitFake, user, '?', """\
<p>Hi! Here are your recent interactions from people who aren't bridged into fake-phrase:
<ul>
<li><a href="http://notif/a">notif/a</a>
<li><a href="http://notif/b">notif/b</a>
</ul>
<p>To disable these messages, reply with the text 'mute'.""")
        self.assertEqual([], get_notifications(user))

    def test_notify_task_no_notifications(self):
        self.make_user(id='efake.brid.gy', cls=Web)
        user = self.make_user(id='fake:user', cls=Fake, enabled_protocols=['efake'],
                              obj_as1={'x': 'y'})

        resp = self.post('/queue/notify', data={
            'user_id': 'fake:user',
            'protocol': 'fake',
        })
        self.assertEqual(204, resp.status_code)
        self.assertEqual([], Fake.sent)
        self.assertEqual([], get_notifications(user))

    @patch('oauth_dropins.webutil.appengine_config.tasks_client.create_task')
    def test_notify_task_user_not_enabled(self, _):
        common.RUN_TASKS_INLINE = False
        self.make_user(id='efake.brid.gy', cls=Web)
        user = self.make_user(id='fake:user', cls=Fake, manual_opt_out=True,
                              enabled_protocols=['efake'], obj_as1={'x': 'y'})

        add_notification(user, Object(id='efake:b'))

        common.RUN_TASKS_INLINE = True
        resp = self.post('/queue/notify', data={
            'user_id': 'fake:user',
            'protocol': 'fake',
        })
        self.assertEqual(204, resp.status_code)
        self.assertEqual([], Fake.sent)
        self.assertEqual([], get_notifications(user))
