"""Send DM notifications of replies, quote posts, mentions from unbridged users."""
from datetime import timedelta
import logging

from flask import request
from granary import as1
from oauth_dropins.webutil import appengine_info, util
from oauth_dropins.webutil.flask_util import cloud_tasks_only

import common
import dms
from memcache import memcache, key
from models import PROTOCOLS

logger = logging.getLogger(__name__)

NOTIFY_TASK_FREQ = timedelta(hours=1)


def notification_key(user):
    return key(f'notifs-{user.key.id()}')


def add_notification(user, obj):
    """Adds a notification for a given user.

    The memcache key is ``notifs-{user id}``. The value is a space-separated list of
    object URLs to notify the user of.

    Uses gets/cas to create the cache entry if it doesn't exist.

    Args:
      user (models.User): the user to notify
      obj (models.Object): the object to notify about
    """
    key = notification_key(user)
    obj_url = as1.get_url(obj.as1) or obj.key.id()
    assert obj_url

    if user.send_notifs != 'all':
        return

    if not util.is_web(obj_url):
        logger.info(f'Dropping non-URL notif {obj_url} for {user.key.id()}')
        return

    logger.info(f'Adding notif {obj_url} for {user.key.id()}')

    if memcache.add(key, obj_url.encode()):
        common.create_task(queue='notify', delay=NOTIFY_TASK_FREQ,
                           user_id=user.key.id(), protocol=user.LABEL)
    else:
        existing = memcache.get(key)
        if existing and obj_url not in existing.decode().split():
            # there's a race condition here if the notify task runs between the gets
            # call above and this append call, since there won't be a value in
            # memcache, so append will do nothing. should be rare.
            #
            # gets/cas wouldn't make it any easier; we'd still need to keep retrying
            # until we have a get/append or gets/cas that no one else writes between.
            memcache.append(key, (' ' + obj_url).encode())


def get_notifications(user, clear=False):
    """Gets enqueued notifications for a given user.

    The memcache key is ``notifs-{user id}``.

    Args:
      user (models.User)
      clear (bool): clear notifications from memcache after fetching them

    Returns:
      list of str: URLs to notify the user of; possibly empty
    """
    key = notification_key(user)
    notifs = memcache.get(key, default=b'').decode().strip().split()

    if notifs and clear:
        memcache.delete(key)

    return notifs


@cloud_tasks_only()
def notify_task():
    """Task handler for sending a notification DM to a user.

    Fetches notifications from memcache.

    Parameters:
      user_id (str): ID of the user to send notifications to
      protocol (str): Protocol label the user is on
    """
    common.log_request()

    proto = PROTOCOLS[request.form['protocol']]
    user_id = request.form['user_id']

    if not (user := proto.get_by_id(user_id)):
        logger.info(f"Couldn't load user {user_id}")
        return '', 204

    if not (notifs := get_notifications(user, clear=True)):
        logger.info(f'No notifications for {user_id}')
        return '', 204

    if user.send_notifs == 'none':
        logger.info(f'User {user_id} has notifs disabled')
        return '', 204

    from_proto_label = (user.enabled_protocols[0] if user.enabled_protocols
        else user.DEFAULT_ENABLED_PROTOCOLS[0] if user.DEFAULT_ENABLED_PROTOCOLS
        else None)
    if not from_proto_label:
        logger.info(f"User {user_id} isn't enabled")
        return '', 204

    message = f"<p>Hi! Here are your recent interactions from people who aren't bridged into {user.PHRASE}:\n<ul>\n"
    for url in notifs:
        message += f'<li>{util.pretty_link(url)}\n'
    message += "</ul>\n<p>To disable these messages, reply with the text 'mute'."

    logger.info(f'sending notifications DM for {user_id}')
    dms.maybe_send(from_=PROTOCOLS[from_proto_label], to_user=user, text=message)

    return '', 200
