"""Protocol-independent code for sending and receiving DMs aka chat messages."""
import logging

from granary import as1
from oauth_dropins.webutil import util

import common
import models
import protocol

logger = logging.getLogger(__name__)


def maybe_send(*, from_proto, to_user, text, type):
    """Sends a DM if we haven't already sent one of this type to this user.

    Creates a task to send the DM asynchronously.

    If ``type`` isn't ``welcome``, and we've already sent this user a DM of
    this type from this protocol, does nothing.

    Args:
      from_proto (protocol.Protocol)
      to_user (models.User)
      text (str): message content. May be HTML.
      type (str): one of DM.TYPES
    """
    dm = models.DM(protocol=from_proto.LABEL, type=type)
    if dm in to_user.sent_dms:
        return

    from web import Web
    bot = Web.get_by_id(from_proto.bot_user_id())
    logger.info(f'Sending DM from {bot.key.id()} to {to_user.key.id()} : {text}')

    if not to_user.obj or not to_user.obj.as1:
        logger.info("  can't send DM, recipient has no profile obj")
        return

    id = f'{bot.profile_id()}#{type}-dm-{to_user.key.id()}-{util.now().isoformat()}'
    target_uri = to_user.target_for(to_user.obj, shared=False)
    target = models.Target(protocol=to_user.LABEL, uri=target_uri)
    obj_key = models.Object(id=id, source_protocol='web', undelivered=[target],
                            our_as1={
        'objectType': 'activity',
        'verb': 'post',
        'id': f'{id}-create',
        'actor': bot.key.id(),
        'object': {
            'objectType': 'note',
            'id': id,
            'author': bot.key.id(),
            'content': text,
            'tags': [{
                'objectType': 'mention',
                'url': to_user.key.id(),
            }],
            'to': [to_user.key.id()],
        },
        'to': [to_user.key.id()],
    }).put()

    common.create_task(queue='send', obj=obj_key.urlsafe(), protocol=to_user.LABEL,
                       url=target.uri, user=bot.key.urlsafe())

    to_user.sent_dms.append(dm)
    to_user.put()


def receive(*, from_user, obj):
    """Handles a DM that a user sent to one of our protocol bot users.

    Args:
      from_user (models.User)
      obj (Object): DM

    Returns:
      (str, int) tuple: (response body, HTTP status code) Flask response
    """
    recip = as1.recipient_if_dm(obj.as1)
    assert recip

    to_proto = protocol.Protocol.for_bridgy_subdomain(recip)
    assert to_proto  # already checked in check_supported call in Protocol.receive

    inner_obj = (as1.get_object(obj.as1) if as1.object_type(obj.as1) == 'post'
                 else obj.as1)
    logger.info(f'got DM from {from_user.key.id()} to {to_proto.LABEL}: {inner_obj.get("content")}')

    # remove @-mentions of bot user in HTML links
    soup = util.parse_html(inner_obj.get('content', ''))
    for link in soup.find_all('a'):
        link.extract()
    content = soup.get_text().strip().lower()

    if content in ('yes', 'ok'):
        from_user.enable_protocol(to_proto)
        to_proto.bot_follow(from_user)
    elif content == 'no':
        to_proto.delete_user_copy(from_user)
        from_user.disable_protocol(to_proto)

    return 'OK', 200
