"""Protocol-independent code for sending and receiving DMs aka chat messages."""
import logging

from oauth_dropins.webutil import util

import common
import models

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

