"""Protocol-independent code for sending and receiving DMs aka chat messages."""
from datetime import timedelta
import logging

from granary import as1
from oauth_dropins.webutil import util

from common import create_task, memcache, memcache_key
import models
import protocol

logger = logging.getLogger(__name__)

REQUESTS_LIMIT_EXPIRE = timedelta(days=1)
REQUESTS_LIMIT_USER = 10


def maybe_send(*, from_proto, to_user, text, type=None):
    """Sends a DM.

    Creates a task to send the DM asynchronously.

    If ``type`` is provided, and we've already sent this user a DM of this type
    from this protocol, does nothing.

    Args:
      from_proto (protocol.Protocol)
      to_user (models.User)
      text (str): message content. May be HTML.
      type (str): optional, one of DM.TYPES
    """
    if type:
        dm = models.DM(protocol=from_proto.LABEL, type=type)
        if dm in to_user.sent_dms:
            return

    from web import Web
    bot = Web.get_by_id(from_proto.bot_user_id())
    logger.info(f'Sending DM from {bot.key.id()} to {to_user.key.id()} : {text}')

    if not to_user.obj or not to_user.obj.as1:
        logger.info("  can't send DM, recipient has no profile obj")
        return

    id = f'{bot.profile_id()}#{type or "?"}-dm-{to_user.key.id()}-{util.now().isoformat()}'
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

    create_task(queue='send', obj=obj_key.urlsafe(), protocol=to_user.LABEL,
                url=target.uri, user=bot.key.urlsafe())

    if type:
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

    # remove @-mentions in HTML links
    soup = util.parse_html(inner_obj.get('content', ''))
    for link in soup.find_all('a'):
        link.extract()
    content = soup.get_text().strip().lower()

    # parse and handle message
    if content in ('yes', 'ok'):
        from_user.enable_protocol(to_proto)
        to_proto.bot_follow(from_user)
        return 'OK', 200

    elif content == 'no':
        to_proto.delete_user_copy(from_user)
        from_user.disable_protocol(to_proto)
        return 'OK', 200

    # request a user
    elif to_proto.owns_handle(content) is not False:
        def reply(text, type=None):
            maybe_send(from_proto=to_proto, to_user=from_user, text=text, type=type)
            return 'OK', 200

        if not from_user.is_enabled(to_proto):
            return reply(f'Please bridge your account to {to_proto.PHRASE} by following this account before requesting another user.')

        if to_id := to_proto.handle_to_id(content):
            handle = content
            if to_user := to_proto.get_or_create(to_id):
                from_proto = from_user.__class__

                if not to_user.obj:
                    # doesn't exist
                    return reply(f"Couldn't find {to_proto.PHRASE} user {handle}")

                elif to_user.is_enabled(from_proto):
                    # already bridged
                    return reply(f'{to_user.user_link()} is already bridged into {from_proto.PHRASE}.')

                elif (models.DM(protocol=from_proto.LABEL, type='request_bridging')
                      in to_user.sent_dms):
                    # already requested
                    return reply(f"We've already sent {to_user.user_link()} a DM. Fingers crossed!")

                # check and update rate limits
                attempts_key = f'dm-user-requests-{from_user.LABEL}-{from_user.key.id()}'
                # incr leaves existing expiration as is, doesn't change it
                # https://stackoverflow.com/a/4084043/186123
                attempts = memcache.incr(attempts_key, 1)
                if not attempts:
                    memcache.add(attempts_key, 1,
                                 expire=int(REQUESTS_LIMIT_EXPIRE.total_seconds()))
                elif attempts > REQUESTS_LIMIT_USER:
                    return reply(f"Sorry, you've hit your limit of {REQUESTS_LIMIT_USER} requests per day. Try again tomorrow!")

                # send the DM request!
                maybe_send(from_proto=from_proto, to_user=to_user,
                           type='request_bridging', text=f"""\
<p>Hi! {from_user.user_link(proto=to_proto)} is using Bridgy Fed to bridge their account on {from_proto.PHRASE} into {to_proto.PHRASE} here, and they'd like to follow you. You can bridge your account into {from_proto.PHRASE} by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.
<p>If you do nothing, your account won't be bridged, and users on {from_proto.PHRASE} won't be able to see or interact with you.
<p>Bridgy Fed will only send you this message once.""")
                return reply(f"Got it! We'll send {to_user.user_link()} a DM. Fingers crossed!")

        return reply(f"Couldn't find {to_proto.PHRASE} user {handle}")

    return "Couldn't understand DM: foo bar", 304
