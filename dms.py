"""Protocol-independent code for sending and receiving DMs aka chat messages."""
from datetime import timedelta
import logging

from granary import as1
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil import util

from common import create_task, DOMAINS, memcache, memcache_key
import ids
import models
from models import PROTOCOLS
import protocol

logger = logging.getLogger(__name__)

REQUESTS_LIMIT_EXPIRE = timedelta(days=1)
REQUESTS_LIMIT_USER = 10

COMMANDS = (
    'did',
    'help',
    'no',
    'ok',
    'start',
    'stop',
    'username',
    'yes',
)


def maybe_send(*, from_proto, to_user, text, type=None, in_reply_to=None):
    """Sends a DM.

    Creates a task to send the DM asynchronously.

    If ``type`` is provided, and we've already sent this user a DM of this type
    from this protocol, does nothing.

    Args:
      from_proto (protocol.Protocol)
      to_user (models.User)
      text (str): message content. May be HTML.
      type (str): optional, one of DM.TYPES
      in_reply_to (str): optional, ``id`` of a DM to reply to
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
    models.Object(id=id, source_protocol='web', undelivered=[target], our_as1={
        'objectType': 'activity',
        'verb': 'post',
        'id': f'{id}-create',
        'actor': bot.key.id(),
        'object': {
            'objectType': 'note',
            'id': id,
            'author': bot.key.id(),
            'content': text,
            'inReplyTo': in_reply_to,
            'tags': [{
                'objectType': 'mention',
                'url': to_user.key.id(),
            }],
            'to': [to_user.key.id()],
        },
        'to': [to_user.key.id()],
    }).put()

    create_task(queue='send', obj_id=id, protocol=to_user.LABEL,
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

    soup = util.parse_html(inner_obj.get('content', ''))

    content = soup.get_text().strip().lower()
    if not content:
        return r'¯\_(ツ)_/¯', 204

    def reply(text, type=None):
        maybe_send(from_proto=to_proto, to_user=from_user, text=text, type=type,
                   in_reply_to=inner_obj.get('id'))
        return 'OK', 200

    # parse and handle message
    tokens = content.split()
    logger.info(f'  tokens: {tokens}')

    # remove @-mention of bot, if any
    bot_handles = (DOMAINS + ids.BOT_ACTOR_AP_IDS
                   + tuple(h.lstrip('@') for h in ids.BOT_ACTOR_AP_HANDLES))
    if tokens[0].lstrip('@') in bot_handles:
        logger.info(f'  first token is bot mention, removing')
        tokens = tokens[1:]

    if tokens[0].lstrip('/') in COMMANDS:
        cmd = tokens[0].lstrip('/')
        arg = tokens[1] if len(tokens) > 1 else None
    else:
        cmd = None
        arg = tokens[0]

    # handle commands
    if cmd in ('?', 'help', 'commands', 'info', 'hi', 'hello'):
        extra = ''
        if to_proto.LABEL == 'atproto':
            extra = """<li><em>did</em>: get your bridged Bluesky account's <a href="https://atproto.com/guides/identity#identifiers">DID</a>"""
        return reply(f"""\
<p>Hi! I'm a friendly bot that can help you bridge your account into {to_proto.PHRASE}. Here are some commands I respond to:</p>
<ul>
<li><em>start</em>: enable bridging for your account
<li><em>stop</em>: disable bridging for your account
<li><em>username [domain]</em>: set a custom domain username (handle)
<li><em>[handle]</em>: ask me to DM a user on {to_proto.PHRASE} to request that they bridge their account into {from_user.PHRASE}
{extra}
<li><em>help</em>: print this message
</ul>""")

    if cmd in ('yes', 'ok', 'start') and not arg:
        from_user.enable_protocol(to_proto)
        to_proto.bot_follow(from_user)
        return 'OK', 200

    # all other commands require the user to be bridged to this protocol first
    if not from_user.is_enabled(to_proto):
        return reply(f"Looks like you're not bridged to {to_proto.PHRASE} yet! Please bridge your account first by following this account.")

    if cmd == 'did' and not arg and to_proto.LABEL == 'atproto':
        return reply(f'Your DID is <code>{from_user.get_copy(PROTOCOLS["atproto"])}</code>')
        return 'OK', 200

    if cmd in ('no', 'stop') and not arg:
        from_user.delete(to_proto)
        from_user.disable_protocol(to_proto)
        return 'OK', 200

    if cmd in ('username', 'handle') and arg:
        try:
            to_proto.set_username(from_user, arg)
        except NotImplementedError:
            return reply(f"Sorry, Bridgy Fed doesn't support custom usernames for {to_proto.PHRASE} yet.")
        except (ValueError, RuntimeError) as e:
            return reply(str(e))
        return reply(f"Your username in {to_proto.PHRASE} has been set to {from_user.user_link(proto=to_proto, name=False, handle=True)}. It should appear soon!")

    # are they requesting a user?
    if not cmd:
        if not to_proto.owns_handle(arg) and arg.startswith('@'):
            logging.info(f"doesn't look like a handle, trying without leading @")
            arg = arg.removeprefix('@')

        if to_proto.owns_handle(arg) is not False:
            handle = arg
            from_proto = from_user.__class__

            try:
                ids.translate_handle(handle=handle, from_=to_proto, to=from_user,
                                     enhanced=False)
            except ValueError as e:
                logger.warning(e)
                return reply(f"Sorry, Bridgy Fed doesn't yet support bridging handle {handle} from {to_proto.PHRASE} to {from_proto.PHRASE}.")

            to_id = to_proto.handle_to_id(handle)
            if not to_id:
                return reply(f"Couldn't find {to_proto.PHRASE} user {handle}")

            to_user = to_proto.get_or_create(to_id)
            if not to_user:
                return reply(f"Couldn't find {to_proto.PHRASE} user {handle}")

            if not to_user.obj:
                # doesn't exist
                return reply(f"Couldn't find {to_proto.PHRASE} user {handle}")

            elif to_user.is_enabled(from_proto):
                # already bridged
                return reply(f'{to_user.user_link(proto=from_proto)} is already bridged into {from_proto.PHRASE}.')

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
            maybe_send(from_proto=from_proto, to_user=to_user, type='request_bridging', text=f"""\
<p>Hi! {from_user.user_link(proto=to_proto, proto_fallback=True)} is using Bridgy Fed to bridge their account from {from_proto.PHRASE} into {to_proto.PHRASE}, and they'd like to follow you. You can bridge your account into {from_proto.PHRASE} by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.
<p>If you do nothing, your account won't be bridged, and users on {from_proto.PHRASE} won't be able to see or interact with you.
<p>Bridgy Fed will only send you this message once.""")
            return reply(f"Got it! We'll send {to_user.user_link()} a message and say that you hope they'll enable the bridge. Fingers crossed!")

    error(f"Couldn't understand DM: {tokens}", status=304)
