"""Protocol-independent code for sending and receiving DMs aka chat messages."""
from datetime import timedelta
import logging

from flask import request
from granary import as1, source
from oauth_dropins.webutil.flask_util import cloud_tasks_only, error
from oauth_dropins.webutil import util

from collections import namedtuple
import common
from common import create_task, DOMAINS
import ids
import memcache
import models
from models import Object, PROTOCOLS
import protocol

logger = logging.getLogger(__name__)

REQUESTS_LIMIT_EXPIRE = timedelta(days=1)
REQUESTS_LIMIT_USER = 10

# populated by the command() decorator
_commands = {}


def command(names, arg=False, user_bridged=None, handle_bridged=None):
    """Function decorator. Defines and registers a DM command.

    Args:
      names (sequence of str): the command strings that trigger this command, or
        ``None`` if this command has no command string
      arg: whether this command takes an argument. ``False`` for no, ``True``
        for yes, anything, ``'handle'`` for yes, a handle in the bot account's
        protocol for a user that must not already be bridged.
      user_bridged (bool): whether the user sending the DM should be
        bridged. ``True`` for yes, ``False`` for no, ``None` for either.
      handle_bridged (bool): whether the handle arg should be bridged. ``True``
        for yes, ``False`` for no, ``None` for either.

    The decorated function should have the signature:
      (from_user, to_proto, arg=None, to_user=None) => (str, None)

    If it returns a string, that text is sent to the user as a reply to their DM.

    Args for the decorated function:
      from_user (models.User): the user who sent the DM
      to_proto (protocol.Protocol): the protocol bot account they sent it to
      arg (str or None): the argument to the command, if any
      to_user (models.User or None): the user for the argument, if it's a handle

    The decorated function returns:
      str: text to reply to the user in a DM, if any
    """
    assert arg in (False, True, 'handle'), arg
    if handle_bridged is not None:
        assert arg == 'handle', arg

    def decorator(fn):
        def wrapped(from_user, to_proto, cmd, cmd_arg, dm_as1):
            def reply(text, type=None):
                maybe_send(from_proto=to_proto, to_user=from_user, text=text,
                           type=type, in_reply_to=dm_as1.get('id'))
                return 'OK', 200

            if arg and not cmd_arg:
                return reply(f'{cmd} command needs an argument<br><br>{help_text(from_user, to_proto)}')

            if arg == 'handle':
                if not to_proto.owns_handle(cmd_arg) and cmd_arg.startswith('@'):
                    logging.info(f"doesn't look like a handle, trying without leading @")
                    cmd_arg = cmd_arg.removeprefix('@')

                to_user = load_user(to_proto, cmd_arg)
                from_proto = from_user.__class__
                if not to_user:
                    return reply(f"Couldn't find user {cmd_arg} on {to_proto.PHRASE}")
                elif (handle_bridged is not None
                      and handle_bridged != to_user.is_enabled(from_proto)):
                    return reply(f'{to_user.user_link(proto=from_proto)} is {"not" if handle_bridged else "already"} bridged into {from_proto.PHRASE}.')

            from_user_enabled = from_user.is_enabled(to_proto)
            if user_bridged is True and not from_user_enabled:
                return reply(f"Looks like you're not bridged to {to_proto.PHRASE} yet! Please bridge your account first by following this account.")
            elif user_bridged is False and from_user_enabled:
                return reply(f"Looks like you're already bridged to {to_proto.PHRASE}!")
            # dispatch!
            kwargs = {}
            if arg and cmd_arg:
                kwargs['arg'] = cmd_arg
            if arg == 'handle':
                kwargs['to_user'] = to_user
            reply_text = fn(from_user, to_proto, **kwargs)
            if reply_text:
                reply(reply_text)

            return 'OK', 200

        if names is None:
            assert None not in _commands
            _commands[None] = wrapped
        else:
            assert isinstance(names, (tuple, list))
            for name in names:
                _commands[name] = wrapped

        return wrapped

    return decorator


def help_text(from_user, to_proto):
    extra = ''
    if to_proto.LABEL == 'atproto':
        extra = """<li><em>did</em>: get your bridged Bluesky account's <a href="https://atproto.com/guides/identity#identifiers">DID</a>"""

    text = f"""\
<p>Hi! I'm a friendly bot that can help you bridge your account into {to_proto.PHRASE}. Here are some commands I respond to:</p>
<ul>
<li><em>start</em>: enable bridging for your account
<li><em>stop</em>: disable bridging for your account
<li><em>notify</em>: enable notifications when someone who's not bridged replies to you, quotes you, or @-mentions you
<li><em>mute</em>: disable notifications
<li><em>username [domain]</em>: set a custom domain username (handle)
<li><em>[handle]</em>: ask me to DM a user on {to_proto.PHRASE} to request that they bridge their account into {from_user.PHRASE}
<li><em>block [handle]</em>: block a user on {to_proto.PHRASE} who's not bridged here
<li><em>unblock [handle]</em>: unblock a user on {to_proto.PHRASE} who's not bridged here
{extra}
<li><em>help</em>: print this message
</ul>"""
# <li><em>migrate-to [handle]</em>: migrate your bridged account on {to_proto.PHRASE} out of Bridgy Fed to a native account

    if from_user.LABEL == 'atproto':
        text = source.html_to_text(text, ignore_emphasis=True)

    return text

@command(['?', 'help', 'commands', 'info', 'hi', 'hello'])
def help(from_user, to_proto):
    return help_text(from_user, to_proto)


@command(['yes', 'ok', 'start'], user_bridged=False)
def start(from_user, to_proto):
    from_user.enable_protocol(to_proto)
    to_proto.bot_follow(from_user)


@command(['no', 'stop'])
def stop(from_user, to_proto, user_bridged=True):
    from_user.delete(to_proto)
    from_user.disable_protocol(to_proto)


@command(['notify'], user_bridged=True)
def notify(from_user, to_proto):
    from_user.send_notifs = 'all'
    from_user.put()
    return f"Notifications enabled! You'll now receive batched notifications via DM when someone on {to_proto.PHRASE} who's not bridged replies to you, quotes you, or @-mentions you."


@command(['mute'], user_bridged=True)
def mute(from_user, to_proto):
    from_user.send_notifs = 'none'
    from_user.put()
    return f"Notifications disabled. You won't receive DM notifications when someone on {to_proto.PHRASE} who's not bridged replies to you, quotes you, or @-mentions you."


@command(['did'], user_bridged=True)
def did(from_user, to_proto):
    if to_proto.LABEL == 'atproto':
        return f'Your DID is <code>{from_user.get_copy(PROTOCOLS["atproto"])}</code>'


@command(['username', 'handle'], arg=True, user_bridged=True)
def username(from_user, to_proto, arg):
    try:
        to_proto.set_username(from_user, arg)
    except NotImplementedError:
        return f"Sorry, Bridgy Fed doesn't support custom usernames for {to_proto.PHRASE} yet."
    except (ValueError, RuntimeError) as e:
        return str(e)

    return f"Your username in {to_proto.PHRASE} has been set to {from_user.user_link(proto=to_proto, name=False, handle=True)}. It should appear soon!"


@command(['block'], arg='handle', user_bridged=True)
def block(from_user, to_proto, arg, to_user):
    id = f'{from_user.key.id()}#bridgy-fed-block-{util.now().isoformat()}'
    obj = Object(id=id, source_protocol=from_user.LABEL, our_as1={
        'objectType': 'activity',
        'verb': 'block',
        'id': id,
        'actor': from_user.key.id(),
        'object': to_user.key.id(),
    })
    obj.put()
    from_user.deliver(obj, from_user=from_user)
    return f"""OK, you're now blocking {to_user.user_link()} on {to_proto.PHRASE}."""


@command(['unblock'], arg='handle', user_bridged=True)
def unblock(from_user, to_proto, arg, to_user):
    id = f'{from_user.key.id()}#bridgy-fed-unblock-{util.now().isoformat()}'
    obj = Object(id=id, source_protocol=from_user.LABEL, our_as1={
        'objectType': 'activity',
        'verb': 'undo',
        'id': id,
        'actor': from_user.key.id(),
        'object': {
            'objectType': 'activity',
            'verb': 'block',
            'actor': from_user.key.id(),
            'object': to_user.key.id(),
        },
    })
    obj.put()
    from_user.deliver(obj, from_user=from_user)
    return f"""OK, you're not blocking {to_user.user_link()} on {to_proto.PHRASE}."""


@command(['migrate-to'], arg='handle', user_bridged=True)
def migrate_to(from_user, to_proto, arg, to_user):
    try:
        to_proto.migrate_out(from_user, to_user.key.id())
    except ValueError as e:
        return str(e)

    return f"OK, we'll migrate your bridged account on {to_proto.PHRASE} to {to_user.user_link()}."


@command(None, arg='handle', user_bridged=True)  # no command, just the handle, alone
def prompt(from_user, to_proto, arg, to_user):
    from_proto = from_user.__class__
    try:
        ids.translate_handle(handle=arg, from_=to_proto, to=from_user, enhanced=False)
    except ValueError as e:
        logger.warning(e)
        return f"Sorry, Bridgy Fed doesn't yet support bridging handle {arg} from {to_proto.PHRASE} to {from_proto.PHRASE}."

    if to_user.is_enabled(from_proto):
        # already bridged
        return f'{to_user.user_link(proto=from_proto)} is already bridged into {from_proto.PHRASE}.'

    elif (models.DM(protocol=from_proto.LABEL, type='request_bridging')
          in to_user.sent_dms):
        # already requested
        return f"We've already sent {to_user.user_link()} a DM. Fingers crossed!"

    # check and update rate limits
    attempts_key = f'dm-user-requests-{from_user.LABEL}-{from_user.key.id()}'
    # incr leaves existing expiration as is, doesn't change it
    # https://stackoverflow.com/a/4084043/186123
    attempts = memcache.memcache.incr(attempts_key, 1)
    if not attempts:
        memcache.memcache.add(
            attempts_key, 1,
            expire=int(REQUESTS_LIMIT_EXPIRE.total_seconds()))
    elif attempts > REQUESTS_LIMIT_USER:
        return f"Sorry, you've hit your limit of {REQUESTS_LIMIT_USER} requests per day. Try again tomorrow!"

    # send the DM request!
    maybe_send(from_proto=from_proto, to_user=to_user, type='request_bridging', text=f"""\
<p>Hi! {from_user.user_link(proto=to_proto, proto_fallback=True)} is using Bridgy Fed to bridge their account from {from_proto.PHRASE} into {to_proto.PHRASE}, and they'd like to follow you. You can bridge your account into {from_proto.PHRASE} by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.
<p>If you do nothing, your account won't be bridged, and users on {from_proto.PHRASE} won't be able to see or interact with you.
<p>Bridgy Fed will only send you this message once.""")
    return f"Got it! We'll send {to_user.user_link()} a message and say that you hope they'll enable the bridge. Fingers crossed!"


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

    now = util.now().isoformat()
    dm_id = f'{bot.profile_id()}#bridgy-fed-dm-{type or "?"}-{to_user.key.id()}-{now}'
    dm_as1 = {
        'objectType': 'note',
        'id': dm_id,
        'author': bot.key.id(),
        'content': text,
        'inReplyTo': in_reply_to,
        'tags': [{
            'objectType': 'mention',
            'url': to_user.key.id(),
        }],
        'published': now,
        'to': [to_user.key.id()],
    }
    Object(id=dm_id, our_as1=dm_as1, source_protocol='web').put()

    create_id = f'{dm_id}-create'
    create_as1 = {
        'objectType': 'activity',
        'verb': 'post',
        'id': create_id,
        'actor': bot.key.id(),
        'object': dm_as1,
        'published': now,
        'to': [to_user.key.id()],
    }

    target_uri = to_user.target_for(to_user.obj, shared=False)
    target = models.Target(protocol=to_user.LABEL, uri=target_uri)
    create_task(queue='send', id=create_id, our_as1=create_as1, source_protocol='web',
                protocol=to_user.LABEL, url=target.uri, user=bot.key.urlsafe())

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

    inner_as1 = (as1.get_object(obj.as1) if as1.object_type(obj.as1) == 'post'
                 else obj.as1)
    logger.info(f'got DM from {from_user.key.id()} to {to_proto.LABEL}: {inner_as1.get("content")}')

    # parse message
    text = util.remove_invisible_chars(source.html_to_text(inner_as1.get('content', '')))
    tokens = text.strip().lower().split()
    logger.info(f'  tokens: {tokens}')

    # remove @-mention of bot, if any
    bot_handles = (DOMAINS + ids.BOT_ACTOR_AP_IDS
                   + tuple(h.lstrip('@') for h in ids.BOT_ACTOR_AP_HANDLES))
    if tokens and tokens[0].lstrip('@') in bot_handles:
        logger.debug(f'  first token is bot mention, removing')
        tokens = tokens[1:]

    if not tokens or len(tokens) > 2:
        return r'¯\_(ツ)_/¯', 204

    if fn := _commands.get(tokens[0]):
        return fn(from_user, to_proto, dm_as1=inner_as1,
                  cmd=tokens[0], cmd_arg=tokens[1] if len(tokens) == 2 else None)
    elif len(tokens) == 1:
        fn = _commands.get(None)
        assert fn, tokens[0]
        return fn(from_user, to_proto, dm_as1=inner_as1, cmd=None, cmd_arg=tokens[0])

    return r'¯\_(ツ)_/¯', 204


def load_user(proto, handle):
    """
    Args:
      proto (protocol.Protocol)
      handle (str)

    Returns:
      models.User or None
    """
    if proto.owns_handle(handle) is False:
        return None

    if id := proto.handle_to_id(handle):
        if user := proto.get_or_create(id):
            if user.obj:
                return user


@cloud_tasks_only(log=None)
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

    if not (notifs := memcache.get_notifications(user, clear=True)):
        logger.info(f'No notifications for {user_id}')
        return '', 204

    from_proto_label = (user.enabled_protocols[0] if user.enabled_protocols
        else user.DEFAULT_ENABLED_PROTOCOLS[0] if user.DEFAULT_ENABLED_PROTOCOLS
        else None)
    if not from_proto_label:
        logger.info(f"User {user_id} isn't enabled")
        return '', 204

    message = "<p>Hi! Here are your recent interactions from people who aren't bridged into fake-phrase:\n<ul>\n"
    for url in notifs:
        message += f'<li>{util.pretty_link(url)}\n'
    message += '</ul>\n<p>To disable these messages, reply with the text <em>mute</em>.'

    logger.info(f'sending notifications DM for {user_id}')
    maybe_send(from_proto=PROTOCOLS[from_proto_label], to_user=user, text=message)

    return '', 200
