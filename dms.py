"""Protocol-independent code for sending and receiving DMs aka chat messages."""
from dataclasses import dataclass
from datetime import timedelta
import inspect
import logging
from typing import Callable, Optional

from granary import as1, source
from oauth_dropins.webutil import util
from werkzeug.exceptions import BadRequest

from collections import namedtuple
import common
from common import create_task
from domains import DOMAINS
import ids
import memcache
import models
import protocol

REQUESTS_LIMIT_EXPIRE = timedelta(days=1)
REQUESTS_LIMIT_USER = 10

# populated by the command() decorator
# {str command name: {str protocol label or None: wrapped dispatch fn}}
_commands = {}

logger = logging.getLogger(__name__)


@dataclass
class CommandSpec:
    fn: Callable
    from_user_bridged: Optional[bool]
    """Whether the user sending the DM should be bridged.
       ``True``, ``False``, or ``None`` for either."""
    to_user_bridged: object        # True / False / 'eligible' / None
    """Whether ``to_user`` should already be bridged. ``True``, ``False``,
       ``None`` for either, or ``'eligible'`` for not bridged but eligible."""


def command(names, *, to_proto=None, from_user_bridged=None, to_user_bridged=None):
    """Function decorator. Defines and registers a DM command.

    The decorated function's signature determines the cmd_args it accepts.
    After ``(from_user, to_proto)``, required positionals are required cmd_args,
    defaulted positionals are optional, and ``*args`` accepts any number.

    If the function declares a ``to_user`` parameter, ``cmd_args[0]`` is loaded via
    :func:`load_user` and passed in.

    Args:
      names (sequence of str): the command strings that trigger this command, or
        ``None`` if this command has no command string
      to_proto (str): if set, only dispatch to this handler when the DM's
        recipient protocol has this ``LABEL``. If ``None``, this handler is the
        generic fallback for any ``to_proto`` without a specific handler.
      from_user_bridged (bool): whether the user sending the DM should be
        bridged. ``True``, ``False``, or ``None`` for either.
      to_user_bridged: whether ``to_user`` should already be bridged. ``True``,
        ``False``, ``None`` for either, or ``'eligible'`` for not bridged but
        eligible.
    """
    def decorator(fn):
        spec = CommandSpec(fn=fn, from_user_bridged=from_user_bridged,
                           to_user_bridged=to_user_bridged)

        def wrapped(from_user, to_proto, cmd, cmd_args, dm_as1):
            return dispatch(spec, from_user, to_proto, cmd, cmd_args, dm_as1)

        if names is None:
            names_ = [None]
        else:
            assert isinstance(names, (tuple, list))
            names_ = names

        for name in names_:
            by_proto = _commands.setdefault(name, {})
            assert to_proto not in by_proto, \
                f'duplicate command {name} for to_proto {to_proto}'
            by_proto[to_proto] = wrapped

        return wrapped

    return decorator


def load_user(handle, proto, from_proto, bridged):
    """Loads the user for ``handle`` and applies the ``bridged`` policy.

    Args:
      handle (str): the handle or id to look up
      proto (protocol.Protocol): the protocol the handle belongs to
      from_proto (protocol.Protocol): the sender's protocol, used for the
        ``bridged`` enabled check
      bridged (bool or str): whether the user should be bridged into ``from_proto``.
        ``True``, ``False``, ``None`` for either, or ``'eligible'`` for not bridged
        but eligible.

    Returns:
      models.User:

    Raises: ValueError
    """
    try:
        to_user = models.load_user(handle, proto, create=True, allow_opt_out=True,
                                   raise_=True)
    except (AttributeError, RuntimeError) as err:
        raise ValueError(str(err))

    assert to_user

    enabled = to_user.is_enabled(from_proto)
    if bridged is True and not enabled:
        raise ValueError(f'{to_user.html_link(proto=from_proto)} is not bridged into {from_proto.PHRASE}.')
    if bridged in (False, 'eligible') and enabled:
        raise ValueError(f'{to_user.html_link(proto=from_proto)} is already bridged into {from_proto.PHRASE}.')
    if bridged == 'eligible' and to_user.status:
        to_user.reload_profile()
        if to_user.status:
            because = ''
            if desc := to_user.status_description():
                because = f' because their {desc}'
            raise ValueError(f"{to_user.html_link()} on {proto.PHRASE} isn't eligible for bridging into {from_proto.PHRASE}{because}.")

    return to_user


def dispatch(spec, from_user, to_proto, cmd, cmd_args, dm_as1):
    """Dispatches a parsed DM command to its handler.

    Validates ``cmd_args``, optionally loads ``to_user`` via :func:`load_user`,
    enforces ``spec.from_user_bridged``, then invokes ``spec.fn`` and sends its
    return value (if any) as a reply.

    Args:
      spec (CommandSpec): the registered command's spec
      from_user (models.User): the user who sent the DM
      to_proto (protocol.Protocol): the protocol bot account they sent it to
      cmd (str or None): the command name as typed, used in error messages
      cmd_args (list of str): the tokens after the command name
      dm_as1 (dict): the inbound DM as AS1; ``id`` is used as the reply's
        ``inReplyTo``

    Returns:
      (str, int): a ``(body, status)`` tuple suitable for returning from a
        Flask view. Always ``('OK', 200)`` once a reply (if any) is sent.
    """
    def reply(text):
        maybe_send(from_=to_proto, to_user=from_user, text=text,
                   in_reply_to=dm_as1.get('id'))
        return 'OK', 200

    # validate
    sig = inspect.signature(spec.fn)
    params = list(sig.parameters.values())
    has_to_user = any(p.name == 'to_user' for p in params)
    if spec.to_user_bridged is not None:
        assert has_to_user, f'{spec.fn.__name__}: to_user_bridged requires a to_user parameter'

    # validate fn signature
    bind_sig = sig.replace(parameters=[p for p in params if p.name != 'to_user'])
    try:
        bind_sig.bind(from_user, to_proto, *cmd_args)
    except TypeError as e:
        return reply(f'{cmd}: {e}<br><br>{help_text(from_user, to_proto)}')

    kwargs = {}
    if has_to_user:
        try:
            to_user = load_user(cmd_args[0], to_proto, from_user.__class__,
                                spec.to_user_bridged)
        except ValueError as err:
            return reply(str(err))
        kwargs['to_user'] = to_user

    enabled = from_user.is_enabled(to_proto)
    if spec.from_user_bridged is True and not enabled:
        return reply(f"Looks like you're not bridged to {to_proto.PHRASE} yet! Please bridge your account first by following this account.")
    if spec.from_user_bridged is False and enabled:
        return reply(f"Looks like you're already bridged to {to_proto.PHRASE}!")

    reply_text = spec.fn(from_user, to_proto, *cmd_args, **kwargs)
    if reply_text:
        reply(reply_text)
    return 'OK', 200


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
<li><em>[handle or ID]</em>: ask me to DM a user on {to_proto.PHRASE} to request that they bridge their account into {from_user.PHRASE}
<li><em>block [handle or ID or list URL]...</em>: block one or more users who aren't bridged here, and/or lists, on {to_proto.PHRASE}
<li><em>unblock [handle or ID or list URL]...</em>: unblock one or more users who aren't bridged here, and/or lists, on {to_proto.PHRASE}
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


@command(['yes', 'ok', 'start'], from_user_bridged=False)
def start(from_user, to_proto):
    from_user.enable_protocol(to_proto)
    to_proto.bot_maybe_follow_back(from_user)


@command(['no', 'stop'])
def stop(from_user, to_proto):
    from_user.delete(to_proto)
    from_user.disable_protocol(to_proto)


@command(['notify'], from_user_bridged=True)
def notify(from_user, to_proto):
    from_user.send_notifs = 'all'
    from_user.put()
    return f"Notifications enabled! You'll now receive batched notifications via DM when someone on {to_proto.PHRASE} who's not bridged replies to you, quotes you, or @-mentions you. To disable, reply with the text 'mute'."


@command(['mute'], from_user_bridged=True)
def mute(from_user, to_proto):
    from_user.send_notifs = 'none'
    from_user.put()
    return f"Notifications disabled. You won't receive DM notifications when someone on {to_proto.PHRASE} who's not bridged replies to you, quotes you, or @-mentions you. To re-enable, reply with the text 'notify'."


@command(['did'], from_user_bridged=True)
def did(from_user, to_proto):
    if to_proto.LABEL == 'atproto':
        return f'Your DID is <code>{from_user.get_copy(models.PROTOCOLS["atproto"])}</code>'


@command(['username', 'handle'], from_user_bridged=True)
def username(from_user, to_proto, handle):
    try:
        to_proto.set_username(from_user, handle)
    except NotImplementedError:
        return f"Sorry, Bridgy Fed doesn't support custom usernames for {to_proto.PHRASE} yet."
    except (ValueError, RuntimeError) as e:
        return str(e)

    return f"Your username in {to_proto.PHRASE} has been set to {from_user.html_link(proto=to_proto, name=False, handle=True)}. It should appear soon!"


@command(['block'], from_user_bridged=True)
def block(from_user, to_proto, *handles):
    # duplicated in unblock
    links = []

    for handle in handles:
        try:
            result = to_proto.block(from_user, handle)
            links.append(result.html_link())
        except ValueError as e:
            return str(e)

    return f"""OK, you're now blocking {', '.join(links)} on {to_proto.PHRASE}."""


@command(['unblock'], from_user_bridged=True)
def unblock(from_user, to_proto, *handles):
    # duplicated in block
    links = []

    for handle in handles:
        try:
            result = to_proto.unblock(from_user, handle)
            links.append(result.html_link())
        except ValueError as e:
            return str(e)

    return f"""OK, you're not blocking {', '.join(links)} on {to_proto.PHRASE}."""


@command(['migrate-to'], from_user_bridged=True)
def migrate_to(from_user, to_proto, handle, *, to_user):
    try:
        to_proto.check_can_migrate_out(from_user, to_user.key.id())
        to_proto.migrate_out(from_user, to_user.key.id())
    except ValueError as e:
        msg = str(e)

        # WARNING: this is brittle! depends on the exact exception message
        # from ActivityPub.check_can_migrate_out
        if "alsoKnownAs doesn't contain" in msg:
            return f"First, you'll need to <a href='https://docs.joinmastodon.org/user/moving/#summary'>add an alias</a> for this account. In the account settings for {to_user.handle}, add an alias to <code>{from_user.handle_as(to_proto)}</code>."

        return msg

    return f"OK, we'll migrate your bridged account on {to_proto.PHRASE} to {to_user.html_link()}."


@command(None, from_user_bridged=True, to_user_bridged='eligible')
def prompt(from_user, to_proto, handle, *, to_user):
    """Prompt a non-bridged user to bridge. No command, just the handle, alone."""
    from_proto = from_user.__class__
    try:
        ids.translate_handle(handle=to_user.handle, from_=to_proto, to=from_user)
    except ValueError as e:
        logger.warning(e)
        return f"Sorry, Bridgy Fed doesn't yet support bridging handle {handle} from {to_proto.PHRASE} to {from_proto.PHRASE}."

    if (models.DM(protocol=from_proto.LABEL, type='request_bridging')
          in to_user.sent_dms):
        # already requested
        return f"We've already sent {to_user.html_link()} a DM. Fingers crossed!"

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
    maybe_send(from_=from_proto, to_user=to_user, type='request_bridging', text=f"""\
<p>Hi! {from_user.html_link(proto=to_proto, proto_fallback=True)} is using Bridgy Fed to bridge their account from {from_proto.PHRASE} into {to_proto.PHRASE}, and they'd like to follow you. You can bridge your account into {from_proto.PHRASE} by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.
<p>If you do nothing, your account won't be bridged, and users on {from_proto.PHRASE} won't be able to see or interact with you.
<p>Bridgy Fed will only send you this message once.""")
    return f"Got it! We'll send {to_user.html_link()} a message and say that you hope they'll enable the bridge. Fingers crossed!"


def maybe_send(*, from_, to_user, text, type=None, in_reply_to=None, **kwargs):
    """Sends a DM.

    Creates a task to send the DM asynchronously.

    If ``type`` is provided, and we've already sent this user a DM of this type
    from this protocol, does nothing.

    Args:
      from_ (protocol.Protocol or models.User)
      to_user (models.User)
      text (str): message content. May be HTML.
      type (str): optional, one of DM.TYPES
      in_reply_to (str): optional, ``id`` of a DM to reply to
      kwargs: added to the outgoing DM activity as additional (AS1) fields
    """
    if not to_user.SUPPORTS_DMS:
        return

    from_proto = from_
    if not isinstance(from_, models.User):
        assert issubclass(from_, protocol.Protocol)
        from web import Web
        if not (from_ := Web.get_by_id(from_.bot_user_id())):
            logger.info(f'not sending DM, {from_proto.LABEL} has no bot user')
            return

    if type:
        dm = models.DM(protocol=from_proto.LABEL, type=type)
        if dm in to_user.sent_dms:
            return

    logger.info(f'Sending DM from {from_.key.id()} to {to_user.key.id()} : {text}')

    if not to_user.obj or not to_user.obj.as1:
        logger.info("  can't send DM, recipient has no profile obj")
        return

    now = util.now().isoformat()
    dm_id = f'{from_.profile_id()}#bridgy-fed-dm-{type or "?"}-{to_user.key.id()}-{now}'
    dm_as1 = {
        'objectType': 'note',
        'id': dm_id,
        'author': from_.key.id(),
        'content': text,
        'inReplyTo': in_reply_to,
        'tags': [{
            'objectType': 'mention',
            'url': to_user.key.id(),
        }],
        'published': now,
        'to': [to_user.key.id()],
        **kwargs,
    }
    models.Object(id=dm_id, our_as1=dm_as1).put()

    create_id = f'{dm_id}-create'
    create_as1 = {
        'objectType': 'activity',
        'verb': 'post',
        'id': create_id,
        'actor': from_.key.id(),
        'object': dm_as1,
        'published': now,
        'to': [to_user.key.id()],
    }

    target_uri = to_user.target_for(to_user.obj, shared=False)
    target = models.Target(protocol=to_user.LABEL, uri=target_uri)
    create_task(queue='send', id=create_id, our_as1=create_as1, source_protocol='web',
                protocol=to_user.LABEL, url=target.uri, user=from_.key.urlsafe())

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
    # preserve case because some args are case sensitive, eg migrate-to password
    tokens = text.strip().split()
    logger.info(f'  tokens: {tokens}')

    # remove @-mention of bot, if any
    bot_handles = (DOMAINS + ids.BOT_ACTOR_AP_IDS
                   + tuple(h.lstrip('@') for h in ids.BOT_ACTOR_AP_HANDLES))
    if tokens and tokens[0].lstrip('@').lower() in bot_handles:
        logger.debug(f'  first token is bot mention, removing')
        tokens = tokens[1:]

    if not tokens:
        return r'¯\_(ツ)_/¯', 204

    cmd = tokens[0].lower()
    if command := _commands.get(cmd):
        args = tokens[1:]
    elif len(tokens) == 1:  # implicit req't: the no-command prompt to request a user
                            # to bridge only accepts a single arg
        command = _commands[None]
        cmd = None
        args = tokens
    else:
        return r'¯\_(ツ)_/¯', 204

    fn = command.get(to_proto.LABEL) or command[None]
    return fn(from_user, to_proto, dm_as1=inner_as1, cmd=cmd, cmd_args=args)
