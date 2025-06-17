"""Nostr backfeed, via long-lived websocket connection(s) to relay(s)."""
from datetime import datetime, timedelta
import logging
import secrets
from threading import Event, Lock, Thread, Timer
import time

from google.cloud.ndb.exceptions import ContextError
from granary.nostr import (
    id_to_uri,
    KIND_DELETE,
    uri_for,
    uri_to_id,
    verify,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.util import HTTP_TIMEOUT, json_dumps, json_loads
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from common import (
    create_task,
    NDB_CONTEXT_KWARGS,
    report_error,
    report_exception,
)
from models import PROTOCOLS
import nostr
from nostr import Nostr
from protocol import DELETE_TASK_DELAY

logger = logging.getLogger(__name__)

RECONNECT_DELAY = timedelta(seconds=30)
LOAD_USERS_FREQ = timedelta(seconds=10)

# global: _load_pubkeys populates them, subscribe uses them
nostr_pubkeys = set()
nostr_loaded_at = datetime(1900, 1, 1)
bridged_pubkeys = set()
bridged_loaded_at = datetime(1900, 1, 1)
pubkeys_initialized = Event()

subscribed_relays = []
subscribed_relays_lock = Lock()


def init(subscribe=True):
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_users, daemon=True).start()
    pubkeys_initialized.wait()
    pubkeys_initialized.clear()

    if subscribe:
        add_relay(Nostr.DEFAULT_TARGET)


def _load_users():
    global bridged_loaded_at, nostr_loaded_at

    if not DEBUG:
        Timer(LOAD_USERS_FREQ.total_seconds(), _load_users).start()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
        try:
            loaded_at = util.now()

            new_nostr = Nostr.query(Nostr.status == None,
                                    Nostr.enabled_protocols != None,
                                    Nostr.updated > nostr_loaded_at,
                                    ).fetch()
            Nostr.load_multi(new_nostr)
            for user in new_nostr:
                nostr_pubkeys.add(uri_to_id(user.key.id()))
                if target := Nostr.target_for(user.obj):
                    add_relay(target)

            # set *after* we populate nostr_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            nostr_loaded_at = loaded_at

            new_bridged = []
            for proto in PROTOCOLS.values():
                if proto and proto != Nostr:
                    # query for all users, then filter for nostr enabled
                    users = proto.query(proto.status == None,
                                       proto.enabled_protocols != None,
                                       proto.updated > bridged_loaded_at,
                                       ).fetch()
                    new_bridged.extend([u for u in users if u.is_enabled(Nostr)])

            bridged_pubkeys.update(user.hex_pubkey() for user in new_bridged)

            # set *after* we populate bridged_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            bridged_loaded_at = loaded_at

            pubkeys_initialized.set()
            total = len(nostr_pubkeys) + len(bridged_pubkeys)
            logger.info(f'Nostr pubkeys: {total}, Nostr {len(nostr_pubkeys)} (+{len(new_nostr)}), bridged {len(bridged_pubkeys)} (+{len(new_bridged)})')

        except BaseException:
            # eg google.cloud.ndb.exceptions.ContextError when we lose the ndb context
            # https://console.cloud.google.com/errors/detail/CLO6nJnRtKXRyQE?project=bridgy-federated
            report_exception()


def add_relay(relay):
    """Subscribes to a new relay if we're not already connected to it."""
    if Nostr.is_blocklisted(relay):
        logger.warning(f'Not subscribing to relay {relay}')
        return

    with subscribed_relays_lock:
        if relay not in subscribed_relays:
            subscribed_relays.append(relay)
            Thread(target=subscriber, daemon=True, args=(relay,)).start()


def subscriber(relay):
    """Wrapper around :func:`_subscribe` that catches exceptions and reconnects."""
    logger.info(f'started thread to subscribe to relay {relay}')

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
         while True:
            try:
                subscribe(relay)
            except ConnectionClosed as err:
                logger.warning(err)
            except BaseException:
                report_exception()
            logger.info(f'disconnected! waiting {RECONNECT_DELAY}, then reconnecting')
            time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe(relay, limit=None):
    """Subscribes to relay(s), backfeeds responses to our users' activities.

    Args:
      relay (str): URI, relay websocket adddress, starting with ``ws://`` or ``wss://``
      limit (int): return after receiving this many messages. Only used in tests.
    """
    with connect(relay, user_agent_header=util.user_agent,
                 open_timeout=util.HTTP_TIMEOUT, close_timeout=util.HTTP_TIMEOUT,
                 ) as ws:
        if not DEBUG:
            assert limit is None

        received = 0
        subscription = secrets.token_urlsafe(16)
        req = json_dumps([
            'REQ', subscription,
            {'#p': sorted(bridged_pubkeys)},
            {'authors': sorted(nostr_pubkeys)},
        ])
        logger.debug(f'{ws.remote_address} <= {req}')
        ws.send(req)

        while True:
            msg = ws.recv(timeout=HTTP_TIMEOUT)
            logger.debug(f'{ws.remote_address} => {msg}')
            resp = json_loads(msg)

            # https://nips.nostr.com/1
            match resp[0]:
                case 'EVENT':
                    handle(resp[2])

                case 'CLOSED':
                    # relay closed our query. reconnect!
                    return

                case 'OK':
                    # TODO: this is a response to an EVENT we sent
                    pass

                case 'EOSE':
                    # switching from stored results to live
                    pass

                case 'NOTICE':
                    # already logged this
                    pass

            received += 1
            if limit and received >= limit:
                return


def handle(event):
    """Handles a Nostr event. Enqueues a receive task for it if necessary.

    Args:
      event (dict): Nostr event
    """
    if not (isinstance(event, dict) and event.get('kind') is not None
            and event.get('pubkey') and event.get('id') and event.get('sig')):
        logger.info(f'ignoring bad event: {event}')
        return

    id = event['id']
    pubkey = event['pubkey']

    mentions = set(tag[1] for tag in event.get('tags', []) if tag[0] == 'p')

    if not (pubkey in nostr_pubkeys          # from a Nostr user who's bridged
            or mentions & bridged_pubkeys):  # mentions a user bridged into Nostr
        return

    if not verify(event):
        logger.debug(f'bad id or sig for {id}')
        return

    try:
        obj_id = uri_for(event)
        npub_uri = id_to_uri('npub', pubkey)
    except (TypeError, ValueError):
        logger.info(f'bad id {id} or pubkey {pubkey}')
        return
    logger.debug(f'Got Nostr event {obj_id} from {pubkey}')

    delay = DELETE_TASK_DELAY if event.get('kind') == KIND_DELETE else None
    try:
        create_task(queue='receive', id=obj_id, source_protocol=Nostr.LABEL,
                    authed_as=npub_uri, nostr=event, delay=delay)
        # when running locally, comment out above and uncomment this
        # logger.info(f'enqueuing receive task for {obj_id}')
    except ContextError:
        raise  # handled in subscriber()
    except BaseException:
        report_error(obj_id, exception=True)
