"""Nostr backfeed, via long-lived websocket connection(s) to relay(s)."""
from datetime import datetime, timedelta
import logging
import secrets
from threading import Event, Lock, Thread, Timer
import time

import cachetools
from google.cloud.ndb import context
from google.cloud.ndb.exceptions import ContextError
from granary.nostr import (
    KIND_DELETE,
    KIND_REACTION,
    KIND_RELAYS,
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
from models import Object, PROTOCOLS
from nostr import normalize_relay_uri, Nostr, NostrRelay
from protocol import DELETE_TASK_DELAY
from ui import UIProtocol

logger = logging.getLogger(__name__)

AUTHOR_FILTER_KINDS = list(Nostr.SUPPORTED_KINDS - {KIND_REACTION})
RECONNECT_DELAY = timedelta(seconds=10)
LOAD_USERS_FREQ = timedelta(seconds=10)
STORE_RELAY_SINCE_FREQ = timedelta(seconds=10)

# global: _load_pubkeys populates them, subscribe uses them
nostr_pubkeys = set()
bridged_pubkeys = set()
pubkeys_loaded_at = datetime(1900, 1, 1)
pubkeys_initialized = Event()

seen_ids = cachetools.TTLCache(maxsize=1_000_000,
                               ttl=timedelta(weeks=1).total_seconds())
seen_ids_lock = Lock()

# maps string relay websocket address URI to NostrRelay
subscribed_relays = {}
subscribed_relays_lock = Lock()


def ndb_context():
    if ctx := context.get_context(raise_context_error=False):
        return ctx.use()

    return ndb_client.context(**NDB_CONTEXT_KWARGS)


def init(subscribe=True):
    logger.info('Starting _load_users timer')
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_users, daemon=True, name='nostr_hub._load_users',
           kwargs={'subscribe': subscribe}).start()
    pubkeys_initialized.wait()
    pubkeys_initialized.clear()

    if subscribe:
        with ndb_context():
            add_relay(Nostr.DEFAULT_TARGET)


def _load_users(subscribe=True):
    global pubkeys_loaded_at

    if not DEBUG:
        Timer(LOAD_USERS_FREQ.total_seconds(), _load_users).start()

    with ndb_context():
        try:
            loaded_at = util.now().replace(tzinfo=None)

            new_nostr = Nostr.query(Nostr.status == None,
                                    Nostr.enabled_protocols != None,
                                    Nostr.updated > pubkeys_loaded_at,
                                    ).fetch()
            Nostr.load_multi(new_nostr)
            for user in new_nostr:
                nostr_pubkeys.add(uri_to_id(user.key.id()))
                if subscribe and (target := Nostr.target_for(user.obj)):
                    add_relay(target)

            new_bridged = []
            for proto in PROTOCOLS.values():
                if proto and proto not in (Nostr, UIProtocol):
                    # query for all users, then filter for nostr enabled
                    users = proto.query(proto.status == None,
                                        proto.enabled_protocols == 'nostr',
                                        proto.updated > pubkeys_loaded_at,
                                        ).fetch()
                    new_bridged.extend(users)

            bridged_pubkeys.update(user.hex_pubkey() for user in new_bridged)

            # set *after* we populate bridged_pubkeys and nostr_pubkeys so that if we
            # crash earlier, we re-query from the earlier timestamp
            pubkeys_loaded_at = loaded_at
            pubkeys_initialized.set()
            total = len(nostr_pubkeys) + len(bridged_pubkeys)
            logger.info(f'Nostr pubkeys: {total}, Nostr {len(nostr_pubkeys)} (+{len(new_nostr)}), bridged {len(bridged_pubkeys)} (+{len(new_bridged)})')

        except BaseException:
            # eg google.cloud.ndb.exceptions.ContextError when we lose the ndb context
            # https://console.cloud.google.com/errors/detail/CLO6nJnRtKXRyQE?project=bridgy-federated
            report_exception()


def add_relay(uri):
    """Subscribes to a new relay if we're not already connected to it.

    Args:
      uri (str): URI, relay websocket adddress, starting with ``ws://`` or ``wss://``
    """
    uri = normalize_relay_uri(uri)
    if Nostr.is_blocklisted(uri):
        logger.warning(f'Not subscribing to relay {uri}')
        return

    with subscribed_relays_lock:
        if uri not in subscribed_relays:
            relay = NostrRelay.get_or_insert(uri)
            subscribed_relays[uri] = relay
            Thread(target=subscriber, daemon=True, args=(relay,),
                   name=f'nostr_hub.subscriber {uri}').start()


def subscriber(relay):
    """Wrapper around :func:`_subscribe` that catches exceptions and reconnects.

    Args:
      relay (NostrRelay)
    """
    logger.info(f'started thread to subscribe to relay {relay.key.id()}')

    with ndb_context():
        while True:
            try:
                subscribe(relay)
            except (ConnectionClosed, TimeoutError) as err:
                logger.warning(err)
                logger.info(f'disconnected! waiting {RECONNECT_DELAY}, then reconnecting')
            except BaseException as err:
                report_exception()

            if DEBUG:
                return

            time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe(relay, limit=None):
    """Subscribes to relay(s), backfeeds responses to our users' activities.

    Args:
      relay (NostrRelay)
      limit (int): return after receiving this many messages. Only used in tests.
    """
    if not DEBUG:
        assert limit is None

    uri = relay.key.id()
    with connect(uri, user_agent_header=util.user_agent,
                 open_timeout=util.HTTP_TIMEOUT, close_timeout=util.HTTP_TIMEOUT,
                 ) as ws:
        while True:
            nostr_pubkeys_count = len(nostr_pubkeys)
            bridged_pubkeys_count = len(bridged_pubkeys)

            received = 0
            subscription = secrets.token_urlsafe(16)
            req = [
                'REQ', subscription,
                {
                    '#p': sorted(bridged_pubkeys),
                    'kinds': list(Nostr.SUPPORTED_KINDS),
                },
                {
                    'authors': sorted(nostr_pubkeys),
                    'kinds': AUTHOR_FILTER_KINDS,
                },
            ]
            # ideally this should prevent us seeing and handling many duplicate
            # events. since is compared against events' created_at, though, which is
            # client-provided, so malicious clients could publish events in the
            # future, which would always come back as results. is there any way to
            # handle/prevent that?
            #
            # some discussion in https://github.com/nostr-protocol/nips/issues/407 ,
            # but I don't fully follow it, and it doesn't have a solution anyway.
            if relay.since:
                req[2]['since'] = req[3]['since'] = relay.since

            req = json_dumps(req)
            logger.debug(f'{uri} {ws.remote_address} <= {req}')
            ws.send(req)

            while True:
                if (nostr_pubkeys_count != len(nostr_pubkeys)
                        or bridged_pubkeys_count != len(bridged_pubkeys)):
                    logger.info(f're-querying to pick up new user(s)')
                    ws.send(json_dumps(['CLOSE', subscription]))
                    break

                try:
                    # use timeout to make sure we periodically loop and check whether
                    # we've loaded any new users, above, and need to re-query
                    msg = ws.recv(timeout=util.HTTP_TIMEOUT)
                except TimeoutError:
                    continue

                logger.debug(f'{ws.remote_address} => {msg}')
                resp = json_loads(msg)

                # https://nips.nostr.com/1
                event = None
                match resp[0]:
                    case 'EVENT':
                        event = resp[2]
                        if event.get('kind') in Nostr.SUPPORTED_KINDS:
                            with seen_ids_lock:
                                id = event.get('id')
                                if not (seen := id in seen_ids):
                                    seen_ids[id] = True

                            if not seen:
                                handle(event)

                    case 'CLOSED':
                        # relay closed our query. reconnect!
                        relay.put()
                        break

                    case 'OK':
                        # TODO: this is a response to an EVENT we sent
                        pass

                    case 'EOSE':
                        # switching from stored results to live
                        pass

                    case 'NOTICE':
                        # already logged this
                        pass

                # update stored relay timestamp if it's been a while
                if event and (created_at := event.get('created_at')):
                    relay.since = int(created_at)
                    elapsed = util.now() - relay.updated
                    if elapsed > STORE_RELAY_SINCE_FREQ:
                        behind_s = util.now().timestamp() - relay.since
                        logger.info(f"updating {uri}'s since to {relay.since}, {behind_s} s behind")
                        relay.put()

                # for unit tests
                received += 1
                if limit and received >= limit:
                    relay.put()
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

    logger.debug(f'Got Nostr event {id} from {pubkey}')
    obj_id = 'nostr:' + id
    authed_as = 'nostr:' + pubkey

    # special case relay events, just store them
    if event.get('kind') == KIND_RELAYS and pubkey in nostr_pubkeys:
        obj = Object.get_or_create(obj_id, nostr=event, authed_as=authed_as,
                                   source_protocol=Nostr.LABEL)
        if user := Nostr.get_by_id(authed_as):
            user.relays = obj.key
            user.put()
        return

    delay = DELETE_TASK_DELAY if event.get('kind') == KIND_DELETE else None
    try:
        create_task(queue='receive', id=obj_id, source_protocol=Nostr.LABEL,
                    authed_as=authed_as, nostr=event, delay=delay)
        # when running locally, comment out above and uncomment this
        # logger.info(f'enqueuing receive task for {obj_id}')
    except ContextError:
        raise  # handled in subscriber()
    except BaseException:
        report_exception(obj_id)
