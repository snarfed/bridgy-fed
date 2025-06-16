"""Nostr backfeed, via long-lived websocket connection(s) to relay(s)."""
from datetime import datetime, timedelta, timezone
import logging
from threading import Event, Thread, Timer
import time

from google.cloud import ndb
from google.cloud.ndb.exceptions import ContextError
import granary.nostr
from granary.nostr import (
    bech32_decode,
    bech32_encode,
    id_to_uri,
    KIND_CONTACTS,
    KIND_DELETE,
)
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from common import (
    create_task,
    NDB_CONTEXT_KWARGS,
    PROTOCOL_DOMAINS,
    report_error,
    report_exception,
)
from models import PROTOCOLS
import nostr
from nostr import Nostr
from protocol import DELETE_TASK_DELAY
from web import Web

logger = logging.getLogger(__name__)

RECONNECT_DELAY = timedelta(seconds=30)
STORE_CURSOR_FREQ = timedelta(seconds=10)

# global: _load_pubkeys populates them, subscribe uses them
nostr_pubkeys = set()
nostr_loaded_at = datetime(1900, 1, 1)
bridged_pubkeys = set()
bridged_loaded_at = datetime(1900, 1, 1)
protocol_bot_pubkeys = set()
pubkeys_initialized = Event()


def load_pubkeys():
    # run in a separate thread since it needs to make its own NDB
    # context when it runs in the timer thread
    Thread(target=_load_pubkeys, daemon=True).start()
    pubkeys_initialized.wait()
    pubkeys_initialized.clear()


def _load_pubkeys():
    global nostr_pubkeys, nostr_loaded_at, bridged_pubkeys, bridged_loaded_at

    if not DEBUG:
        Timer(STORE_CURSOR_FREQ.total_seconds(), _load_pubkeys).start()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
        try:
            # nostr_query = Nostr.query(Nostr.status == None,
            #                               Nostr.enabled_protocols != None,
            #                               Nostr.updated > nostr_loaded_at)
            # loaded_at = Nostr.query().order(-Nostr.updated).get().updated
            # new_nostr = [key.id() for key in nostr_query.iter(keys_only=True)]
            # nostr_pubkeys.update(new_nostr)

            # set *after* we populate nostr_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            new_nostr = []
            # nostr_loaded_at = loaded_at

            loaded_at = util.now()
            new_bridged = []
            for proto in PROTOCOLS.values():
                if proto and proto != Nostr:
                    # query for all users, then filter for nostr enabled
                    users = proto.query(proto.status == None,
                                       proto.enabled_protocols != None,
                                       proto.updated > bridged_loaded_at,
                                       ).fetch()
                    new_bridged.extend([u for u in users if 'nostr' in u.enabled_protocols])
            # Extract pubkeys from bridged users' Nostr copies
            for user in new_bridged:
                nostr_copy = user.get_copy(Nostr)
                if nostr_copy and nostr_copy.startswith('nostr:npub'):
                    # Extract hex pubkey from npub
                    try:
                        npub = nostr_copy.replace('nostr:', '')
                        hex_pubkey = bech32_decode(npub)
                        if hex_pubkey:
                            bridged_pubkeys.add(hex_pubkey)
                    except Exception as e:
                        logger.warning(f'Failed to decode npub {nostr_copy}: {e}')

            # set *after* we populate bridged_pubkeys so that if we crash earlier, we
            # re-query from the earlier timestamp
            bridged_loaded_at = loaded_at

            if not protocol_bot_pubkeys:
                bot_keys = [Web(id=domain).key for domain in PROTOCOL_DOMAINS]
                for bot in ndb.get_multi(bot_keys):
                    if bot and (nostr_copy := bot.get_copy(Nostr)):
                        if nostr_copy.startswith('nostr:npub'):
                            try:
                                npub = nostr_copy.replace('nostr:', '')
                                hex_pubkey = bech32_decode(npub)
                                if hex_pubkey:
                                    logger.info(f'Loaded protocol bot user {bot.key.id()} {nostr_copy} -> {hex_pubkey}')
                                    protocol_bot_pubkeys.add(hex_pubkey)
                            except:
                                pass

            pubkeys_initialized.set()
            total = len(nostr_pubkeys) + len(bridged_pubkeys)
            logger.info(f'Nostr pubkeys: {total} Nostr {len(nostr_pubkeys)} (+{len(new_nostr)}), bridged {len(bridged_pubkeys)} (+{len(new_bridged)})')

        except BaseException:
            # eg google.cloud.ndb.exceptions.ContextError when we lose the ndb context
            # https://console.cloud.google.com/errors/detail/CLO6nJnRtKXRyQE?project=bridgy-federated
            report_exception()


def subscriber():
    """Wrapper around :func:`_subscribe` that catches exceptions and reconnects."""
    logger.info(f'started thread to subscribe to relay {Nostr.DEFAULT_TARGET}')
    load_pubkeys()

    with ndb_client.context(**NDB_CONTEXT_KWARGS):
         while True:
            try:
                subscribe()
            except BaseException:
                report_exception()
            logger.info(f'disconnected! waiting {RECONNECT_DELAY} and then reconnecting')
            time.sleep(RECONNECT_DELAY.total_seconds())


def subscribe():
    """Subscribes to relay(s), backfeeds responses to our users' activities.

    Relay URL comes from :attr:`Nostr.DEFAULT_TARGET`.
    """
    with nostr.connect(Nostr.DEFAULT_TARGET, user_agent_header=util.user_agent,
                       open_timeout=util.HTTP_TIMEOUT, close_timeout=util.HTTP_TIMEOUT,
                       ) as ws:
        # TODO: query() returns a list of events, not a generator
        events = granary.nostr.Nostr().query(ws, {'#p': list(bridged_pubkeys)})
        for event in events:
            assert (isinstance(event, dict)
                    and event.keys() >= set(('pubkey', 'id', 'kind', 'sig'))
                    and event['pubkey'] and event['id']
                    and event['kind'] and event['sig']
                    ), event

            pubkey = event['pubkey']

            # TODO: validate signature

            follow_of_bot = False
            if event['kind'] == KIND_CONTACTS:
                for tag in event.get('tags', []):
                    if tag[0] == 'p' and tag[1] in protocol_bot_pubkeys:
                        follow_of_bot = True

            if not (pubkey not in nostr_pubkeys  # from a Nostr user who's bridged
                    or follow_of_bot):
                continue

            logger.debug(f'Got Nostr event {event["id"]} from {pubkey}')
            obj_id = id_to_uri('nevent', event['id'])
            npub_uri = id_to_uri('npub', pubkey)
            delay = DELETE_TASK_DELAY if event.get('kind') == KIND_DELETE else None
            # TODO: new fn in granary, deterministic conversion from event (by kind)
            # to bech32 id w/prefix
            try:
                create_task(queue='receive', id=obj_id, source_protocol=Nostr.LABEL,
                            authed_as=npub_uri, nostr=event, delay=delay)
                # when running locally, comment out above and uncomment this
                # logger.info(f'enqueuing receive task for {obj_id}')
            except ContextError:
                raise  # handled in subscriber()
            except BaseException:
                report_error(obj_id, exception=True)
