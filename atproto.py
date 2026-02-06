"""ATProto protocol implementation.

https://atproto.com/
"""
from collections import defaultdict
from datetime import timedelta
import itertools
import logging
import os
import re
from urllib.parse import urljoin, urlparse

from arroba import did
from arroba.did import get_handle
from arroba import datastore_storage
from arroba.datastore_storage import (
    AtpRemoteBlob,
    AtpRepo,
    DatastoreStorage,
    MemcacheSequences,
)
from arroba.repo import Repo, Write
import arroba.memcache
import arroba.server
from arroba.storage import Action, CommitData, Sequences
from arroba.util import (
    at_uri,
    dag_cbor_cid,
    InactiveRepo,
    next_tid,
    parse_at_uri,
    service_jwt,
    TOMBSTONED,
)
from arroba import xrpc_repo
from domain2idna import domain2idna
from flask import abort, redirect, request
from google.cloud import dns
from google.cloud.dns.resource_record_set import ResourceRecordSet
from google.cloud import ndb
import googleapiclient.discovery
from granary import as1, as2, bluesky
from granary.bluesky import Bluesky, FROM_AS1_TYPES, to_external_embed
from granary.source import html_to_text, INCLUDE_LINK, Source
from lexrpc import Client, ValidationError
from lexrpc.base import AT_URI_RE, DID_RE
from requests import RequestException
import oauth_dropins.bluesky
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER, TESTING
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import (
    canonicalize_request_domain,
    FlashErrors,
    get_required_param,
)
from oauth_dropins.webutil.models import StringIdModel
from oauth_dropins.webutil.util import add, json_dumps, json_loads
from pymemcache.test.utils import MockMemcacheClient
from werkzeug.exceptions import HTTPException, NotFound

import common
from common import (
    CACHE_CONTROL,
    error,
    FlashErrors,
    USER_AGENT,
)
import config
import domains
from domains import (
    DOMAIN_RE,
    DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    SUPERDOMAIN,
)
from flask_app import app
import ids
import memcache
from models import Follower, Object, PROTOCOLS, Target, User
from protocol import Protocol
import web

logger = logging.getLogger(__name__)

arroba.server.storage = None  # initialized in init() below
appview = Client(f'https://{os.environ["APPVIEW_HOST"]}',
                 headers={'User-Agent': USER_AGENT})
LEXICONS = appview.defs

# https://atproto.com/guides/applications#record-types
COLLECTION_TO_TYPE = {
  'app.bsky.actor.profile': 'profile',
  'app.bsky.feed.like': 'like',
  'app.bsky.feed.post': 'post',
  'app.bsky.feed.repost': 'repost',
  'app.bsky.graph.follow': 'follow',
}

DNS_GCP_PROJECT = 'brid-gy'
DNS_ZONE = 'brid-gy'
DNS_TTL = 10800  # seconds
logger.info(f'Using GCP DNS project {DNS_GCP_PROJECT} zone {DNS_ZONE}')
# "Cloud DNS API" https://github.com/googleapis/python-dns
dns_client = dns.Client(project=DNS_GCP_PROJECT)
# "Discovery API" https://github.com/googleapis/google-api-python-client
dns_discovery_api = googleapiclient.discovery.build('dns', 'v1')


def init(sequences_cls):
    """Connect arroba's storage and sequence numbers.

    Bridgy Fed uses memcache sequence number allocation in production. If we ever
    allocated a sequence number from the datastore instead of memcache, we'd allocate
    a duplicate from memcache and collide. So, we make all services that use this
    module explicitly initialize it with the sequence number class they need.

    https://github.com/snarfed/bridgy-fed/issues/2269

    Args:
      sequences_cls: :class:`arroba.storage.Sequences` subclass
    """
    if sequences_cls == MemcacheSequences:
        if LOCAL_SERVER:
            logger.warning('MemcacheSequences requested! Not connecting arroba to datastore!')
            assert arroba.server.storage is None
            return
        elif not DEBUG and not TESTING:
            assert memcache.memcache.client_class != MockMemcacheClient
        sequences = MemcacheSequences(
            memcache=memcache.memcache,
            ndb_client=ndb_client,
            ndb_context_kwargs=common.NDB_CONTEXT_KWARGS)
    elif sequences_cls == RemoteSequences:
        sequences = RemoteSequences(base_url='https://fed.brid.gy/')
    else:
        assert False, f'unsupported sequences class {sequences_cls}'

    arroba.server.storage = DatastoreStorage(
        sequences=sequences,
        ndb_client=ndb_client,
        ndb_context_kwargs=common.NDB_CONTEXT_KWARGS)


def oauth_client_metadata():
    return {
        **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
        'client_id': f'{request.host_url}oauth/bluesky/client-metadata.json',
        'client_name': 'Bridgy Fed',
        'client_uri': request.host_url,
        'redirect_uris': [f'{request.host_url}oauth/bluesky/finish'],
    }


def chat_client(*, repo, method, **kwargs):
    """Returns a new Bluesky chat :class:`Client` for a given XRPC method.

    Args:
      repo (arroba.repo.Repo): ATProto user
      method (str): XRPC method NSID, eg ``chat.bsky.convo.sendMessage``
      kwargs: passed through to the :class:`lexrpc.client.Client` constructor

    Returns:
      lexrpc.client.Client:
    """
    token = service_jwt(host=os.environ['CHAT_HOST'],
                        aud=os.environ['CHAT_DID'],
                        repo_did=repo.did,
                        privkey=repo.signing_key,
                        lxm=method)
    kwargs.setdefault('headers', {}).update({
        'User-Agent': USER_AGENT,
        'Authorization': f'Bearer {token}',
    })
    kwargs.setdefault('truncate', True)
    return Client(f'https://{os.environ["CHAT_HOST"]}', **kwargs)


def repo_callback(data=None, lost_seq=None):
    common.create_task(queue='atproto-commit', lost_seq=lost_seq)


class RemoteSequences(Sequences):
    """Sequence number implementation that uses remote HTTP endpoints.

    Makes requests to ``/admin/sequences/alloc`` and ``/admin/sequences/last``
    to allocate and retrieve sequence numbers.

    Used for local shells and scripts, outside GCP.
    """
    def __init__(self, base_url):
        """Constructor.

        Args:
          base_url (str): base URL for the remote server, eg ``https://fed.brid.gy/``
        """
        super().__init__()
        assert base_url
        self.base_url = base_url

    def allocate(self, nsid):
        """Allocates a sequence number via HTTP POST.

        Args:
          nsid (str): subscription XRPC method this sequence number is for

        Returns:
          int:
        """
        url = urljoin(self.base_url, '/admin/sequences/alloc')
        logger.info(f'allocating seq via remote: {url}')
        resp = util.requests_post(url, data={'nsid': nsid},
                                  headers={'Authorization': config.SECRET_KEY})
        resp.raise_for_status()

        seq = int(resp.text.strip())
        logger.info(f'  allocated seq {seq}')
        return seq

    def last(self, nsid):
        """Gets the last sequence number via HTTP GET.

        Args:
          nsid (str): subscription XRPC method this sequence number is for

        Returns:
          int or None:
        """
        resp = util.requests_get(urljoin(self.base_url, '/admin/sequences/last'),
                                 params={'nsid': nsid},
                                 headers={'Authorization': config.SECRET_KEY})
        resp.raise_for_status()
        text = resp.text.strip()
        return int(text) if text and text != 'None' else None


class DatastoreClient(Client):
    """Bluesky client that uses the datastore as well as remote XRPC calls.

    Overrides ``getRecord`` and ``resolveHandle``. If we have a record or DID
    document stored locally, uses it as is instead of making a remote XRPC call.
    Otherwise, passes through to the server.

    Right now, requires that the server address is the same as
    ``$APPVIEW_HOST``, because ``getRecord`` passes through to ``ATProto.load``
    and then to ``ATProto.fetch``, which uses the ``appview`` global.
    """
    remote = True
    ''

    def __init__(self, remote=True, *args, **kwargs):
        """
        Args:
          remote (bool): if False, don't make any external calls, only look
            in the datastore
        """
        super().__init__(*args, address=f'https://{os.environ["APPVIEW_HOST"]}',
                         **kwargs)
        self.remote = remote

    def call(self, nsid, input=None, headers={}, **params):
        if nsid == 'com.atproto.repo.getRecord':
            return self.get_record(**params)  # may return {}

        if nsid == 'com.atproto.identity.resolveHandle':
            if ret := self.resolve_handle(**params):
                return ret

        if self.remote:
            return super().call(nsid, input=input, headers=headers, **params)

    def get_record(self, repo=None, collection=None, rkey=None):
        assert repo and collection and rkey, (repo, collection, rkey)

        did = repo
        uri = at_uri(did=did, collection=collection, rkey=rkey)
        record = None

        if repo := arroba.server.storage.load_repo(did):
            # local record in a repo we own
            record = repo.get_record(collection=collection, rkey=rkey)
        else:
            # remote record that we may have a cached copy of
            obj = ATProto.load(uri, remote=(None if self.remote else False),
                               raise_=False)
            if (not obj or not obj.bsky) and self.remote:
                obj = ATProto.load(uri, local=False, remote=True, raise_=False)
            if obj:
                record = obj.bsky

        if record:
            return {
                'uri': uri,
                'cid': record.get('cid') or dag_cbor_cid(record).encode('base32'),
                'value': record,
            }
        else:
            return {}

    @staticmethod
    def resolve_handle(handle=None):
        assert handle

        got = (ATProto.query(ATProto.handle == handle).get()   # native Bluesky user
               or AtpRepo.query(AtpRepo.handles == handle,     # bridged user,
                                AtpRepo.status == None).get()  # non-tombstoned first
               or AtpRepo.query(AtpRepo.handles == handle).get())
        if got:
            return {'did': got.key.id()}


def did_to_handle(did, remote=None):
    """Resolves a DID to a handle.

    Args:
      did (str)
      remote (bool): whether to fetch the object over the network. See
        :meth:`Protocol.load`

    Returns:
      str: handle, or None
    """
    assert did.startswith('did:'), did
    if did_obj := ATProto.load(did, raw=True, remote=remote):
        return get_handle(did_obj.raw)


class Cursor(StringIdModel):
    """The last cursor (sequence number) we've seen for a host and event stream.

    https://atproto.com/specs/event-stream#sequence-numbers

    Key id is ``[HOST] [XRPC]``, where ``[XRPC]`` is the NSID of the XRPC method
    for the event stream. For example, `subscribeRepos` on the production relay
    is ``bsky.network com.atproto.sync.subscribeRepos``.

    ``cursor`` is the latest sequence number that we know we've seen, so when we
    re-subscribe to this event stream, we should send ``cursor + 1``.
    """
    cursor = ndb.IntegerProperty()
    ''
    created = ndb.DateTimeProperty(auto_now_add=True)
    ''
    updated = ndb.DateTimeProperty(auto_now=True)
    ''


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'bsky'
    ''
    PHRASE = 'Bluesky'
    ''
    LOGO_EMOJI = '🦋'
    ''
    LOGO_HTML = '<img src="/oauth_dropins_static/bluesky.svg">'
    ''
    DEFAULT_TARGET = f'https://atproto{SUPERDOMAIN}'
    """Note that PDS hostname is atproto.brid.gy here, not bsky.brid.gy. Bluesky
    team currently has our hostname as atproto.brid.gy in their federation
    test. also note that PDS URL shouldn't include trailing slash.
    https://atproto.com/specs/did#did-documents
    """
    CONTENT_TYPE = 'application/json'
    ''
    HAS_COPIES = True
    ''
    REQUIRES_AVATAR = True
    ''
    REQUIRES_NAME = False
    ''
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    ''
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + ('block', 'follow', 'flag', 'like', 'share', 'stop-following')
    )
    ''
    SUPPORTED_RECORD_TYPES = frozenset(
        type for type in itertools.chain(*FROM_AS1_TYPES.values())
        if '#' not in type)
    'Which incoming record lexicons we should accept from the firehose.'
    STORE_RECORD_TYPES = frozenset(['community.lexicon.payments.webMonetization'])
    ''
    SUPPORTS_DMS = True
    ''
    HTML_PROFILES = False
    ''

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web."""
        super()._pre_put_hook()
        id = self.key.id()
        assert id

        if id.startswith('did:plc:'):
            assert id.removeprefix('did:plc:')
        elif id.startswith('did:web:'):
            domain = id.removeprefix('did:web:')
            assert (DOMAIN_RE.fullmatch(domain)
                    and not Protocol.is_blocklisted(domain)), domain
        else:
            assert False, f'{id} is not valid did:plc or did:web'

    @ndb.ComputedProperty
    def handle(self):
        """Returns handle if the DID document includes one, otherwise None."""
        return did_to_handle(self.key.id())

    def web_url(self):
        return Bluesky.user_url(self.handle_or_id())

    @classmethod
    def owns_id(cls, id):
        return (bool(AT_URI_RE.match(id))
                or bool(DID_RE.fullmatch(id))
                or id.startswith('https://bsky.app/'))

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        # TODO: implement allow_internal?
        if not did.HANDLE_RE.fullmatch(handle):
            return False

    @classmethod
    def handle_to_id(cls, handle):
        if not handle or cls.owns_handle(handle) is False:
            return None

        if resp := DatastoreClient.resolve_handle(handle):
            return resp['did']

        return did.resolve_handle(handle, get_fn=util.requests_get)

    def reload_profile(self, **kwargs):
        """Reloads this user's DID doc along with their profile object."""
        # load DID doc first so that when we write the ATProto, it populates
        # the new handle
        self.load(self.key.id(), raw=True, remote=True, **kwargs)
        super().reload_profile(**kwargs)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        """Returns a bridged user's profile URL on bsky.app.

        For example, returns ``https://bsky.app/profile/alice.com.web.brid.gy``
        for Web user ``alice.com``.
        """
        if not isinstance(user, ATProto):
            if did := user.get_copy(ATProto):
                # bsky.app doesn't fully support IDNs in profile URLs yet, so use
                # punycode. https://github.com/snarfed/bridgy-fed/issues/2222
                return Bluesky.user_url(domain2idna(did_to_handle(did)) or did)

        return super().bridged_web_url_for(user, fallback=fallback)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns our PDS URL as the target for the given object.

        ATProto delivery is indirect. We write all records to the user's local
        repo that we host, then relays and other subscribers receive them via the
        subscribeRepos event streams. So, we use a single target, our base URL
        (eg ``https://atproto.brid.gy``) as the PDS URL, for all activities.
        """
        if cls.owns_id(obj.key.id()) is not False:
            return cls.DEFAULT_TARGET

    @classmethod
    def pds_for(cls, obj):
        """Returns the PDS URL for the given object, or None.

        Args:
          obj (Object)

        Returns:
          str:
        """
        id = obj.key.id()
        # logger.debug(f'Finding ATProto PDS for {id}')

        if id.startswith('did:'):
            if obj.raw:
                for service in obj.raw.get('service', []):
                    if service.get('id') in ('#atproto_pds', f'{id}#atproto_pds'):
                        return service.get('serviceEndpoint')

            logger.info(f"{id}'s DID doc has no ATProto PDS")
            return None

        if id.startswith('https://bsky.app/'):
            return cls.pds_for(Object(id=bluesky.web_url_to_at_uri(id)))

        if id.startswith('at://'):
            repo, collection, rkey = parse_at_uri(id)

            if not repo.startswith('did:'):
                # repo is a handle; resolve it
                repo_did = cls.handle_to_id(repo)
                if repo_did:
                    return cls.pds_for(Object(id=id.replace(
                        f'at://{repo}', f'at://{repo_did}')))
                else:
                    return None

            did_obj = ATProto.load(repo, raw=True)
            if did_obj:
                return cls.pds_for(did_obj)
            # TODO: what should we do if the DID doesn't exist? should we return
            # None here? or do we need this path to return BF's URL so that we
            # then create the DID for non-ATP users on demand?

        # don't use Object.as1 if bsky is set, since that conversion calls
        # pds_for, which would infinite loop
        if not obj.bsky and obj.as1:
            if owner := as1.get_owner(obj.as1):
                if user_key := Protocol.key_for(owner):
                    if user := user_key.get():
                        if owner_did := user.get_copy(ATProto):
                            return cls.pds_for(Object(id=f'at://{owner_did}'))

        return None

    @classmethod
    def is_blocklisted(cls, url, allow_internal=False):
        if util.domain_from_link(url) == cls.DEFAULT_TARGET:
            return False

        return super().is_blocklisted(url, allow_internal=allow_internal)

    @classmethod
    def create_for(cls, user):
        """Creates an ATProto repo and profile for a non-ATProto user.

        If the repo already exists, reactivates it by emitting an #account event
        with active: True.

        Args:
          user (models.User)

        Raises:
          ValueError: if the user's handle is invalid, eg begins or ends with an
            underscore or dash
        """
        assert not isinstance(user, ATProto)

        handle = user.handle_as('atproto')

        if copy_did := user.get_copy(ATProto):
            # already bridged and inactive
            repo = arroba.server.storage.load_repo(copy_did)
            if not repo.status:
                # already active; noop
                return
            elif repo.status == TOMBSTONED:
                # tombstoned repos can't be reactivated, have to wipe and start fresh
                user.copies = []
                if user.obj:
                    user.obj.copies = []
                    user.obj.put()
                # fall through to create new DID, repo
            else:
                # deactivated or deleted
                arroba.server.storage.activate_repo(repo)
                common.create_task(queue='atproto-commit')
                if handle.endswith(SUPERDOMAIN):
                    cls.set_dns(handle=handle, did=copy_did)
                return

        # create new DID
        # PDS URL shouldn't include trailing slash!
        # https://atproto.com/specs/did#did-documents
        pds_url = domains.host_url().rstrip('/') if DEBUG else cls.DEFAULT_TARGET
        logger.info(f'Creating new did:plc for {user.key.id()} {handle} {pds_url}')
        did_plc = did.create_plc(handle, pds_url=pds_url, post_fn=util.requests_post,
                                 also_known_as=user.id_uri())

        Object.get_or_create(did_plc.did, raw=did_plc.doc, authed_as=did_plc)
        cls.set_dns(handle=handle, did=did_plc.did)

        # fetch user profile. (we store it later, at the end of this method)
        if not user.obj or not user.obj.as1:
            user.reload_profile()

        # create repo
        repo = Repo.create(arroba.server.storage, did_plc.did, handle=handle,
                           callback=repo_callback, signing_key=did_plc.signing_key,
                           rotation_key=did_plc.rotation_key)

        # create chat declaration
        logger.info(f'Storing ATProto chat declaration record')
        chat_declaration = {
            "$type" : "chat.bsky.actor.declaration",
            "allowIncoming" : "none",
        }
        initial_writes = [Write(action=Action.CREATE, record=chat_declaration,
                                collection='chat.bsky.actor.declaration', rkey='self')]
        arroba.server.storage.commit(repo, initial_writes)

        # don't add the copy id until the end, here, until we've fully
        # successfully created the DID, repo, etc
        user.add('copies', Target(uri=did_plc.did, protocol='atproto'))
        user.put()

        # create user profile. can't include this in initial writes because
        # bluesky.to_as1 in convert fetches the pinned post, which with our
        # DatastoreClient looks it up as an ATProto record in the repo.
        if user.obj and user.obj.as1:
            create_profile = Object(our_as1={
                'objectType': 'activity',
                'verb': 'post',
                'actor': user.key.id(),
                'object': user.obj.as1,
            }, source_protocol=user.LABEL)
            if not cls.send(create_profile, pds_url, from_user=user):
                logger.warning(f"couldn't create profile {user.obj_key.id()}")

    @classmethod
    def set_dns(cls, handle, did):
        """Create _atproto DNS record for handle resolution.

        https://atproto.com/specs/handle#handle-resolution

        If the DNS record already exists, or if we're not in prod, does nothing.
        If the DNS record exists with a different DID, deletes it and recreates
        it with this DID.

        Args:
          handle (str): Bluesky handle, eg ``snarfed.org.web.brid.gy``
          did (str): ATProto DID
        """
        name = f'_atproto.{handle}.'
        val = f'"did={did}"'
        logger.info(f'adding GCP DNS TXT record for {name} {val}')
        if DEBUG:
            logger.info('  skipped since DEBUG is true')
            return
        elif util.domain_or_parent_in(handle, ids.ATPROTO_HANDLE_DOMAINS):
            logger.info('  skipped since domain is in ATPROTO_HANDLE_DOMAINS')
            return

        # https://cloud.google.com/python/docs/reference/dns/latest
        # https://cloud.google.com/dns/docs/reference/rest/v1/
        zone = dns_client.zone(DNS_ZONE)
        changes = zone.changes()

        logger.info('Checking for existing record')
        ATProto.remove_dns(handle)

        changes.add_record_set(zone.resource_record_set(name=name, record_type='TXT',
                                                        ttl=DNS_TTL, rrdatas=[val]))
        changes.create()
        logger.info('done!')

    @classmethod
    def remove_dns(cls, handle):
        """Removes an _atproto DNS record.

        https://atproto.com/specs/handle#handle-resolution

        Args:
          handle (str): Bluesky handle, eg ``snarfed.org.web.brid.gy``
        """
        name = f'_atproto.{handle}.'
        logger.info(f'removing GCP DNS TXT record for {name}')
        if DEBUG:
            logger.info('  skipped since DEBUG is true')
            return

        # https://cloud.google.com/python/docs/reference/dns/latest
        # https://cloud.google.com/dns/docs/reference/rest/v1/
        zone = dns_client.zone(DNS_ZONE)
        changes = zone.changes()

        # sadly can't check if the record exists with the google.cloud.dns API
        # because it doesn't support list_resource_record_sets's name param.
        # heed to use the generic discovery-based API instead.
        # https://cloud.google.com/python/docs/reference/dns/latest/zone#listresourcerecordsetsmaxresultsnone-pagetokennone-clientnone
        # https://github.com/googleapis/python-dns/issues/31#issuecomment-1595105412
        # https://cloud.google.com/apis/docs/client-libraries-explained
        # https://googleapis.github.io/google-api-python-client/docs/dyn/dns_v1.resourceRecordSets.html
        resp = dns_discovery_api.resourceRecordSets().list(
            project=DNS_GCP_PROJECT, managedZone=DNS_ZONE, type='TXT', name=name,
        ).execute()
        if rrsets := resp.get('rrsets', []):
            for existing in rrsets:
                logger.info(f'  deleting {existing}')
                changes.delete_record_set(ResourceRecordSet.from_api_repr(existing, zone=zone))
            changes.create()

    @classmethod
    def set_username(to_cls, user, username):
        if not user.is_enabled(ATProto):
            raise ValueError("First, you'll need to bridge your account into Bluesky by following this account.")
        copy_did = user.get_copy(ATProto)

        username = username.removeprefix('@')

        repo = arroba.server.storage.load_repo(copy_did)
        assert repo
        if repo.status:
            logger.info(f'{repo.did} is {repo.status}, giving up')
            return False
        elif username == repo.handle:
            logger.info(f'repo {repo.did} already has handle {username}, setting anyway')

        # resolve_handle checks that username is a valid domain
        resolved = did.resolve_handle(username, get_fn=util.requests_get)
        if resolved != copy_did:
            raise RuntimeError(f"""<p>You'll need to connect that domain to your bridged Bluesky account, either <a href="https://bsky.social/about/blog/4-28-2023-domain-handle-tutorial">with DNS</a> <a href="https://atproto.com/specs/handle#handle-resolution">or HTTP</a>. Your DID is: <code>{copy_did}</code><p>Once you're done, <a href="https://bsky-debug.app/handle?handle={username}">check your work here</a>, then try again.""")

        logger.info(f'Setting ATProto handle for {user.key.id()} to {username}')
        repo.callback = repo_callback
        did.update_plc(did=copy_did, handle=username,
                       signing_key=repo.signing_key, rotation_key=repo.rotation_key,
                       get_fn=util.requests_get, post_fn=util.requests_post)
        repo.handle = username
        arroba.server.storage.store_repo(repo)
        arroba.server.storage.write_event(repo=repo, type='identity', handle=username)

        # refresh our stored DID doc and repo handle
        to_cls.load(copy_did, raw=True, remote=True)
        repo.handle = username

    @classmethod
    def send(to_cls, obj, pds_url, from_user=None, orig_obj_id=None):
        """Creates a record if we own its repo.

        If the repo's DID doc doesn't say we're its PDS, does nothing and
        returns False.

        Doesn't deliver anywhere externally! Relays will receive this record
        through ``subscribeRepos`` and then deliver it to AppView(s), which will
        notify recipients as necessary.

        Exceptions:
        * ``flag``s are translated to ``createReport`` to the mod service
        * DMs are translated to ``sendMessage`` to the chat service
        """
        if util.domain_from_link(pds_url) not in DOMAINS:
            logger.info(f'Target PDS {pds_url} is not us')
            return False

        # determine "base" object, if any
        type = as1.object_type(obj.as1)
        base_obj = obj
        base_obj_as1 = obj.as1
        base_id = base_obj.key.id() if base_obj.key else None
        allow_opt_out = (type == 'delete')

        if type in as1.CRUD_VERBS:
            base_obj_as1 = as1.get_object(obj.as1)
            base_id = base_obj_as1.get('id')
            base_obj_type = as1.object_type(base_obj_as1)

            if type == 'undo' and base_obj_type == 'block' and not base_id:
                # we allow undo of block without id
                # https://github.com/snarfed/bridgy-fed/issues/2073
                base_obj = Object(our_as1=base_obj_as1)
            else:
                if not base_id:
                    logger.info(f'{type} object has no id!')
                    return False
                base_obj = (from_user or PROTOCOLS[obj.source_protocol]).load(base_id, remote=False)

            if type not in ('delete', 'undo'):
                if not base_obj:  # probably a new repo
                    base_obj = Object(id=base_id, source_protocol=obj.source_protocol)
                base_obj.our_as1 = base_obj_as1

                # profile update. if it has a pinned post that's not bridged, do that
                # first, before calling convert below
                if base_obj_as1.get('objectType') in as1.ACTOR_TYPES:
                    feat_as1 = as1.get_object(base_obj_as1, 'featured')
                    if feat_id := as1.get_id(feat_as1, 'items'):
                        from_cls = obj.owner_protocol()
                        if ((feat_obj := from_cls.load(feat_id))
                                and not feat_obj.get_copy(ATProto)):
                            logger.info(f'first, creating pinned post {feat_id}')
                            ATProto.send(feat_obj, pds_url, from_user=from_user)

            if not base_obj:
                logger.info(f"Can't {type} {base_id}, no original object")
                return False

        elif type == 'stop-following':
            assert from_user
            to_id = as1.get_object(obj.as1).get('id')
            assert to_id
            to_key = Protocol.key_for(to_id, allow_opt_out=True)
            follower = Follower.query(Follower.from_ == from_user.key,
                                      Follower.to == to_key).get()
            if not follower or not follower.follow:
                logger.info(f"Skipping, can't find Follower for {from_user.key.id()} => {to_key.id()} with follow")
                return False

            base_obj = follower.follow.get()

        # convert to Bluesky record; short circuits on error
        records = to_cls.convert(base_obj, fetch_blobs=True, from_user=from_user,
                                 multiple=True)

        # find user
        from_cls = obj.owner_protocol()
        if not from_user:
            from_key = from_cls.actor_key(obj, allow_opt_out=allow_opt_out)
            if not from_key:
                logger.info(f"Couldn't find {from_cls.LABEL} user for {obj.key.id() if obj.key else None}")
                return False
            from_user = from_cls.get_or_create(
                from_key.id(), allow_opt_out=allow_opt_out, propagate=True)

        # load user's DID
        did = from_user.get_copy(ATProto)
        assert did and did.startswith('did:'), did
        logger.info(f'{from_user.key.id()} is {did}')
        did_doc = to_cls.load(did, raw=True)
        pds = to_cls.pds_for(did_doc)
        if not pds or util.domain_from_link(pds) not in DOMAINS:
            logger.warning(f'  PDS {pds} is not us')
            return False

        # load repo
        repo = arroba.server.storage.load_repo(did)
        assert repo
        repo.callback = repo_callback

        # non-commit operations:
        # * delete actor => deactivate repo
        # * flag => send report to mod service
        # * stop-following => delete follow record (prepared above)
        # * dm => chat message
        verb = obj.as1.get('verb')
        if verb == 'delete':
            atp_base_id = (base_id if ATProto.owns_id(base_id)
                           else ids.translate_user_id(from_=from_cls, to=to_cls,
                                                      id=base_id))
            if atp_base_id == did:
                logger.info(f'Deactivating bridged ATProto account {did} !')
                arroba.server.storage.deactivate_repo(repo)
                to_cls.remove_dns(from_user.handle_as('atproto'))
                return True

        if not records and verb not in ('delete', 'undo'):
            # _convert already logged
            return False

        # check repo status after handling delete actor so that we can re-send
        # #account status=deactivate events if necessary
        if repo.status:
            logger.info(f'{repo.did} is {repo.status}, giving up')
            return False

        if verb == 'flag':
            logger.info(f'flag => createReport with {records[0]}')
            return create_report(input=records[0], from_user=from_user)

        elif verb == 'stop-following':
            logger.info(f'stop-following => delete of {base_obj.key.id()}')
            assert base_obj and base_obj.type == 'follow', base_obj
            verb = 'delete'

        elif verb == 'undo' and base_obj_type == 'block':
            # for undo of block without id (eg from dms.unblock()), find and delete
            # *all* block records with the given object (subject)
            # https://github.com/snarfed/bridgy-fed/issues/2073
            blockee = as1.get_object(base_obj_as1).get('id')
            if not (blockee_proto := Protocol.for_id(blockee)):
                logger.error(f"can't determine protocol for {blockee}")
                return False
            blockee = (
                ids.translate_user_id(id=blockee, from_=blockee_proto, to=to_cls)
                or ids.translate_object_id(id=blockee, from_=blockee_proto, to=to_cls))
            if not blockee:
                logger.error('no object.object for undo block')
                return False

            if blockee.startswith('did:'):
                collection = 'app.bsky.graph.block'
            elif parse_at_uri(blockee)[1] == 'app.bsky.graph.list':
                collection = 'app.bsky.graph.listblock'
            else:
                logger.warning(f"unknown block object {blockee}")
                return

            logger.info(f'Deleting {collection}s for subject {blockee}')
            writes = []
            resp = xrpc_repo.list_records({}, repo=did, limit=None,
                                          collection=collection)
            for record in resp['records']:
                if record['value']['subject'] == blockee:
                    _, _, rkey = parse_at_uri(record['uri'])
                    writes.append(Write(action=Action.DELETE, collection=collection,
                                        rkey=rkey))

            with arroba.memcache.Lease(memcache.memcache, f'arroba-commit-{did}',
                                       retries=250):
                arroba.server.storage.commit(repo, writes)
            return True

        elif recip := as1.recipient_if_dm(obj.as1):
            assert recip.startswith('did:'), recip
            return send_chat(msg=records[0], from_repo=repo, to_did=recip)

        copies = {}  # maps string collection to (DID, collection, rkey) tuple
        for copy in base_obj.get_copies(to_cls):
            copy_did, collection, rkey = parse_at_uri(copy)
            if existing := copies.get(collection):
                logger.warning(f'{base_id} has multiple {collection}: {existing[2]} {rkey}')
                continue
            copies[collection] = (copy_did, collection, rkey)

        writes = []

        # generate commit
        if verb in ('delete', 'undo'):
            writes = [Write(action=Action.DELETE, collection=collection, rkey=rkey)
                      for _, collection, rkey in copies.values()]

        else:
            # create or other verb
            for record in records:
                type = record['$type']
                lex_type = LEXICONS[type]['type']
                assert lex_type == 'record', f"Can't store {type} object of type {lex_type}"
                copy = copies.get(type)

                if verb == 'create' and copy:
                    logger.info(f'already has ATProto copy {copy}, cowardly refusing to create again')
                    continue

                if verb == 'create' or not copy:
                    action = Action.CREATE
                    if not (rkey := generate_rkey(type)):
                        continue
                else:  # update
                    action = Action.UPDATE
                    copy_did, collection, rkey = copy
                    assert collection == type
                    if copy_did != did:
                        logger.warning(f"Can't update {base_id} {type}, original {copy} is in a different repo")
                        continue

                writes.append(Write(action=action, collection=type,
                                    rkey=rkey, record=record))

        if not writes:
            logger.info('Nothing to do!')
            return False

        postprocess_writes(writes, from_user)
        logger.info(f'Storing ATProto {writes}')
        try:
            # serialize commits per repo. constructing and writing the commits can
            # take some time, so without serializing, we hit datastore contention,
            # which makes us drop sequence numbers, since they're allocated before
            # the commit transaction, and those delay hub from emitting commit events
            # over the firehose while it waits for the skipped seqs, and sometimes
            # those delays mean we drop events entirely.
            # https://github.com/snarfed/arroba/issues/74
            with arroba.memcache.Lease(memcache.memcache, f'arroba-commit-{did}',
                                       retries=250):
                arroba.server.storage.commit(repo, writes)
        except (ValueError, InactiveRepo) as e:
            # update and delete raise ValueError if no record exists for this
            # collection/rkey
            logger.warning(e)
            return False

        logger.info(f'  seq {repo.head.seq}')

        if verb not in ('delete', 'undo'):
            @ndb.transactional()
            def add_copies():
                # read_consistency=ndb.STRONG shouldn't be necessary here, but oddly
                # it is, ndb seems to use cache inside txes even though it shouldn't
                # https://github.com/googleapis/python-ndb/issues/751
                # https://github.com/googleapis/python-ndb/issues/888 ?
                stored_obj = base_obj.key.get(read_consistency=ndb.STRONG)
                for write in writes:
                    copy = Target(uri=at_uri(did, write.collection, write.rkey),
                                  protocol=to_cls.LABEL)
                    base_obj.add('copies', copy)
                    if stored_obj:
                        stored_obj.add('copies', copy)

                (stored_obj or base_obj).put()

            add_copies()

        return True

    @classmethod
    def load(cls, id, **kwargs):
        """Thin wrapper that converts bsky.app URLs to at:// URIs."""
        # legacy
        assert 'did_doc' not in kwargs

        if id.startswith('https://bsky.app/'):
            if not id.startswith('https://bsky.app/profile'):
                return None
            try:
                id = bluesky.web_url_to_at_uri(id)
            except ValueError as e:
                logger.warning(f"Couldn't convert {id} to at:// URI: {e}")
                return None

        return super().load(id, **kwargs)

    @classmethod
    def fetch(cls, obj, **kwargs):
        """Tries to fetch a ATProto object.

        Args:
          obj (models.Object): with the id to fetch. Fills data into the ``as2``
            property.
          kwargs: ignored

        Returns:
          bool: True if the object was fetched and populated successfully,
          False otherwise
        """
        id = obj.key.id()
        if not cls.owns_id(id):
            logger.info(f"ATProto can't fetch {id}")
            return False

        assert not id.startswith('https://bsky.app/')  # handled in load

        try:
            # did:plc, did:web
            if id.startswith('did:'):
                obj.raw = did.resolve(id, get_fn=util.requests_get)
                return True
            # at:// URI. if it has a handle, resolve and replace with DID.
            # examples:
            # at://did:plc:s2koow7r6t7tozgd4slc3dsg/app.bsky.feed.post/3jqcpv7bv2c2q
            # https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
            repo, collection, rkey = parse_at_uri(id)
            if not repo or not collection or not rkey:
                return False
        except (ValueError, RequestException) as e:
            util.interpret_http_exception(e)
            return False

        if not repo.startswith('did:'):
            handle = repo
            repo = cls.handle_to_id(repo)
            if not repo:
                return False
            assert repo.startswith('did:'), repo
            obj.key = ndb.Key(Object, id.replace(f'at://{handle}', f'at://{repo}'))

        try:
            appview.address = f'https://{os.environ["APPVIEW_HOST"]}'
            ret = appview.com.atproto.repo.getRecord(
                repo=repo, collection=collection, rkey=rkey)
        except RequestException as e:
            util.interpret_http_exception(e)
            return False
        except ValidationError as e:
            logger.warning(e)
            return False

        # TODO: verify sig?
        obj.bsky = {
            **ret['value'],
            'cid': ret.get('cid'),
        }
        return True

    @classmethod
    def _convert(cls, obj, fetch_blobs=False, from_user=None, multiple=False,
                 **kwargs):
        r"""Converts a :class:`models.Object` to ``app.bsky.*`` lexicon JSON record(s).

        Args:
          obj (models.Object)
          fetch_blobs (bool): whether to fetch images and other blobs, store
            them in :class:`arroba.datastore_storage.AtpRemoteBlob`\s if they
            don't already exist, and fill them into the returned object.
          from_user (models.User): user (actor) this activity/object is from
          multiple: whether to return multiple records. Default False.
          kwargs: passed through to :func:`granary.bluesky.from_as1`

        Returns:
          dict or list of dict: one or more JSON objects, depending on ``multiple``
        """
        from_proto = PROTOCOLS.get(obj.source_protocol)

        if obj.bsky:
            return [obj.bsky] if multiple else obj.bsky

        if not obj.as1:
            return [] if multiple else {}

        obj_as1 = obj.as1
        blobs = {}  # maps str URL to dict blob object
        aspect_ratios = {}  # maps str URL to (int width, int height) tuple

        repo_key = None
        if from_user and (did := from_user.get_copy(ATProto)):
            repo_key = AtpRepo(id=did)

        def fetch_blob(url, blob_field, name, check_size=True, check_type=True):
            if url and url not in blobs:
                max_size = blob_field[name].get('maxSize') if check_size else None
                accept = blob_field[name].get('accept') if check_type else None
                try:
                    blob = AtpRemoteBlob.get_or_create(
                        url=url, get_fn=util.requests_get, max_size=max_size,
                        accept_types=accept, repo=repo_key)
                    blobs[url] = blob.as_object()
                    if blob.width and blob.height:
                        aspect_ratios[url] = (blob.width, blob.height)
                except (RequestException, ValidationError) as e:
                    logger.info(f'blob failed, skipping it: {url} : {e}')

        if fetch_blobs:
            for o in obj.as1, as1.get_object(obj.as1):
                for url in util.get_urls(o, 'image'):
                    # TODO: maybe eventually check size and type? the current
                    # 1MB limit feels too small though, and the AppView doesn't
                    # seem to validate, it's happily allowing bigger image blobs
                    # and different types as of 9/29/2024:
                    # https://github.com/snarfed/bridgy-fed/issues/1348#issuecomment-2381056468
                    props = appview.defs['app.bsky.embed.images#image']['properties']
                    fetch_blob(url, props, name='image', check_size=False,
                               check_type=False)

                for att in util.get_list(o, 'attachments'):
                    if isinstance(att, dict):
                        props = appview.defs['app.bsky.embed.video']['properties']
                        fetch_blob(as1.get_object(att, 'stream').get('url'), props,
                                   name='video', check_size=True, check_type=True)
                        for url in util.get_urls(att, 'image'):
                            props = appview.defs['app.bsky.embed.external#external']['properties']
                            fetch_blob(url, props, name='thumb',
                                       check_size=False, check_type=False)

        inner_obj = as1.get_object(obj.as1) or obj.as1
        orig_url = as1.get_url(inner_obj) or inner_obj.get('id')

        # convert! using our records in the datastore and fetching code instead
        # of granary's
        translated = cls.translate_ids(obj.as1)

        client = DatastoreClient()
        try:
            recs = bluesky.from_as1(translated, blobs=blobs,
                                    aspects=aspect_ratios, client=client,
                                    original_fields_prefix='bridgy',
                                    as_embed=obj.type == 'article', raise_=True,
                                    dynamic_sensitive_labels=True, multiple=True,
                                    **kwargs)
        except (ValueError, RequestException):
            logger.info(f"Couldn't convert to ATProto", exc_info=True)
            return [] if multiple else {}

        for rec in recs:
            # if there are any links, generate an external embed as a preview
            # for the first non-@-mention link
            #
            # not good enough to just look for #link facets, since bluesky.from_as1
            # generates those for mention tags for non-Bluesky URLs, so we also
            # need to check against the AS1 mention tags and avoid those
            if rec.get('$type') == 'app.bsky.feed.post' and not rec.get('embed'):
                mentions = [
                    as1.get_url(tag) for tag in as1.get_objects(obj.as1, 'tags')
                    if tag.get('objectType') == 'mention']
                for facet in rec.get('facets', []):
                    if feats := facet.get('features'):
                        feat = feats[0]
                        first_char = rec['text'].encode()[facet['index']['byteStart']]
                        if (feat['$type'] == 'app.bsky.richtext.facet#link'
                                and feat['uri'] not in mentions
                                # background discussion:
                                # https://github.com/snarfed/bridgy-fed/issues/1615#issuecomment-2667191265
                                and first_char != ord('@')):
                            try:
                                link = web.Web.load(feat['uri'], metaformats=True,
                                                    authorship_fetch_mf2=False,
                                                    raise_=False)
                            except AssertionError as e:
                                # we probably have an Object already stored for this
                                # URL with source_protocol that's not web
                                logger.warning(e)
                                continue

                            if link and link.as1:
                                if img := util.get_url(link.as1, 'image'):
                                    props = appview.defs['app.bsky.embed.external#external']['properties']
                                    fetch_blob(img, props, name='thumb',
                                               check_size=False, check_type=False)
                                rec['embed'] = to_external_embed(link.as1, blobs=blobs)
                                uri = rec['embed']['external']['uri']
                                # backward compatibility for some Objects with bad urls
                                if not util.is_url(uri) or not util.is_web(uri):
                                    rec['embed']['external']['uri'] = feat['uri']
                                break

            if from_proto != ATProto:
                if rec['$type'] == 'app.bsky.actor.profile':
                    # populated by Protocol.convert
                    if orig_summary := obj.as1.get('bridgyOriginalSummary'):
                        rec['bridgyOriginalDescription'] = orig_summary
                    else:
                        # don't use granary's since it will include source links
                        rec.pop('bridgyOriginalDescription', None)

                    # bridged actors get a self label
                    label_val = 'bridged-from-bridgy-fed'
                    if from_proto:
                        label_val += f'-{from_proto.LABEL}'
                    rec.setdefault('labels', {
                        '$type': 'com.atproto.label.defs#selfLabels',
                    })
                    rec['labels'].setdefault('values', []).append({'val' : label_val})

                if (rec['$type'] in ('app.bsky.actor.profile', 'app.bsky.feed.post')
                        and orig_url):
                    rec['bridgyOriginalUrl'] = orig_url

        return recs if multiple else rec

    @classmethod
    def _migrate_in(cls, user, from_user_id, plc_code, pds_client):
        """Migrates an ATProto account on another PDS in to be a bridged account.

        https://atproto.com/guides/account-migration

        Before calling this, the repo must have already been imported with
        ``com.atproto.repo.importRepo``!

        Args:
          user (models.User): native user on another protocol to attach the
            newly imported account to. Unused.
          from_user_id (str): DID of the account to be migrated in
          plc_code (str): a PLC operation confirmation code from the account's
            old PDS, from ``com.atproto.identity.requestPlcOperationSignature``
          pds_client (lexrpc.Client): authenticated client for the account's old PDS

        Raises:
          ValueError: if the repo hasn't been imported yet
        """
        assert from_user_id.startswith('did:')

        if not (repo := arroba.server.storage.load_repo(from_user_id)):
            msg = f"Please import {from_user_id}'s repo first"
            logger.error(msg)
            raise ValueError(msg)

        did_doc = cls.load(from_user_id, raw=True)
        assert did_doc, from_user_id
        aka = did_doc.raw.get('alsoKnownAs') or []
        util.add(aka, user.id_uri())

        # ask old PDS to generate signed PLC operation
        # https://atproto.com/guides/account-migration#updating-identity
        op = pds_client.com.atproto.identity.signPlcOperation({
            'token': plc_code,
            'rotationKeys': [did.encode_did_key(repo.rotation_key.public_key())],
            # note the name here, verificationMethods *with* trailing s! different
            # from verificationMethod (no s) in DID docs! confusing! and important!
            # https://github.com/snarfed/bounce/issues/45#issuecomment-3254425427
            'verificationMethods': {
                'atproto': did.encode_did_key(repo.signing_key.public_key()),
            },
            'alsoKnownAs': aka,
            'services': {
                'atproto_pds': {
                    'type': 'AtprotoPersonalDataServer',
                    'endpoint': cls.DEFAULT_TARGET,
                },
            },
        })
        logger.debug(op)

        # submit PLC operation to directory
        # https://github.com/did-method-plc/did-method-plc#did-update
        #
        # ideally we'd use com.atproto.identity.submitPlcOperation on the PDS
        # instead, since it includes extra error checks, but it doesn't let us change
        # the PDS (ie the AtprotoPersonalDataServer endpoint) :(
        # https://github.com/bluesky-social/atproto/blob/cf4117966c1b1c1786a25bb352c12ad57b617a05/packages/pds/src/api/com/atproto/identity/submitPlcOperation.ts#L19-L50
        util.requests_post(f'https://{os.environ["PLC_HOST"]}/{from_user_id}',
                           json=op['operation'], gateway=True)

        # activate our repo, deactivate account on old PDS
        # https://atproto.com/guides/account-migration#finalizing-account-status
        arroba.server.storage.activate_repo(repo)
        arroba.server.storage.commit(repo, [])
        pds_client.com.atproto.server.deactivateAccount()

    @classmethod
    def migrate_out(cls, user, to_user_id):
        """Noop, does nothing.

        This may eventually do something when we support actual account migration,
        https://atproto.com/guides/account-migration , but right now we only migrate
        to a separate DID.

        Args:
          user (models.User)
          to_user_id (str)

        Raises:
          ValueError: eg if ``ATProto`` doesn't own ``to_user_id``
        """
        logger.info(f"ATProto migrate_out to a different DID is a noop, doing nothing. (migrating {user.key.id()} to {to_user_id})")

        cls.check_can_migrate_out(user, to_user_id)

        if user.get_copy(ATProto) == to_user_id:
            raise ValueError(f'{user.key.id()} is already bridged to {to_user_id}')

    @classmethod
    def add_source_links(cls, obj, from_user):
        """Adds "bridged from ... by Bridgy Fed" text to ``actor['summary']``.

        Calls the parent implementation and then truncates the result for
        Bluesky's character limits.

        Args:
          obj (models.Object): user's actor/profile object
          from_user (models.User): user (actor) this activity/object is from
        """
        def get_actor():
            return (as1.get_object(obj.as1) if obj.as1.get('verb') in as1.CRUD_VERBS
                    else obj.as1)

        actor = get_actor()
        summary = actor.get('summary', '')
        if '🌉 bridged' in summary:
            return

        # consumed by _convert
        actor.setdefault('bridgyOriginalSummary', summary)

        super().add_source_links(obj, from_user)

        # truncate
        actor = get_actor()
        if '🌉 bridged' in actor['summary']:
            parts = actor['summary'].rsplit('\n\n', 1)
            if len(parts) == 2:
                text, source_links = parts
                # Need to add back the newlines between text and source_links
                actor['summary'] = Bluesky('unused').truncate(
                    text, url='\n\n' + source_links, punctuation=('', ''),
                    type=obj.type)


def generate_rkey(type):
    """Generates a new rkey based on a collection lexicon's key type.

    https://atproto.com/specs/lexicon#record
    https://atproto.com/specs/record-key

    Args:
      type (str): collection NSID, eg ``app.bsky.feed.post``

    Returns:
      str or None: rkey, eg ``self`` or ``3me5cnh2poyt2``
    """
    key_type = LEXICONS[type]['key']
    if type == 'community.lexicon.payments.webMonetization':
        # https://github.com/lexicon-community/lexicon/tree/main/community/lexicon/payments#usage
        return 'self'
    elif key_type.startswith('literal:'):
        return key_type.removeprefix('literal:')
    elif key_type in ('tid', 'any'):
        return next_tid()
    else:
        logger.error(f'unsupported key type for {type}: {key_type}')


def postprocess_writes(writes, user):
    """Applies custom logic to writes before we commit them.

    * For ``site.standard.document``s:
      * Populate the ``bskyPostRef`` property, if we also have an
        ``app.bsky.feed.post``.
      * Create a ``site.standard.publication`` if we don't already have one.

    Args:
      writes (sequence of arroba.repo.Write)
      user (models.User)
    """
    did = user.get_copy(ATProto)

    by_collection = defaultdict(list)
    for write in writes:
        by_collection[write.collection].append(write)


    # map site.standard.documents to app.bsky.feed.posts
    docs = [write for write in by_collection['site.standard.document']
            if write.action in (Action.CREATE, Action.UPDATE)]

    for post in by_collection['app.bsky.feed.post']:
        if post.action in (Action.CREATE, Action.UPDATE):
            for doc in docs:
                doc.record['bskyPostRef'] = {
                    'uri': at_uri(did, post.collection, post.rkey),
                    'cid': dag_cbor_cid(post.record).encode('base32'),
                }
            break

    # create site.standard.publication for user if it doesn't exist
    if (docs and user and user.verified_domain
            and user.key.id() in common.BETA_USER_IDS):
        has_publication = any(parse_at_uri(uri)[1] == 'site.standard.publication'
                              for uri in user.obj.get_copies(ATProto))
        if not has_publication:
            if pub := ATProto.convert(user.obj, out_type='site.standard.publication',
                                      domain=user.verified_domain):
                rkey = generate_rkey('site.standard.publication')
                writes.append(Write(action=Action.CREATE,
                                    collection='site.standard.publication',
                                    rkey=rkey, record=pub))
                uri = at_uri(did, 'site.standard.publication', rkey)
                user.obj.add('copies', Target(uri=uri, protocol='atproto'))
                user.obj.put()
                logger.info(f'creating {uri} for {user.obj_key.id()}')

def create_report(*, input, from_user):
    """Sends a ``createReport`` for a ``flag`` activity.

    Args:
      input (dict): ``createReport`` input
      from_user (models.User): user (actor) this flag is from

    Returns:
      bool: True if the report was sent successfully, False if the flag's
        actor is not bridged into ATProto
    """
    assert input['$type'] == 'com.atproto.moderation.createReport#input'

    repo_did = from_user.get_copy(ATProto)
    if not repo_did:
        return False

    repo = arroba.server.storage.load_repo(repo_did)
    assert repo
    if repo.status:
        logger.info(f'{repo.did} is {repo.status}, giving up')
        return False

    mod_host = os.environ['MOD_SERVICE_HOST']
    token = service_jwt(host=mod_host,
                        aud=os.environ['MOD_SERVICE_DID'],
                        repo_did=repo_did,
                        privkey=repo.signing_key)

    client = Client(f'https://{mod_host}', truncate=True, headers={
                        'User-Agent': USER_AGENT,
                        'Authorization': f'Bearer {token}',
                    })
    output = client.com.atproto.moderation.createReport(input)
    logger.info(f'Created report on {mod_host}: {json_dumps(output)}')
    return True


def send_chat(*, msg, from_repo, to_did):
    """Sends a chat message to this user.

    Args:
      msg (dict): ``chat.bsky.convo.defs#messageInput``
      from_repo (arroba.repo.Repo)
      to_did (str)

    Returns:
      bool: True if the message was sent successfully, False otherwise, eg
        if the recipient has disabled chat
    """
    assert msg['$type'] == 'chat.bsky.convo.defs#messageInput'

    client = chat_client(repo=from_repo, method='chat.bsky.convo.getConvoForMembers')
    try:
        convo = client.chat.bsky.convo.getConvoForMembers(members=[to_did])
    except RequestException as e:
        util.interpret_http_exception(e)
        if e.response is not None and e.response.status_code == 400:
            body = e.response.json()
            if (body.get('error') == 'InvalidRequest'
                    and body.get('message') == 'recipient has disabled incoming messages'):
                return False
        raise

    client = chat_client(repo=from_repo, method='chat.bsky.convo.sendMessage')
    sent = client.chat.bsky.convo.sendMessage({
        'convoId': convo['convo']['id'],
        'message': msg,
    })

    logger.info(f'Sent chat message from {from_repo.handle} to {to_did}: {json_dumps(sent)}')
    return True


@flask_util.cloud_tasks_only(log=False)
def poll_chat_task():
    """Polls for incoming chat messages for our protocol bot users.

    Params:
      proto: protocol label, eg ``activitypub``
    """
    proto = PROTOCOLS[get_required_param('proto')]
    logger.info(f'Polling incoming chat messages for {proto.LABEL}')

    from web import Web
    bot = Web.get_by_id(proto.bot_user_id())
    assert bot.atproto_last_chat_log_cursor
    repo = arroba.server.storage.load_repo(bot.get_copy(ATProto))
    client = chat_client(repo=repo, method='chat.bsky.convo.getLog')

    while True:
        # getLog returns logs in ascending order, starting from cursor
        # https://github.com/bluesky-social/atproto/issues/2760
        #
        # we could use rev for idempotence, but we don't yet, since cursor alone
        # should mostly avoid dupes, and we also de-dupe on chat message id, so
        # we should hopefully be ok as is
        logs = client.chat.bsky.convo.getLog(cursor=bot.atproto_last_chat_log_cursor)
        for log in logs['logs']:
            if (log['$type'] == 'chat.bsky.convo.defs#logCreateMessage'
                    and log['message']['$type'] == 'chat.bsky.convo.defs#messageView'):
                sender = log['message']['sender']['did']
                if sender != repo.did:
                    # generate synthetic at:// URI for this message
                    id = at_uri(did=sender,
                                collection='chat.bsky.convo.defs.messageView',
                                rkey=log['message']['id'])
                    msg_as1 = {
                        **bluesky.to_as1(log['message']),
                        'to': [bot.key.id()],
                    }
                    common.create_task(queue='receive', id=id, bsky=log['message'],
                                       our_as1=msg_as1, source_protocol=ATProto.LABEL,
                                       authed_as=sender,
                                       received_at=log['message']['sentAt'])

        # check if we've caught up yet
        cursor = logs.get('cursor')
        if cursor:
            bot.atproto_last_chat_log_cursor = cursor
        if not logs['logs'] or not cursor:
            break

    # done!
    bot.put()
    return 'OK'


@app.get(f'/hashtag/<hashtag>')
@flask_util.headers(CACHE_CONTROL)
def hashtag_redirect(hashtag):
    if util.domain_from_link(request.host_url) == f'{ATProto.ABBREV}{SUPERDOMAIN}':
        try:
            return redirect(f'https://bsky.app/search?q=%23{hashtag}')
        except ValueError as e:
            logging.warning(e)

    raise NotFound()


@app.get('/.well-known/atproto-did')
@flask_util.headers(CACHE_CONTROL)
def atproto_did():
    """Programmatic handle resolution for bridged users.

    https://github.com/snarfed/bridgy-fed/issues/1537
    https://atproto.com/specs/handle#handle-resolution

    Query params:
      protocol (str)
      id (str): native user id or handle
    """
    protocol = get_required_param('protocol')
    if not (proto := PROTOCOLS.get(protocol)):
        flask_util.error(f'Unknown protocol {protocol}')

    id = get_required_param('id')

    user = proto.get_by_id(id) or proto.query(proto.handle == id).get()

    # heuristic for fediverse accounts with mixed case usernames
    # https://github.com/snarfed/bridgy-fed/issues/1974
    if not user and protocol == 'ap':
        if match := as2.URL_RE.match(id):
            for domain in ids.ATPROTO_HANDLE_DOMAINS:
                if util.domain_or_parent_in(match.group('server'), [domain]):
                    handle_as_domain = f'{match.group("username")}.{domain}'.lower()
                    logger.info(f'Looking for {handle_as_domain}')
                    user = proto.query(proto.handle_as_domain == handle_as_domain).get()

    if user:
        if copy := user.get_copy(ATProto):
            return copy, {'Content-Type': 'text/plain'}

    raise NotFound()


@app.get('/.well-known/site.standard.publication')
@flask_util.headers(CACHE_CONTROL)
def site_standard_publication():
    """Serves site.standard.publication records for bridged users.

    https://standard.site/#verification

    Query params:
      protocol (str)
      id (str): native user id or handle
    """
    protocol = get_required_param('protocol')
    if not (proto := PROTOCOLS.get(protocol)):
        flask_util.error(f'Unknown protocol {protocol}')

    id = get_required_param('id')

    user = proto.get_by_id(id) or proto.query(proto.handle == id).get()
    if not user or user.status or not user.obj:
        raise NotFound()

    did = user.get_copy(ATProto)
    for uri in user.obj.get_copies(ATProto):
        copy_did, collection, rkey = parse_at_uri(uri)
        assert copy_did == did
        if collection == 'site.standard.publication':
            logger.info(f'publication record is {uri}')
            repo = arroba.server.storage.load_repo(did)
            if record := repo.get_record(collection=collection, rkey=rkey):
                logger.info('found!')
                return record

    raise NotFound()


#
# OAuth
#
@app.get('/.well-known/oauth-protected-resource')
@app.get('/.well-known/oauth-authorization-server')
@flask_util.headers(CACHE_CONTROL)
def no_oauth():
    return "Sorry, Bridgy Fed doesn't serve OAuth. https://fed.brid.gy/docs#use-like-normal", 404


class BlueskyOAuthStart(FlashErrors, oauth_dropins.bluesky.OAuthStart):
    @property
    def CLIENT_METADATA(self):
        return oauth_client_metadata()

class BlueskyOAuthCallback(FlashErrors, oauth_dropins.bluesky.OAuthCallback):
    @property
    def CLIENT_METADATA(self):
        return oauth_client_metadata()


@app.get('/oauth/bluesky/client-metadata.json')
@canonicalize_request_domain(PROTOCOL_DOMAINS, PRIMARY_DOMAIN)
@flask_util.headers(CACHE_CONTROL)
def bluesky_oauth_client_metadata():
    """https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata"""
    return oauth_client_metadata()


app.add_url_rule('/oauth/bluesky/start', view_func=BlueskyOAuthStart.as_view(
    '/oauth/bluesky/start', '/oauth/bluesky/finish'), methods=['POST'])
app.add_url_rule('/oauth/bluesky/finish', view_func=BlueskyOAuthCallback.as_view(
    '/oauth/bluesky/finish', '/settings'))
