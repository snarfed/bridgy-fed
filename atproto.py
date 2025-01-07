"""ATProto protocol implementation.

https://atproto.com/
"""
from datetime import timedelta
import itertools
import logging
import os
import re

from arroba import did
from arroba.datastore_storage import AtpRemoteBlob, AtpRepo, DatastoreStorage
from arroba.repo import Repo, Write
import arroba.server
from arroba.storage import Action, CommitData
from arroba.util import (
    at_uri,
    dag_cbor_cid,
    next_tid,
    parse_at_uri,
    service_jwt,
    TOMBSTONED,
)
import brevity
import dag_json
from flask import abort, redirect, request
from google.cloud import dns
from google.cloud.dns.resource_record_set import ResourceRecordSet
from google.cloud import ndb
import googleapiclient.discovery
from granary import as1, bluesky
from granary.bluesky import Bluesky, FROM_AS1_TYPES, to_external_embed
from granary.source import html_to_text, INCLUDE_LINK, Source
from lexrpc import Client, ValidationError
from requests import RequestException
from oauth_dropins.webutil import util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import get_required_param
from oauth_dropins.webutil.models import StringIdModel
from oauth_dropins.webutil.util import add, json_dumps, json_loads
from werkzeug.exceptions import NotFound

import common
from common import (
    DOMAIN_BLOCKLIST,
    DOMAIN_RE,
    DOMAINS,
    error,
    PRIMARY_DOMAIN,
    SUPERDOMAIN,
    USER_AGENT,
)
from flask_app import app
import ids
from models import Follower, Object, PROTOCOLS, Target, User
from protocol import Protocol
import web

logger = logging.getLogger(__name__)

arroba.server.storage = DatastoreStorage(ndb_client=ndb_client,
                                         ndb_context_kwargs=common.NDB_CONTEXT_KWARGS)

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


def chat_client(*, repo, method, **kwargs):
    """Returns a new Bluesky chat :class:`Client` for a given XRPC method.

    Args:
      repo (arroba.repo.Repo): ATProto user
      method (str): XRPC method NSID, eg ``chat.bsky.convo.sendMessage``
      kwargs: passed through to the :class:`lexrpc.Client` constructor

    Returns:
      lexrpc.Client:
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


class DatastoreClient(Client):
    """Bluesky client that uses the datastore as well as remote XRPC calls.

    Overrides ``getRecord`` and ``resolveHandle``. If we have a record or DID
    document stored locally, uses it as is instead of making a remote XRPC call.
    Otherwise, passes through to the server.

    Right now, requires that the server address is the same as
    ``$APPVIEW_HOST``, because ``getRecord`` passes through to ``ATProto.load``
    and then to ``ATProto.fetch``, which uses the ``appview`` global.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert self.address == f'https://{os.environ["APPVIEW_HOST"]}', self.address

    def call(self, nsid, input=None, headers={}, **params):
        if nsid == 'com.atproto.repo.getRecord':
            return self.get_record(**params)  # may return {}

        if nsid == 'com.atproto.identity.resolveHandle':
            if ret := self.resolve_handle(**params):
                return ret

        return super().call(nsid, input=input, headers=headers, **params)

    def get_record(self, repo=None, collection=None, rkey=None):
        assert repo and collection and rkey, (repo, collection, rkey)

        uri = at_uri(did=repo, collection=collection, rkey=rkey)
        record = None

        # local record in a repo we own?
        if repo := arroba.server.storage.load_repo(repo):
            record = repo.get_record(collection=collection, rkey=rkey)

        # remote record that we may have a cached copy of
        if not record:
            if obj := ATProto.load(uri, raise_=False):
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

    Returns:
      str: handle, or None
      remote (bool): whether to fetch the object over the network. See
        :meth:`Protocol.load`
    """
    if did_obj := ATProto.load(did, did_doc=True, remote=remote):
        # use first at:// URI in alsoKnownAs
        for aka in util.get_list(did_obj.raw, 'alsoKnownAs'):
            if aka.startswith('at://'):
                handle, _, _ = parse_at_uri(aka)
                if handle:
                    return handle


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
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)


class ATProto(User, Protocol):
    """AT Protocol class.

    Key id is DID, currently either did:plc or did:web.
    https://atproto.com/specs/did
    """
    ABBREV = 'bsky'
    PHRASE = 'Bluesky'
    LOGO_HTML = '<img src="/oauth_dropins_static/bluesky.svg">'
    # note that PDS hostname is atproto.brid.gy here, not bsky.brid.gy. Bluesky
    # team currently has our hostname as atproto.brid.gy in their federation
    # test. also note that PDS URL shouldn't include trailing slash.
    # https://atproto.com/specs/did#did-documents
    PDS_URL = f'https://atproto{common.SUPERDOMAIN}'
    CONTENT_TYPE = 'application/json'
    HAS_COPIES = True
    REQUIRES_AVATAR = True
    REQUIRES_NAME = False
    DEFAULT_ENABLED_PROTOCOLS = ('web',)
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + ('block', 'follow', 'flag', 'like', 'share', 'stop-following')
    )
    SUPPORTED_RECORD_TYPES = frozenset(
        type for type in itertools.chain(*FROM_AS1_TYPES.values())
        if '#' not in type)
    SUPPORTS_DMS = True

    def _pre_put_hook(self):
        """Validate id, require did:plc or non-blocklisted did:web."""
        super()._pre_put_hook()
        id = self.key.id()
        assert id

        if id.startswith('did:plc:'):
            assert id.removeprefix('did:plc:')
        elif id.startswith('did:web:'):
            domain = id.removeprefix('did:web:')
            assert (re.match(common.DOMAIN_RE, domain)
                    and not Protocol.is_blocklisted(domain)), domain
        else:
            assert False, f'{id} is not valid did:plc or did:web'

    @ndb.ComputedProperty
    def handle(self):
        """Returns handle if the DID document includes one, otherwise None."""
        return did_to_handle(self.key.id())

    def web_url(self):
        return Bluesky.user_url(self.handle_or_id())

    def id_uri(self):
        return f'at://{self.key.id()}'

    @classmethod
    def owns_id(cls, id):
        return (id.startswith('at://')
                or id.startswith('did:plc:')
                or id.startswith('did:web:')
                or id.startswith('https://bsky.app/'))

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        # TODO: implement allow_internal
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
        super().reload_profile(**kwargs)
        self.load(self.key.id(), did_doc=True, remote=True, **kwargs)

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        """Returns a bridged user's profile URL on bsky.app.

        For example, returns ``https://bsky.app/profile/alice.com.web.brid.gy``
        for Web user ``alice.com``.
        """
        if not isinstance(user, ATProto):
            if did := user.get_copy(ATProto):
                return Bluesky.user_url(did_to_handle(did) or did)

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns our PDS URL as the target for the given object.

        ATProto delivery is indirect. We write all records to the user's local
        repo that we host, then relays and other subscribers receive them via the
        subscribeRepos event streams. So, we use a single target, our base URL
        (eg ``https://atproto.brid.gy``) as the PDS URL, for all activities.
        """
        if cls.owns_id(obj.key.id()) is not False:
            return cls.PDS_URL

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

            did_obj = ATProto.load(repo, did_doc=True)
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

    def is_blocklisted(url, allow_internal=False):
        # don't block common.DOMAINS since we want ourselves, ie our own PDS, to
        # be a valid domain to send to
        return util.domain_or_parent_in(util.domain_from_link(url), DOMAIN_BLOCKLIST)

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
            if repo.status == TOMBSTONED:
                # tombstoned repos can't be reactivated, have to wipe and start fresh
                user.copies = []
                if user.obj:
                    user.obj.copies = []
                    user.obj.put()
                # fall through to create new DID, repo
            else:
                # deactivated or deleted, or maybe still active?
                arroba.server.storage.activate_repo(repo)
                common.create_task(queue='atproto-commit')
                if handle.endswith(SUPERDOMAIN):
                    cls.set_dns(handle=handle, did=copy_did)
                return

        # create new DID, repo
        # PDS URL shouldn't include trailing slash!
        # https://atproto.com/specs/did#did-documents
        pds_url = common.host_url().rstrip('/') if DEBUG else cls.PDS_URL
        logger.info(f'Creating new did:plc for {user.key.id()} {handle} {pds_url}')
        did_plc = did.create_plc(handle, pds_url=pds_url, post_fn=util.requests_post,
                                 also_known_as=user.profile_id())

        Object.get_or_create(did_plc.did, raw=did_plc.doc, authed_as=did_plc)
        # TODO: move this to ATProto.get_or_create?
        add(user.copies, Target(uri=did_plc.did, protocol='atproto'))

        cls.set_dns(handle=handle, did=did_plc.did)

        # fetch and store profile
        if not user.obj or not user.obj.as1:
            user.reload_profile()

        initial_writes = []
        if user.obj and user.obj.as1:
            # create user profile
            profile = cls.convert(user.obj, fetch_blobs=True, from_user=user)
            logger.info(f'Storing ATProto app.bsky.actor.profile self')
            initial_writes.append(
                Write(action=Action.CREATE, collection='app.bsky.actor.profile',
                      rkey='self', record=profile))

            uri = at_uri(did_plc.did, 'app.bsky.actor.profile', 'self')
            user.obj.add('copies', Target(uri=uri, protocol='atproto'))
            user.obj.put()

        # create chat declaration
        logger.info(f'Storing ATProto chat declaration record')
        chat_declaration = {
            "$type" : "chat.bsky.actor.declaration",
            "allowIncoming" : "none",
        }
        initial_writes.append(
            Write(action=Action.CREATE, collection='chat.bsky.actor.declaration',
                  rkey='self', record=chat_declaration))

        repo = Repo.create(
            arroba.server.storage, did_plc.did, handle=handle,
            callback=lambda _: common.create_task(queue='atproto-commit'),
            initial_writes=initial_writes,
            signing_key=did_plc.signing_key,
            rotation_key=did_plc.rotation_key)

        user.put()

    @classmethod
    def set_dns(cls, handle, did):
        """Create _atproto DNS record for handle resolution.

        https://atproto.com/specs/handle#handle-resolution

        If the DNS record already exists, or if we're not in prod, does nothing.
        If the DNS record exists with a different DID, deletes it and recreates
        it with this DID.

        Args:
          handle (str): Bluesky handle, eg ``snarfed.org.web.brid.gy``
        """
        name = f'_atproto.{handle}.'
        val = f'"did={did}"'
        logger.info(f'adding GCP DNS TXT record for {name} {val}')
        if DEBUG:
            logger.info('  skipped since DEBUG is true')
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

        # resolve_handle checks that username is a valid domain
        resolved = did.resolve_handle(username, get_fn=util.requests_get)
        if resolved != copy_did:
            raise RuntimeError(f"""<p>You'll need to connect that domain to your bridged Bluesky account, either <a href="https://bsky.social/about/blog/4-28-2023-domain-handle-tutorial">with DNS</a> <a href="https://atproto.com/specs/handle#handle-resolution">or HTTP</a>. Your DID is: <code>{copy_did}</code><p>Once you're done, <a href="https://bsky-debug.app/handle?handle={username}">check your work here</a>, then DM me <em>username {username}</em> again.""")

        repo = arroba.server.storage.load_repo(copy_did)
        assert repo
        if repo.status:
            logger.info(f'{repo.did} is {repo.status}, giving up')
            return False

        logger.info(f'Setting ATProto handle for {user.key.id()} to {username}')
        repo.callback = lambda _: common.create_task(queue='atproto-commit')
        did.update_plc(did=copy_did, handle=username,
                       signing_key=repo.signing_key, rotation_key=repo.rotation_key,
                       get_fn=util.requests_get, post_fn=util.requests_post)
        repo.handle = username
        arroba.server.storage.store_repo(repo)
        arroba.server.storage.write_event(repo=repo, type='identity', handle=username)

        # refresh our stored DID doc and repo handle
        to_cls.load(copy_did, did_doc=True, remote=True)
        repo.handle = username

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj_id=None):
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
        if util.domain_from_link(url) not in DOMAINS:
            logger.info(f'Target PDS {url} is not us')
            return False

        # determine "base" object, if any
        type = as1.object_type(obj.as1)
        base_obj = obj
        base_obj_as1 = obj.as1
        allow_opt_out = (type == 'delete')
        if type in as1.CRUD_VERBS:
            base_obj_as1 = as1.get_object(obj.as1)
            base_id = base_obj_as1.get('id')
            if not base_id:
                logger.info(f'{type} object has no id!')
                return False
            base_obj = PROTOCOLS[obj.source_protocol].load(base_id, remote=False)
            if type not in ('delete', 'undo'):
                if not base_obj:  # probably a new repo
                    base_obj = Object(id=base_id, source_protocol=obj.source_protocol)
                base_obj.our_as1 = base_obj_as1

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
        record = to_cls.convert(base_obj, fetch_blobs=True, from_user=from_user)

        # find user
        from_cls = PROTOCOLS[obj.source_protocol]
        from_key = from_cls.actor_key(obj, allow_opt_out=allow_opt_out)
        if not from_key:
            logger.info(f"Couldn't find {obj.source_protocol} user for {obj.key.id()}")
            return False

        # load user
        user = from_cls.get_or_create(from_key.id(), allow_opt_out=allow_opt_out, propagate=True)
        did = user.get_copy(ATProto)
        assert did
        logger.info(f'{user.key.id()} is {did}')
        did_doc = to_cls.load(did, did_doc=True)
        pds = to_cls.pds_for(did_doc)
        if not pds or util.domain_from_link(pds) not in DOMAINS:
            logger.warning(f'  PDS {pds} is not us')
            return False

        # load repo
        repo = arroba.server.storage.load_repo(did)
        assert repo
        repo.callback = lambda _: common.create_task(queue='atproto-commit')

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
                to_cls.remove_dns(user.handle_as('atproto'))
                return True

        if not record:
            # _convert already logged
            return False

        # check repo status after handling delete actor so that we can re-send
        # #account status=deactivate events if necessary
        if repo.status:
            logger.info(f'{repo.did} is {repo.status}, giving up')
            return False

        if verb == 'flag':
            logger.info(f'flag => createReport with {record}')
            return create_report(input=record, from_user=user)

        elif verb == 'stop-following':
            logger.info(f'stop-following => delete of {base_obj.key.id()}')
            assert base_obj and base_obj.type == 'follow', base_obj
            verb = 'delete'

        elif recip := as1.recipient_if_dm(obj.as1):
            assert recip.startswith('did:'), recip
            return send_chat(msg=record, from_repo=repo, to_did=recip)

        # write commit
        type = record['$type']
        lex_type = LEXICONS[type]['type']
        assert lex_type == 'record', f"Can't store {type} object of type {lex_type}"

        # only modify objects that we've bridged
        rkey = None
        if verb in ('update', 'delete', 'undo'):
            # check that they're updating the object we have
            copy = base_obj.get_copy(to_cls)
            if not copy:
                logger.info(f"Can't {verb} {base_obj.key.id()} {type}, we didn't create it originally")
                return False

            copy_did, coll, rkey = parse_at_uri(copy)
            if copy_did != did or coll != type:
                logger.info(f"Can't {verb} {base_obj.key.id()} {type}, original {copy} is in a different repo or collection")
                return False

        ndb.transactional()
        def write():
            nonlocal rkey
            match verb:
                case 'update':
                    action = Action.UPDATE
                case 'delete' | 'undo':
                    action = Action.DELETE
                case _:
                    action = Action.CREATE
                    rkey = 'self' if type == 'app.bsky.actor.profile' else next_tid()

            logger.info(f'Storing ATProto {action} {type} {rkey} {dag_json.encode(record, dialect="atproto")}')
            try:
                repo.apply_writes([Write(action=action, collection=type, rkey=rkey,
                                         record=record)])
            except KeyError as e:
                # raised by update and delete if no record exists for this
                # collection/rkey
                logger.warning(e)
                return False
            logger.info(f'  seq {repo.head.seq}')

            if verb not in ('delete', 'undo'):
                at_uri = f'at://{did}/{type}/{rkey}'
                base_obj.add('copies', Target(uri=at_uri, protocol=to_cls.LABEL))
                base_obj.put()

            return True

        return write()

    @classmethod
    def load(cls, id, did_doc=False, **kwargs):
        """Thin wrapper that converts DIDs and bsky.app URLs to at:// URIs.

        Args:
          did_doc (bool): if True, loads and returns a DID document object
            instead of an ``app.bsky.actor.profile/self``.
        """
        if id.startswith('did:') and not did_doc:
            id = ids.profile_id(id=id, proto=cls)

        elif id.startswith('https://bsky.app/'):
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

        # did:plc, did:web
        if id.startswith('did:'):
            try:
                obj.raw = did.resolve(id, get_fn=util.requests_get)
                return True
            except (ValueError, RequestException) as e:
                util.interpret_http_exception(e)
                return False

        # at:// URI. if it has a handle, resolve and replace with DID.
        # examples:
        # at://did:plc:s2koow7r6t7tozgd4slc3dsg/app.bsky.feed.post/3jqcpv7bv2c2q
        # https://bsky.social/xrpc/com.atproto.repo.getRecord?repo=did:plc:s2koow7r6t7tozgd4slc3dsg&collection=app.bsky.feed.post&rkey=3jqcpv7bv2c2q
        repo, collection, rkey = parse_at_uri(id)
        if not repo or not collection or not rkey:
            return False

        if not repo.startswith('did:'):
            handle = repo
            repo = cls.handle_to_id(repo)
            if not repo:
                return False
            assert repo.startswith('did:')
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
    def _convert(cls, obj, fetch_blobs=False, from_user=None):
        r"""Converts a :class:`models.Object` to ``app.bsky.*`` lexicon JSON.

        Args:
          obj (models.Object)
          fetch_blobs (bool): whether to fetch images and other blobs, store
            them in :class:`arroba.datastore_storage.AtpRemoteBlob`\s if they
            don't already exist, and fill them into the returned object.
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          dict: JSON object
        """
        from_proto = PROTOCOLS.get(obj.source_protocol)

        if obj.bsky:
            return obj.bsky

        if not obj.as1:
            return {}

        obj_as1 = obj.as1
        blobs = {}  # maps str URL to dict blob object
        aspect_ratios = {}  # maps str URL to (int width, int height) tuple

        def fetch_blob(url, blob_field, name, check_size=True, check_type=True):
            if url and url not in blobs:
                max_size = blob_field[name].get('maxSize') if check_size else None
                accept = blob_field[name].get('accept') if check_type else None
                try:
                    blob = AtpRemoteBlob.get_or_create(
                        url=url, get_fn=util.requests_get, max_size=max_size,
                        accept_types=accept)
                    blobs[url] = blob.as_object()
                    if blob.width and blob.height:
                        aspect_ratios[url] = (blob.width, blob.height)
                except (RequestException, ValidationError) as e:
                    logger.info(f'failed, skipping {url} : {e}')

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
        client = DatastoreClient(f'https://{os.environ["APPVIEW_HOST"]}')
        as_embed = obj.atom or obj.rss
        try:
            ret = bluesky.from_as1(cls.translate_ids(obj.as1), blobs=blobs,
                                   aspects=aspect_ratios, client=client,
                                   original_fields_prefix='bridgy', as_embed=as_embed)
        except (ValueError, RequestException):
            logger.info(f"Couldn't convert to ATProto", exc_info=True)
            return {}

        # if there are any links, generate an external embed as a preview
        # for the first link
        if ret.get('$type') == 'app.bsky.feed.post' and not ret.get('embed'):
            for facet in ret.get('facets', []):
                if feats := facet.get('features'):
                    if feats[0]['$type'] == 'app.bsky.richtext.facet#link':
                        try:
                            link = web.Web.load(feats[0]['uri'], metaformats=True,
                                                authorship_fetch_mf2=False,
                                                raise_=False)
                        except AssertionError as e:
                            # we probably have an Object already stored for this URL
                            # with source_protocol that's not web
                            logger.warning(e)
                            continue

                        if link:
                            if img := util.get_url(link.as1, 'image'):
                                props = appview.defs['app.bsky.embed.external#external']['properties']
                                fetch_blob(img, props, name='thumb',
                                           check_size=False, check_type=False)
                            ret['embed'] = to_external_embed(link.as1, blobs=blobs)
                            break

        if from_proto != ATProto:
            if ret['$type'] == 'app.bsky.actor.profile':
                # populated by Protocol.convert
                if orig_summary := obj.as1.get('bridgyOriginalSummary'):
                    ret['bridgyOriginalDescription'] = orig_summary
                else:
                    # don't use granary's since it will include source links
                    ret.pop('bridgyOriginalDescription', None)

                # bridged actors get a self label
                label_val = 'bridged-from-bridgy-fed'
                if from_proto:
                    label_val += f'-{from_proto.LABEL}'
                ret.setdefault('labels', {'$type': 'com.atproto.label.defs#selfLabels'})
                ret['labels'].setdefault('values', []).append({'val' : label_val})

            if (ret['$type'] in ('app.bsky.actor.profile', 'app.bsky.feed.post')
                    and orig_url):
                ret['bridgyOriginalUrl'] = orig_url

        return ret

    @classmethod
    def add_source_links(cls, actor, obj, from_user):
        """Adds "bridged from ... by Bridgy Fed" text to ``obj.our_as1``.

        Overrides the default :meth:`protocol.Protocol.add_source_links`
        implementation to use plain text URLs because ``app.bsky.actor.profile``
        has no ``descriptionFacets`` for the ``description`` field.

        TODO: much of this duplicates
        :meth:`protocol.Protocol.add_source_links`. Refactor somehow.

        Args:
          obj (models.Object):
          from_user (models.User): user (actor) this activity/object is from
        """
        assert obj.our_as1
        assert from_user

        orig_summary = obj.our_as1.setdefault('summary', '')
        summary = html_to_text(orig_summary, ignore_links=True)
        if 'fed.brid.gy ]' in summary or 'Bridgy Fed]' in summary:
            return

        # consumed by _convert above
        actor.setdefault('bridgyOriginalSummary', orig_summary)

        id = obj.key.id() if obj.key else obj.our_as1.get('id')

        proto_phrase = (PROTOCOLS[obj.source_protocol].PHRASE
                        if obj.source_protocol else '')
        if proto_phrase:
            proto_phrase = f' on {proto_phrase}'

        if from_user.key and id in (from_user.key.id(), from_user.profile_id()):
            url = from_user.web_url()
        else:
            url = as1.get_url(obj.our_as1) or id
            url = util.pretty_link(url) if url else '?'

        if from_user.LABEL == 'web':
            # link web users to their user pages
            source_links = f'[bridged from {url}{proto_phrase}: https://{PRIMARY_DOMAIN}{from_user.user_page_path()} ]'
        else:
            source_links = f'[bridged from {url}{proto_phrase} by https://{PRIMARY_DOMAIN}/ ]'

        if summary:
            source_links = '\n\n' + source_links

        obj.our_as1['summary'] = Bluesky('unused').truncate(
            summary, url=source_links, punctuation=('', ''), type=obj.type)

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

    client = chat_client(repo=from_repo,
                         method='chat.bsky.convo.getConvoForMembers')
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
@flask_util.headers(common.CACHE_CONTROL)
def hashtag_redirect(hashtag):
    if (util.domain_from_link(request.host_url) ==
            f'{ATProto.ABBREV}{common.SUPERDOMAIN}'):
        return redirect(f'https://bsky.app/search?q=%23{hashtag}')

    raise NotFound()
