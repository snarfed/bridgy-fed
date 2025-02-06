"""Common test utility code."""
import contextlib
import copy
from datetime import datetime
import logging
import os
import random
import re
import unittest
from unittest.mock import ANY, call
from urllib.parse import parse_qs, urlencode
import warnings

from arroba import did
import arroba.util
from arroba.util import datetime_to_tid
from bs4 import MarkupResemblesLocatorWarning
import dag_cbor.random
from google.cloud import ndb
from google.protobuf.timestamp_pb2 import Timestamp
from granary import as1, as2
from granary.tests.test_as1 import (
    ACTOR,
    COMMENT,
    MENTION,
    NOTE,
)
from oauth_dropins.webutil import flask_util, testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil import appengine_info
from oauth_dropins.webutil.testutil import requests_response
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests

# other modules are imported _after_ Fake etc classes is defined so that it's in
# PROTOCOLS when URL routes are registered.
from common import long_to_base64, NDB_CONTEXT_KWARGS, TASKS_LOCATION
import ids
import models
from models import KEY_BITS, Object, PROTOCOLS, Target, User
import protocol
import router

logger = logging.getLogger(__name__)
logging.getLogger('memcache').setLevel(logging.INFO)

ATPROTO_KEY = arroba.util.new_key(2349823483510)  # deterministic seed

NOTE = {
    **NOTE,
    # bare string author id
    'author': ACTOR['id'],
}
MENTION = {
    **MENTION,
    # author object with just id
    'author': {'id': ACTOR['id']},
    'content': 'a mention',
}
COMMENT = {
    **COMMENT,
    # full author object
    'author': {
        **ACTOR,
        'displayName': 'Dr. Eve',
    },
    'content': 'a comment',
}


class Fake(User, protocol.Protocol):
    ABBREV = 'fa'
    PHRASE = 'fake-phrase'
    CONTENT_TYPE = 'fa/ke'
    DEFAULT_ENABLED_PROTOCOLS = ('other',)
    HAS_COPIES = True
    LOGO_HTML = '<img src="fake-logo">'
    DEFAULT_SERVE_USER_PAGES = True
    SUPPORTED_AS1_TYPES = frozenset(
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + tuple(as1.VERBS_WITH_OBJECT)
    )

    # maps string ids to dict AS1 objects that can be fetched
    fetchable = {}

    # in-order list of (Object, str URL)
    sent = []

    # in-order lists of ids
    fetched = []
    created_for = []

    # maps str user id to str username
    usernames = {}

    @ndb.ComputedProperty
    def handle(self):
        return self.key.id().replace(f'{self.LABEL}:', f'{self.LABEL}:handle:')

    def web_url(self):
        return f'web:{self.key.id()}'

    def id_uri(self):
        return f'uri:{self.key.id()}'

    @classmethod
    def bridged_web_url_for(cls, user, fallback=False):
        return f'web:{cls.LABEL}:{user.key.id()}'

    @classmethod
    def create_for(cls, user):
        id = user.key.id()
        logger.info(f'{cls.__name__}.create_for {id}')
        cls.created_for.append(id)

        if not user.get_copy(cls):
            copy = Target(uri=ids.translate_user_id(id=id, from_=user, to=cls),
                          protocol=cls.LABEL)
            util.add(user.copies, copy)
            user.put()

        if user.obj and not user.obj.get_copy(cls):
            profile_copy_id = ids.translate_object_id(
                id=user.profile_id(), from_=user, to=cls)
            user.obj.add('copies', Target(uri=profile_copy_id, protocol=cls.LABEL))
            user.obj.put()

    @classmethod
    def owns_id(cls, id):
        if id.startswith('nope') or id == f'{cls.LABEL}:nope':
            return False

        return ((id.startswith(f'{cls.LABEL}:')
                 and not id.startswith(f'{cls.LABEL}:handle:'))
                or id in cls.fetchable)

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        return handle.startswith(f'{cls.LABEL}:handle:')

    @classmethod
    def handle_to_id(cls, handle):
        if handle == f'{cls.LABEL}:handle:nope':
            return None
        return handle.replace(f'{cls.LABEL}:handle:', f'{cls.LABEL}:')

    @classmethod
    def is_blocklisted(cls, url, allow_internal=False):
        return url.startswith(f'{cls.LABEL}:blocklisted')

    @classmethod
    def send(to, obj, url, from_user=None, orig_obj_id=None):
        logger.info(f'{to.__name__}.send {url} {obj.as1}')
        to.sent.append((url, obj.as1))

        from_ = PROTOCOLS.get(obj.source_protocol)
        if (from_ and from_ != to and to.HAS_COPIES
                and obj.type not in ('update', 'delete')):
            obj_id = as1.get_object(obj.as1).get('id')
            if not obj_id:
                return False
            if obj.type == 'post':
                obj = Object.get_by_id(obj_id)
            copy_id = ids.translate_object_id(
                id=obj.key.id(), from_=from_, to=to)
            util.add(obj.copies, Target(uri=copy_id, protocol=to.LABEL))
            obj.put()

        return True

    @classmethod
    def fetch(cls, obj,  **kwargs):
        id = obj.key.id()
        logger.info(f'{cls.__name__}.fetch {id}')
        cls.fetched.append(id)

        if id in cls.fetchable:
            obj.our_as1 = cls.fetchable[id]
            return True

        return False

    @classmethod
    def _convert(cls, obj, from_user=None):
        logger.info(f'{cls.__name__}.convert {obj.key.id()} {from_user}')
        return cls.translate_ids(obj.as1)

    @classmethod
    def target_for(cls, obj, shared=False):
        assert obj.source_protocol in (cls.LABEL, cls.ABBREV, 'ui', None), \
            (obj.source_protocol, cls.LABEL)

        if shared:
            return f'{cls.LABEL}:shared:target'

        user_id = ids.normalize_user_id(id=obj.key.id(), proto=cls)
        return f'{user_id}:target'

    @classmethod
    def receive(cls, obj, authed_as=None, **kwargs):
        assert isinstance(obj, Object)
        if not authed_as:
            authed_as = as1.get_owner(obj.as1) or obj.as1['id']
        return super().receive(obj=obj, authed_as=authed_as, **kwargs)

    @classmethod
    def receive_as1(cls, our_as1, **kwargs):
        assert isinstance(our_as1, dict)
        obj = Object(id=our_as1['id'], our_as1=our_as1, source_protocol=cls.LABEL)
        obj.new = kwargs.pop('new', True)
        obj.changed = kwargs.pop('changed', None)
        return cls.receive(obj, **kwargs)


class OtherFake(Fake):
    """Different class because the same-protocol check special cases Fake."""
    LABEL = ABBREV = 'other'
    PHRASE = 'other-phrase'
    CONTENT_TYPE = 'ot/her'
    DEFAULT_ENABLED_PROTOCOLS = ('fake',)
    DEFAULT_SERVE_USER_PAGES = False
    SUPPORTED_AS1_TYPES = Fake.SUPPORTED_AS1_TYPES - set(('accept',))
    SUPPORTS_DMS = True

    fetchable = {}
    sent = []
    fetched = []
    created_for = []
    usernames = {}

    @classmethod
    def target_for(cls, obj, shared=False):
        """No shared target."""
        return f'{obj.key.id()}:target'

    @classmethod
    def set_username(cls, user, username):
        logger.info(f'Setting custom username for {user.key.id()} in {cls.LABEL} to {username}')
        cls.usernames[user.key.id()] = username


class ExplicitFake(Fake):
    """Fake protocol class that isn't default enabled for any other protocols."""
    LABEL = ABBREV = 'efake'
    PHRASE = 'efake-phrase'
    CONTENT_TYPE = 'un/known'
    DEFAULT_ENABLED_PROTOCOLS = ()
    DEFAULT_SERVE_USER_PAGES = False
    SUPPORTS_DMS = True

    fetchable = {}
    sent = []
    fetched = []
    created_for = []
    usernames = {}


# import other modules that register Flask handlers *after* Fake is defined
models.reset_protocol_properties()

import app
import activitypub
from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
import atproto
from atproto import ATProto
import common
from common import (
    LOCAL_DOMAINS,
    OTHER_DOMAINS,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
)
from memcache import (
    global_cache,
    memcache,
    pickle_memcache,
)
from web import Web
from flask_app import app

ActivityPub.DEFAULT_ENABLED_PROTOCOLS += ('fake', 'other')
ATProto.DEFAULT_ENABLED_PROTOCOLS += ('fake', 'other')
Web.DEFAULT_ENABLED_PROTOCOLS += ('fake', 'other')

# used in TestCase.make_user() to reuse keys across Users since they're
# expensive to generate.
requests.post(f'http://{ndb_client.host}/reset')
with ndb_client.context():
    global_user = activitypub._INSTANCE_ACTOR = Fake.get_or_create('fake:user')


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()
        testutil.suppress_warnings()

        appengine_info.APP_ID = 'my-app'
        appengine_info.LOCAL_SERVER = False
        common.RUN_TASKS_INLINE = True
        app.testing = True

        did.resolve_handle.cache.clear()
        did.resolve_plc.cache.clear()
        did.resolve_web.cache.clear()
        ids.web_ap_base_domain.cache.clear()
        protocol.Protocol.for_id.cache.clear()
        protocol.Protocol.for_handle.cache.clear()
        User.count_followers.cache.clear()
        common.protocol_user_copy_ids.cache_clear()

        for cls in ExplicitFake, Fake, OtherFake:
            cls.fetchable = {}
            cls.sent = []
            cls.fetched = []
            cls.created_for = []
            cls.usernames = {}

        # make random test data deterministic
        arroba.util._clockid = 17
        random.seed(1234567890)
        dag_cbor.random.set_options(seed=1234567890)

        self.client = app.test_client()
        self.client.__enter__()

        self.router_client = router.app.test_client()

        memcache.clear()
        pickle_memcache.clear()
        global_cache.clear()
        models.get_original_object_key.cache_clear()
        models.get_original_user_key.cache_clear()

        # clear datastore
        requests.post(f'http://{ndb_client.host}/reset')
        self.ndb_context = ndb_client.context(**NDB_CONTEXT_KWARGS)
        self.ndb_context.__enter__()

        util.now = lambda **kwargs: testutil.NOW
        # used in make_user()
        self.last_make_user_id = 1

        self.app_context = app.app_context()
        self.app_context.push()

        self.request_context = app.test_request_context('/')
        self.request_context.push()

        # arroba config
        os.environ.update({
            'APPVIEW_HOST': 'appview.local',
            'BGS_HOST': 'bgs.local',
            'PDS_HOST': 'pds.local',
            'PLC_HOST': 'plc.local',
            'MOD_SERVICE_HOST': 'mod.service.local',
            'MOD_SERVICE_DID': 'did:mod-service',
            'CHAT_HOST': 'chat.local',
            'CHAT_DID': 'did:chat',
        })
        atproto.appview.address = 'https://appview.local'

    def tearDown(self):
        self.app_context.pop()
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

        # this breaks if it's before super().tearDown(). why?!
        try:
            self.request_context.pop()
        except LookupError as e:
            # the test probably popped this already
            logger.warning('', exc_info=e)

    def run(self, result=None):
        """Override to hide stdlib and virtualenv lines in tracebacks.

        https://docs.python.org/3.9/library/unittest.html#unittest.TestCase.run
        https://docs.python.org/3.9/library/unittest.html#unittest.TestResult
        """
        result = super().run(result=result)

        def prune(results):
            return [
                (tc, re.sub(r'\n  File ".+/(local|.venv|oauth-dropins|Python.framework)/.+\n.+\n',
                            '\n', tb))
                for tc, tb in results]

        result.errors = prune(result.errors)
        result.failures = prune(result.failures)
        return result

    def get(self, url, **kwargs):
        """Adds Cloud tasks header to ``self.client.get``."""
        return self._request('get', url, **kwargs)

    def post(self, url, **kwargs):
        """Adds Cloud tasks header to ``self.client.post``."""
        return self._request('post', url, **kwargs)

    def _request(self, fn, url, client=None, **kwargs):
        if client is None:
            client = (self.router_client
                      if url.startswith('/queue/') or url.startswith('/cron/')
                      else self.client)
        kwargs.setdefault('headers', {})[flask_util.CLOUD_TASKS_TASK_HEADER] = 'x'
        return getattr(client, fn)(url, **kwargs)

    def make_user(self, id, cls, **kwargs):
        """Reuse RSA key across Users because generating it is expensive."""
        obj_as1 = copy.deepcopy(kwargs.pop('obj_as1', None))
        obj_as2 = copy.deepcopy(kwargs.pop('obj_as2', None))
        obj_bsky = copy.deepcopy(kwargs.pop('obj_bsky', None))
        obj_mf2 = copy.deepcopy(kwargs.pop('obj_mf2', None))
        obj_id = copy.deepcopy(kwargs.pop('obj_id', None))

        if cls == Web and not obj_mf2:
            kwargs.setdefault('last_webmention_in', testutil.NOW)

        user = cls(id=id,
                   mod=global_user.mod,
                   public_exponent=global_user.public_exponent,
                   private_exponent=global_user.private_exponent,
                   **kwargs)

        user.obj_key = kwargs.pop('obj_key', None)
        if user.obj_key:
            assert not (obj_as1 or obj_as2 or obj_bsky or obj_mf2 or obj_id)
        elif cls != ATProto or obj_bsky:
            if not obj_id:
                obj_id = ((obj_as2 or {}).get('id')
                          or util.get_url((obj_mf2 or {}), 'properties')
                          or user.profile_id())
            user.obj_key = Object.get_or_create(
                id=obj_id, authed_as=obj_id, our_as1=obj_as1, as2=obj_as2,
                bsky=obj_bsky, mf2=obj_mf2, source_protocol=cls.LABEL).key

        user.put()
        return user

    def add_objects(self):
        user = ndb.Key(Web, 'user.com')

        # post
        self.store_object(id='a',
                          users=[user],
                          notify=[user],
                          feed=[user],
                          our_as1=NOTE)
        # post with mention
        self.store_object(id='b',
                          notify=[user],
                          feed=[user],
                          our_as1=MENTION)
        # reply
        self.store_object(id='d',
                          notify=[user],
                          feed=[user],
                          our_as1=COMMENT)
        # not feed/notif
        self.store_object(id='e',
                          users=[user],
                          our_as1=NOTE)
        # deleted
        self.store_object(id='f',
                          notify=[user],
                          feed=[user],
                          our_as1={**NOTE, 'content': 'deleted!'},
                          deleted=True)
        # different domain
        nope = ndb.Key(Web, 'nope.org')
        self.store_object(id='g',
                          notify=[nope],
                          feed=[nope],
                          our_as1=MENTION)

        # actor whose id is in NOTE.author
        self.store_object(id=ACTOR['id'], our_as1=ACTOR)

    @staticmethod
    def store_object(**kwargs):
        obj = Object(**kwargs)
        obj.put()
        return obj

    @staticmethod
    def random_keys_and_cids(num):
        def tid():
            ms = random.randint(datetime(2020, 1, 1).timestamp() * 1000,
                                datetime(2024, 1, 1).timestamp() * 1000)
            return datetime_to_tid(datetime.fromtimestamp(float(ms) / 1000))

        return [(f'com.example.record/{tid()}', cid)
                for cid in dag_cbor.random.rand_cid(num)]

    def random_tid(num):
        ms = random.randint(datetime(2020, 1, 1).timestamp() * 1000,
                            datetime(2024, 1, 1).timestamp() * 1000)
        tid = datetime_to_tid(datetime.fromtimestamp(float(ms) / 1000))
        return f'com.example.record/{tid}'

    def get_as2(self, *args, **kwargs):
        kwargs.setdefault('headers', {})['Accept'] = CONNEG_HEADERS_AS2_HTML
        return self.client.get(*args, **kwargs)

    @classmethod
    def req(cls, url, **kwargs):
        """Returns a mock requests call."""
        kwargs.setdefault('headers', {}).update({
            'User-Agent': util.user_agent,
        })
        kwargs.setdefault('timeout', util.HTTP_TIMEOUT)
        kwargs.setdefault('stream', True)
        return call(url, **kwargs)

    @classmethod
    def as2_req(cls, url, **kwargs):
        kwargs.setdefault('data', None)
        headers = {
            'Date': 'Sun, 02 Jan 2022 03:04:05 GMT',
            'Host': util.domain_from_link(url, minimize=False),
            'Content-Type': as2.CONTENT_TYPE_LD_PROFILE,
            'Digest': ANY,
            **CONNEG_HEADERS_AS2_HTML,
            **kwargs.pop('headers', {}),
        }
        return cls.req(url, auth=ANY, headers=headers, allow_redirects=False, **kwargs)

    @classmethod
    def as2_resp(cls, obj):
        return requests_response(obj, content_type=as2.CONTENT_TYPE)

    def assert_req(self, mock, url, **kwargs):
        """Checks a mock requests call."""
        kwargs.setdefault('headers', {}).setdefault(
            'User-Agent', 'Bridgy Fed (https://fed.brid.gy/)')
        kwargs.setdefault('stream', True)
        kwargs.setdefault('timeout', util.HTTP_TIMEOUT)
        mock.assert_any_call(url, **kwargs)

    def assert_object(self, id, **props):
        ignore = props.pop('ignore', [])
        got = Object.get_by_id(id)
        assert got, id

        if 'our_as1' in props:
            assert 'as2' not in props
            assert 'bsky' not in props
            assert 'mf2' not in props
            ignore.extend(['as2', 'bsky', 'mf2'])

        mf2 = props.get('mf2')
        if mf2 and 'items' in mf2:
            props['mf2'] = mf2['items'][0]

        # strip @context
        if 'as2' in props:
           props['as2'].pop('@context', None)
           for field in 'actor', 'object':
               val = props['as2'].get(field)
               if isinstance(val, dict):
                   val.pop('@context', None)

        type = props.pop('type', None)
        if type is not None:
            self.assertEqual(type, got.type)

        if expected_as1 := props.pop('as1', None):
            self.assert_equals(expected_as1, got.as1)

        if got.mf2:
            got.mf2.pop('url', None)

        self.assert_entities_equal(Object(id=id, **props), got,
                                   ignore=['as1', 'created', 'expire',
                                           'type', 'updated'] + ignore)
        return got

    def assert_user(self, cls, id, ignore=(), **props):
        got = cls.get_by_id(id)
        assert got, id

        obj_as2 = props.pop('obj_as2', None)
        if obj_as2:
            self.assert_equals(obj_as2, as2.from_as1(got.obj.as1))

        # generated, computed, etc
        ignore = ['created', 'mod', 'handle', 'obj_key', 'private_exponent',
                  'public_exponent', 'status', 'updated'] + list(ignore)
        for prop in ignore:
            assert prop not in props

        self.assert_entities_equal(cls(id=id, **props), got, ignore=ignore)

        if cls != ActivityPub:
            assert got.mod
            assert got.private_exponent
            assert got.public_exponent

        return got

    def assert_task(self, mock_create_task, queue, eta_seconds=None, **params):
        # if only one task was created in this queue, extract and decode HTTP
        # body so we can pretty-print a comparison
        bodies = [body for task_queue, body in self.parse_tasks(mock_create_task)
                 if task_queue == queue]
        if len(bodies) == 1:
            self.assertEqual({k: v.decode() if isinstance(v, bytes) else v
                              for k, v in params.items()},
                             bodies[0])

        # check for exact task
        params = [(k, json_dumps(v, sort_keys=True) if isinstance(v, dict) else v)
                  for k, v in params.items()]
        expected = {
            'app_engine_http_request': {
                'http_method': 'POST',
                'relative_uri': f'/queue/{queue}',
                'body': urlencode(sorted(params)).encode(),
                'headers': {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'traceparent': '',
                },
            },
        }
        if eta_seconds:
            expected['schedule_time'] = Timestamp(seconds=int(eta_seconds))

        mock_create_task.assert_any_call(
            parent=f'projects/{appengine_info.APP_ID}/locations/{TASKS_LOCATION}/queues/{queue}',
            task=expected,
        )

    def assert_ap_deliveries(self, mock_post, inboxes, data, from_user=None,
                             ignore=()):
        self.assertEqual(len(inboxes), len(mock_post.call_args_list),
                         mock_post.call_args_list)

        calls = {}  # maps inbox URL to JSON data
        for args, kwargs in mock_post.call_args_list:
            self.assertEqual(as2.CONTENT_TYPE_LD_PROFILE,
                             kwargs['headers']['Content-Type'])
            rsa_key = kwargs['auth'].header_signer._rsa._key
            self.assertEqual((from_user or self.user).private_pem(),
                             rsa_key.exportKey())
            calls[args[0]] = json_loads(kwargs['data'])

        for inbox in inboxes:
            got = calls[inbox]
            as1.get_object(got).pop('publicKey', None)
            self.assert_equals(data, got, inbox, ignore=ignore)

    def parse_tasks(self, mock_create_task):
        """Returns (queue, {param name: value}) tuples, where JSON param values
        are parsed."""
        tasks = []

        for call in mock_create_task.call_args_list:
            task = call.kwargs['task']['app_engine_http_request']
            queue = task['relative_uri'].removeprefix('/queue/')
            body = {name: json_loads(val[0]) if val and val[0][0] == '{' else val[0]
                    for name, val in parse_qs(task['body'].decode()).items()}
            tasks.append((queue, body))

        return tasks

    def assert_equals(self, expected, actual, msg=None, ignore=(), **kwargs):
        return super().assert_equals(
            expected, actual, msg=msg, ignore=tuple(ignore) + ('@context',), **kwargs)

    @contextlib.contextmanager
    def assertLogs(self):
        """Wraps :meth:`unittest.TestCase.assertLogs` and enables/disables logs.

        Works around ``oauth_dropins.webutil.tests.__init__``.
        """
        orig_disable_level = logging.root.manager.disable
        logging.disable(logging.NOTSET)

        try:
            with super().assertLogs() as logs:
                yield logs
        finally:
            # emit logs that were captured
            for record in logs.records:
                if record.levelno >= orig_disable_level:
                    logging.root.handle(record)
            logging.disable(orig_disable_level)
