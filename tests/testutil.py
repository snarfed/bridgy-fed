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
from urllib.parse import urlencode
import warnings

from arroba import did
import arroba.util
from arroba.util import datetime_to_tid
from bs4 import MarkupResemblesLocatorWarning
import dag_cbor.random
from flask import g
from google.cloud import ndb
from google.protobuf.timestamp_pb2 import Timestamp
from granary import as2
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
import requests

# other modules are imported _after_ Fake etc classes is defined so that it's in
# PROTOCOLS when URL routes are registered.
from common import long_to_base64, TASKS_LOCATION
import models
from models import KEY_BITS, Object, PROTOCOLS, Target, User
import protocol

logger = logging.getLogger(__name__)

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

    # maps string ids to dict AS1 objects that can be fetched
    fetchable = {}

    # in-order list of (Object, str URL)
    sent = []

    # in-order list of ids
    fetched = []

    @ndb.ComputedProperty
    def handle(self):
        return self.key.id().replace(f'{self.LABEL}:', f'{self.LABEL}:handle:')

    def web_url(self):
        return self.key.id()

    @classmethod
    def owns_id(cls, id):
        if id.startswith('nope') or id == f'{cls.LABEL}:nope':
            return False

        return ((id.startswith(f'{cls.LABEL}:')
                 and not id.startswith(f'{cls.LABEL}:handle:'))
                or id in cls.fetchable)

    @classmethod
    def owns_handle(cls, handle):
        return handle.startswith(f'{cls.LABEL}:handle:')

    @classmethod
    def handle_to_id(cls, handle):
        if handle == f'{cls.LABEL}:handle:nope':
            return None
        return handle.replace(f'{cls.LABEL}:handle:', f'{cls.LABEL}:')

    @classmethod
    def is_blocklisted(cls, url):
        return url.startswith(f'{cls.LABEL}:blocklisted')

    @classmethod
    def send(cls, obj, url, from_user=None, orig_obj=None):
        logger.info(f'{cls.__name__}.send {url}')
        cls.sent.append((obj.key.id(), url))
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
    def convert(cls, obj, from_user=None):
        logger.info(f'{cls.__name__}.convert {obj.key.id()} {from_user}')
        return cls.translate_ids(obj.as1)

    @classmethod
    def target_for(cls, obj, shared=False):
        assert obj.source_protocol in (cls.LABEL, cls.ABBREV, 'ui', None)
        return 'shared:target' if shared else f'{obj.key.id()}:target'

    @classmethod
    def receive(cls, obj, **kwargs):
        assert isinstance(obj, Object)
        return super().receive(obj=obj, **kwargs)

    @classmethod
    def receive_as1(cls, our_as1, **kwargs):
        assert isinstance(our_as1, dict)
        return super().receive(Object(id=our_as1['id'], our_as1=our_as1), **kwargs)


class OtherFake(Fake):
    """Different class because the same-protocol check special cases Fake."""
    LABEL = ABBREV = 'other'
    CONTENT_TYPE = 'ot/her'
    HAS_FOLLOW_ACCEPTS = True

    fetchable = {}
    sent = []
    fetched = []

    @classmethod
    def target_for(cls, obj, shared=False):
        """No shared target."""
        return f'{obj.key.id()}:target'


class ExplicitEnableFake(Fake):
    LABEL = ABBREV = 'eefake'
    CONTENT_TYPE = 'un/known'

    fetchable = {}
    sent = []
    fetched = []


# import other modules that register Flask handlers *after* Fake is defined
models.reset_protocol_properties()

import app
import activitypub
from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
from atproto import ATProto
import common
from web import Web
from flask_app import app, cache

# used in TestCase.make_user() to reuse keys across Users since they're
# expensive to generate.
requests.post(f'http://{ndb_client.host}/reset')
with ndb_client.context():
    global_user = activitypub._INSTANCE_ACTOR = Fake.get_or_create('fake:user')


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()

        appengine_info.APP_ID = 'my-app'
        appengine_info.LOCAL_SERVER = False
        common.RUN_TASKS_INLINE = True
        app.testing = True
        cache.clear()
        protocol.seen_ids.clear()
        protocol.objects_cache.clear()
        protocol.Protocol.for_id.cache.clear()
        common.webmention_discover.cache.clear()
        User.count_followers.cache.clear()
        did.resolve_handle.cache.clear()
        did.resolve_plc.cache.clear()
        did.resolve_web.cache.clear()

        for cls in Fake, OtherFake:
            cls.fetchable = {}
            cls.sent = []
            cls.fetched = []

        common.OTHER_DOMAINS += ('fake.brid.gy',)
        common.DOMAINS += ('fake.brid.gy',)

        # make random test data deterministic
        arroba.util._clockid = 17
        random.seed(1234567890)
        dag_cbor.random.set_options(seed=1234567890)

        self.client = app.test_client()
        self.client.__enter__()

        # clear datastore
        requests.post(f'http://{ndb_client.host}/reset')
        # disable in-memory cache
        # (also in flask_app.py)
        # https://github.com/googleapis/python-ndb/issues/888
        self.ndb_context = ndb_client.context(cache_policy=lambda key: False)
        self.ndb_context.__enter__()

        util.now = lambda **kwargs: testutil.NOW
        # used in make_user()
        self.last_make_user_id = 1

        self.app_context = app.app_context()
        self.app_context.push()

        self.request_context = app.test_request_context('/')
        self.request_context.push()

        # suppress a few warnings
        # local/lib/python3.9/site-packages/bs4/__init__.py:435: MarkupResemblesLocatorWarning: The input looks more like a filename than markup. You may want to open this file and pass the filehandle into Beautiful Soup.
        warnings.filterwarnings('ignore', category=MarkupResemblesLocatorWarning)

        # arroba config
        os.environ.update({
            'PDS_HOST': 'pds.local',
            'PLC_HOST': 'plc.local',
        })

    def tearDown(self):
        self.app_context.pop()
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

        # this breaks if it's before super().tearDown(). why?!
        self.request_context.pop()

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

    def post(self, url, client=None, **kwargs):
        """Adds Cloud tasks header to ``self.client.post``."""
        if client is None:
            client = self.client
        kwargs.setdefault('headers', {})[flask_util.CLOUD_TASKS_QUEUE_HEADER] = ''
        return client.post(url, **kwargs)

    def make_user(self, id, cls, **kwargs):
        """Reuse RSA key across Users because generating it is expensive."""
        obj_as1 = kwargs.pop('obj_as1', None)
        obj_as2 = kwargs.pop('obj_as2', None)
        obj_mf2 = kwargs.pop('obj_mf2', None)
        obj_id = kwargs.pop('obj_id', None)

        obj_key = kwargs.pop('obj_key', None)
        if obj_key:
            assert not obj_as1 and not obj_as2 and not obj_mf2 and not obj_id

        if not obj_key and cls != ATProto:
            if not obj_id:
                obj_id = ((obj_as2 or {}).get('id')
                          or util.get_url((obj_mf2 or {}), 'properties')
                          or (f'https://{id}/' if cls == Web else id))
                          # unused right now
                          # or f'fake:{str(self.last_make_user_id)}')
                self.last_make_user_id += 1
            obj_key = Object.get_or_create(id=obj_id, our_as1=obj_as1, as2=obj_as2,
                                           mf2=obj_mf2, source_protocol=cls.LABEL
                                           ).key

        kwargs.setdefault('direct', True)
        user = cls(id=id,
                   mod=global_user.mod,
                   public_exponent=global_user.public_exponent,
                   private_exponent=global_user.private_exponent,
                   obj_key=obj_key,
                   **kwargs)
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
        protocol.objects_cache.pop(obj.key.id(), None)
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

    def assert_object(self, id, delivered_protocol=None, **props):
        ignore = props.pop('ignore', [])
        got = Object.get_by_id(id)
        assert got, id

        for field in 'delivered', 'undelivered', 'failed':
            props[field] = [Target(uri=uri, protocol=delivered_protocol)
                            for uri in props.get(field, [])]

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

        object_ids = props.pop('object_ids', None)
        if object_ids is not None:
            self.assertSetEqual(set(object_ids), set(got.object_ids))

        if expected_as1 := props.pop('as1', None):
            self.assert_equals(expected_as1, got.as1)

        if got.mf2:
            got.mf2.pop('url', None)

        for target in got.delivered:
            del target.key

        self.assert_entities_equal(Object(id=id, **props), got,
                                   ignore=['as1', 'created', 'expire', 'labels',
                                           'object_ids', 'type', 'updated'
                                           ] + ignore)
        return got

    def assert_user(self, cls, id, **props):
        got = cls.get_by_id(id)
        assert got, id

        obj_as2 = props.pop('obj_as2', None)
        if obj_as2:
            self.assert_equals(obj_as2, as2.from_as1(got.obj.as1))

        # generated, computed, etc
        ignore = ['created', 'mod', 'handle', 'obj_key', 'private_exponent',
                  'public_exponent', 'updated']
        for prop in ignore:
            assert prop not in props

        self.assert_entities_equal(cls(id=id, **props), got, ignore=ignore)

        if cls != ActivityPub:
            assert got.mod
            assert got.private_exponent
            assert got.public_exponent

        return got

    def assert_task(self, mock_create_task, queue, path, eta_seconds=None, **params):
        expected = {
            'app_engine_http_request': {
                'http_method': 'POST',
                'relative_uri': path,
                'body': urlencode(sorted(params.items())).encode(),
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            },
        }
        if eta_seconds:
            expected['schedule_time'] = Timestamp(seconds=int(eta_seconds))

        mock_create_task.assert_any_call(
            parent=f'projects/{appengine_info.APP_ID}/locations/{TASKS_LOCATION}/queues/{queue}',
            task=expected,
        )


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
