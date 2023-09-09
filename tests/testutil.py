"""Common test utility code."""
import copy
from datetime import datetime
import logging
import os
import random
import re
import unittest
from unittest.mock import ANY, call
import warnings

import arroba.util
from arroba.util import datetime_to_tid
from bs4 import MarkupResemblesLocatorWarning
import dag_cbor.random
from flask import g
from google.cloud import ndb
from granary import as2
from granary.tests.test_as1 import (
    ACTOR,
    COMMENT,
    MENTION,
    NOTE,
)
from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil import appengine_info
from oauth_dropins.webutil.testutil import requests_response
import requests

# other modules are imported _after_ Fake etc classes is defined so that it's in
# PROTOCOLS when URL routes are registered.
import models
from models import Object, PROTOCOLS, Target, User
import protocol

logger = logging.getLogger(__name__)

NOTE = {
    **NOTE,
    # bare string author id
    'author': ACTOR['id'],
}
MENTION = {
    **MENTION,
    # author object with just id
    'author': {'id': ACTOR['id']},
}
COMMENT = {
    **COMMENT,
    # full author object
    'author': {
        **ACTOR,
        'displayName': 'Dr. Eve',
    },
}


class Fake(User, protocol.Protocol):
    ABBREV = 'fa'

    # maps string ids to dict AS1 objects that can be fetched
    fetchable = {}

    # in-order list of (Object, str URL)
    sent = []

    # in-order list of ids
    fetched = []

    def web_url(self):
        return self.key.id()

    def ap_address(self):
        return f'@{self.key.id()}@fake'

    def ap_actor(self, rest=None):
        return f'http://bf/fake/{self.key.id()}/ap' + (f'/{rest}' if rest else '')

    def atproto_handle(self):
        return self.key.id().removeprefix('fake:') + '.fake.brid.gy'

    @classmethod
    def owns_id(cls, id):
        if id.startswith('nope'):
            return False

        return id.startswith('fake:') or id in cls.fetchable

    @classmethod
    def send(cls, obj, url, log_data=True):
        logger.info(f'Fake.send {url}')
        cls.sent.append((obj, url))
        return True

    @classmethod
    def fetch(cls, obj,  **kwargs):
        id = obj.key.id()
        logger.info(f'Fake.fetch {id}')
        cls.fetched.append(id)

        if id in cls.fetchable:
            obj.our_as1 = cls.fetchable[id]
            return True

        return False

    @classmethod
    def serve(cls, obj):
        logger.info(f'Fake.load {obj.key.id()}')
        return (f'Fake object {obj.key.id()}',
                {'Accept': 'fake/protocol'})

    @classmethod
    def target_for(cls, obj, shared=False):
        assert obj.source_protocol in (cls.LABEL, cls.ABBREV, 'ui', None)
        return 'shared:target' if shared else f'{obj.key.id()}:target'

    @classmethod
    def receive(cls, our_as1):
        assert isinstance(our_as1, dict)
        return super().receive(Object(id=our_as1['id'], our_as1=our_as1))


class OtherFake(Fake):
    """Different class because the same-protocol check special cases Fake.

    Used in ProtocolTest.test_skip_same_protocol
    """
    ABBREV = 'other'

    @classmethod
    def owns_id(cls, id):
        return id.startswith('other:')


# used in TestCase.make_user() to reuse keys across Users since they're
# expensive to generate
requests.post(f'http://{ndb_client.host}/reset')
with ndb_client.context():
    global_user = Fake.get_or_create('fake:user')


# import other modules that register Flask handlers *after* Fake is defined
models.reset_protocol_properties()

import app
from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
from atproto import ATProto
import common
from web import Web
from flask_app import app, cache, init_globals


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()

        appengine_info.LOCAL_SERVER = False
        app.testing = True
        cache.clear()
        protocol.seen_ids.clear()
        protocol.objects_cache.clear()
        common.webmention_discover.cache.clear()

        Fake.fetchable = {}
        Fake.sent = []
        Fake.fetched = []

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
        init_globals()

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

    # TODO: switch default to Fake, start using that more
    def make_user(self, id, cls=Web, **kwargs):
        """Reuse RSA key across Users because generating it is expensive."""
        obj_key = None

        obj_as1 = kwargs.pop('obj_as1', None)
        obj_as2 = kwargs.pop('obj_as2', None)
        obj_mf2 = kwargs.pop('obj_mf2', None)
        obj_id = kwargs.pop('obj_id', None)
        if not obj_id:
            obj_id = ((obj_as2 or {}).get('id')
                      or util.get_url((obj_mf2 or {}), 'properties')
                      or str(self.last_make_user_id))
            self.last_make_user_id += 1
        obj_key = Object(id=obj_id, our_as1=obj_as1, as2=obj_as2, mf2=obj_mf2).put()

        user = cls(id=id,
                   direct=True,
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
                          our_as1=NOTE,
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
        headers = {
            'Date': 'Sun, 02 Jan 2022 03:04:05 GMT',
            'Host': util.domain_from_link(url, minimize=False),
            'Content-Type': 'application/activity+json',
            'Digest': ANY,
            **CONNEG_HEADERS_AS2_HTML,
            **kwargs.pop('headers', {}),
        }
        return cls.req(url, data=None, auth=ANY, headers=headers,
                       allow_redirects=False, **kwargs)

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

        type = props.pop('type', None)
        if type is not None:
            self.assertEqual(type, got.type)

        object_ids = props.pop('object_ids', None)
        if object_ids is not None:
            self.assertSetEqual(set(object_ids), set(got.object_ids))

        if expected_as1 := props.pop('as1', None):
            self.assert_equals(common.redirect_unwrap(expected_as1), got.as1)

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
            self.assert_equals(obj_as2, got.as2())

        # generated, computed, etc
        ignore = ['created', 'mod', 'obj_key', 'private_exponent',
                  'public_exponent', 'readable_id', 'updated']
        for prop in ignore:
            assert prop not in props

        self.assert_entities_equal(cls(id=id, **props), got, ignore=ignore)

        if cls != ActivityPub:
            assert got.mod
            assert got.private_exponent
            assert got.public_exponent

        return got

    def assert_equals(self, expected, actual, msg=None, ignore=(), **kwargs):
        return super().assert_equals(
            expected, actual, msg=msg, ignore=tuple(ignore) + ('@context',), **kwargs)
