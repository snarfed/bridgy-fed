"""Common test utility code."""
import copy
from datetime import datetime
import logging
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
    COMMENT,
    MENTION,
    NOTE,
)
from oauth_dropins.webutil import testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.testutil import requests_response
import requests

# other modules are imported _after_ Fake class is defined so that it's in
# PROTOCOLS when URL routes are registered.
import models
from models import Object, PROTOCOLS, Target, User
import protocol

logger = logging.getLogger(__name__)


class Fake(User, protocol.Protocol):
    ABBREV = 'fa'

    # maps string ids to dict AS1 objects. send adds objects here, fetch
    # returns them
    objects = {}

    # in-order list of (Object, str URL)
    sent = []

    # in-order list of ids
    fetched = []

    def web_url(self):
        return f'fake://{self.key.id()}'

    def ap_address(self):
        return f'@{self.key.id()}@fake'

    def ap_actor(self, rest=None):
        return f'http://bf/fake/{self.key.id()}/ap' + (f'/{rest}' if rest else '')

    @classmethod
    def owns_id(cls, id):
        return id.startswith('fake://')

    @classmethod
    def send(cls, obj, url, log_data=True):
        logger.info(f'Fake.send {url}')
        cls.sent.append((obj, url))
        cls.objects[obj.key.id()] = obj

    @classmethod
    def fetch(cls, obj,  **kwargs):
        id = obj.key.id()
        logger.info(f'Fake.load {id}')
        cls.fetched.append(id)

        if id in cls.objects:
            obj.our_as1 = cls.objects[id]
            return obj

        raise requests.HTTPError(response=util.Struct(status_code='410'))

    @classmethod
    def serve(cls, obj):
        logger.info(f'Fake.load {obj.key.id()}')
        return (f'Fake object {obj.key.id()}',
                {'Accept': 'fake/protocol'})


# used in TestCase.make_user() to reuse keys across Users since they're
# expensive to generate
requests.post(f'http://{ndb_client.host}/reset')
with ndb_client.context():
    global_user = Fake.get_or_create('user')


# import other modules that register Flask handlers *after* Fake is defined
models.reset_protocol_properties()

import app
from activitypub import ActivityPub, CONNEG_HEADERS_AS2_HTML
import common
from web import Web
from flask_app import app, cache, init_globals


class TestCase(unittest.TestCase, testutil.Asserts):
    maxDiff = None

    def setUp(self):
        super().setUp()

        app.testing = True
        cache.clear()
        protocol.seen_ids.clear()
        protocol.objects_cache.clear()
        common.webmention_discover.cache.clear()

        Fake.objects = {}
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
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

        util.now = lambda **kwargs: testutil.NOW

        self.app_context = app.app_context()
        self.app_context.push()
        init_globals()

        self.request_context = app.test_request_context('/')

        # suppress a few warnings
        # local/lib/python3.9/site-packages/bs4/__init__.py:435: MarkupResemblesLocatorWarning: The input looks more like a filename than markup. You may want to open this file and pass the filehandle into Beautiful Soup.
        warnings.filterwarnings('ignore', category=MarkupResemblesLocatorWarning)

    def tearDown(self):
        self.app_context.pop()
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

    def run(self, result=None):
        """Override to hide stdlib and virtualenv lines in tracebacks.

        https://docs.python.org/3.9/library/unittest.html#unittest.TestCase.run
        https://docs.python.org/3.9/library/unittest.html#unittest.TestResult
        """
        result = super().run(result=result)

        def prune(results):
            return [
                (tc, re.sub(r'\n  File ".+/(local|.venv|Python.framework)/.+\n.+\n',
                            '\n', tb))
                for tc, tb in results]

        result.errors = prune(result.errors)
        result.failures = prune(result.failures)
        return result

    # TODO: switch default to Fake, start using that more
    @staticmethod
    def make_user(id, cls=Web, **kwargs):
        """Reuse RSA key across Users because generating it is expensive."""
        user = cls(id=id,
                   direct=True,
                   mod=global_user.mod,
                   public_exponent=global_user.public_exponent,
                   private_exponent=global_user.private_exponent,
                   p256_key=global_user.p256_key,
                   **kwargs)
        user.put()
        return user

    def add_objects(self):
        with self.request_context:
            # post
            Object(id='a', domains=['user.com'], labels=['feed', 'notification'],
                   as2=as2.from_as1(NOTE)).put()
            # different domain
            Object(id='b', domains=['nope.org'], labels=['feed', 'notification'],
                   as2=as2.from_as1(MENTION)).put()
            # reply
            Object(id='d', domains=['user.com'], labels=['feed', 'notification'],
                   as2=as2.from_as1(COMMENT)).put()
            # not feed/notif
            Object(id='e', domains=['user.com'],
                   as2=as2.from_as1(NOTE)).put()
            # deleted
            Object(id='f', domains=['user.com'], labels=['feed', 'notification', 'user'],
                   as2=as2.from_as1(NOTE), deleted=True).put()

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
        got = Object.get_by_id(id)
        assert got, id

        # right now we only do ActivityPub
        for field in 'delivered', 'undelivered', 'failed':
            props[field] = [Target(uri=uri, protocol=delivered_protocol)
                            for uri in props.get(field, [])]

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

        self.assert_entities_equal(Object(id=id, **props), got,
                                   ignore=['as1', 'created', 'expire',
                                           'object_ids', 'type', 'updated'])
        return got

    def assert_user(self, cls, id, **props):
        got = cls.get_by_id(id)
        assert got, id

        self.assert_entities_equal(
            cls(id=id, **props), got,
            ignore=['created', 'mod', 'p256_key', 'private_exponent',
                    'public_exponent', 'updated'])

        if cls != ActivityPub:
            assert got.mod
            assert got.private_exponent
            assert got.public_exponent

        # if cls != ATProto:
        #     assert got.p256_key

        return got

    def assert_equals(self, expected, actual, msg=None, ignore=(), **kwargs):
        return super().assert_equals(
            expected, actual, msg=msg, ignore=tuple(ignore) + ('@context',), **kwargs)
