"""Unit tests for flask_app.py."""
from lexrpc.base import XrpcError
from lexrpc.server import Redirect

import flask_app

from .testutil import TestCase


class FlaskAppTest(TestCase):
    def test_get_repo_redirect(self):
        with self.assertRaises(Redirect) as err, \
             flask_app.app.test_request_context('/xrpc/getRepo?did=foo'):
            flask_app.get_repo({}, did='did:plc:123')

        self.assertEqual(302, err.exception.status)
        self.assertEqual('https://bridgy-hubble.microcosm.blue/xrpc/getRepo?did=foo',
                         err.exception.to)

    def test_get_repo_authorization(self):
        with self.assertRaises(XrpcError), \
             flask_app.app.test_request_context('/', headers={'Authorization': 'x'}):
            flask_app.get_repo({}, did='did:plc:123')
