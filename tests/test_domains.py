"""Unit tests for domains.py."""
from domains import (
    host_url,
    redirect_wrap,
    subdomain_wrap,
    unwrap,
)
from flask_app import app
import protocol  # just to break a circular import
import ui

from .testutil import Fake, TestCase


class DomainsTest(TestCase):
    def test_redirect_wrap_empty(self):
        self.assertIsNone(redirect_wrap(None))
        self.assertEqual('', redirect_wrap(''))

    def test_redirect_wrap(self):
        self.assertEqual('http://localhost/r/http://foo',
                         redirect_wrap('http://foo'))

    def test_redirect_noop(self):
        self.assertEqual('http://ap.brid.gy/r/http://foo',
                         redirect_wrap('http://ap.brid.gy/r/http://foo'))

    def test_unwrap_empty(self):
        self.assertIsNone(unwrap(None))
        for obj in '', {}, []:
            self.assertEqual(obj, unwrap(obj))

    def test_subdomain_wrap(self):
        self.assertEqual('https://fa.brid.gy/', subdomain_wrap(Fake))
        self.assertEqual('https://fa.brid.gy/foo?bar', subdomain_wrap(Fake, 'foo?bar'))
        self.assertEqual('https://fed.brid.gy/', subdomain_wrap(ui.UIProtocol))

    def test_unwrap_protocol_subdomain(self):
        for input, expected in [
                ('https://fa.brid.gy/ap/fake:foo', 'fake:foo'),
                ('https://bsky.brid.gy/convert/ap/did:plc:123', 'did:plc:123'),
                # preserve protocol bot user ids
                ('https://fed.brid.gy/', 'https://fed.brid.gy/'),
                ('https://fa.brid.gy/', 'https://fa.brid.gy/'),
                ('fa.brid.gy', 'fa.brid.gy'),
        ]:
            self.assertEqual(expected, unwrap(input))

    def test_unwrap_protocol_subdomain_object(self):
        self.assert_equals({'object': 'http://foo'},
                           unwrap({'object': 'https://ap.brid.gy/r/http://foo',}))
        self.assert_equals({'object': {'id': 'https://foo.com/'}},
                           unwrap({'object': {'id': 'https://fa.brid.gy/foo.com'}}))

    def test_unwrap_local_actor_urls(self):
        self.assert_equals({'object': 'https://foo.com/'},
                           unwrap({'object': 'http://localhost/foo.com'}))

        self.assert_equals({'object': {'id': 'https://foo.com/'}},
                           unwrap({'object': {'id': 'http://localhost/foo.com'}}))

    def test_unwrap_int_id(self):
        self.assert_equals({'id': 3}, unwrap({'id': 3}))

    def test_host_url(self):
        with app.test_request_context():
            self.assertEqual('http://localhost/', host_url())
            self.assertEqual('http://localhost/asdf', host_url('asdf'))
            self.assertEqual('http://localhost/foo/bar', host_url('/foo/bar'))

        with app.test_request_context(base_url='https://a.xyz', path='/foo'):
            self.assertEqual('https://a.xyz/', host_url())
            self.assertEqual('https://a.xyz/asdf', host_url('asdf'))
            self.assertEqual('https://a.xyz/foo/bar', host_url('/foo/bar'))

        with app.test_request_context(base_url='http://bridgy-federated.uc.r.appspot.com'):
            self.assertEqual('https://fed.brid.gy/asdf', host_url('asdf'))

        with app.test_request_context(base_url='https://bsky.brid.gy', path='/foo'):
            self.assertEqual('https://bsky.brid.gy/asdf', host_url('asdf'))
