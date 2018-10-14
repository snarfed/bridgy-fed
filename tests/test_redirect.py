"""Unit tests for redirect.py.
"""
from redirect import app
import testutil


class ActivityPubTest(testutil.TestCase):

    def test_redirect(self):
        got = app.get_response('/r/https://foo.com/bar?baz=baj&biff')
        self.assertEqual(302, got.status_int)
        self.assertEqual('https://foo.com/bar?baz=baj&biff', got.headers['Location'])

    def test_redirect_scheme_missing(self):
        got = app.get_response('/r/asdf.com')
        self.assertEqual(400, got.status_int)

    def test_redirect_url_missing(self):
        got = app.get_response('/r/')
        self.assertEqual(404, got.status_int)
