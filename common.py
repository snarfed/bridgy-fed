# coding=utf-8
"""Misc common utilities.
"""
from __future__ import unicode_literals
import logging

from oauth_dropins.webutil import util
import requests
from webob import exc

DOMAIN_RE = r'([^/]+\.[^/]+)'
ACCT_RE = r'(?:acct:)?([^@]+)@' + DOMAIN_RE
HEADERS = {
    'User-Agent': 'Bridgy Fed (https://fed.brid.gy/)',
}
ATOM_CONTENT_TYPE = 'application/atom+xml'
MAGIC_ENVELOPE_CONTENT_TYPE = 'application/magic-envelope+xml'
XML_UTF8 = "<?xml version='1.0' encoding='UTF-8'?>\n"
USERNAME = 'me'
# USERNAME_EMOJI = '🌎'  # globe


def requests_get(url, **kwargs):
    return _requests_fn(util.requests_get, url, **kwargs)


def requests_post(url, **kwargs):
    return _requests_fn(util.requests_post, url, **kwargs)


def _requests_fn(fn, url, parse_json=False, log=False, **kwargs):
    """Wraps requests.* and adds raise_for_status() and User-Agent."""
    kwargs.setdefault('headers', {}).update(HEADERS)

    resp = fn(url, **kwargs)
    if log:
        logging.info('Got %s\n  headers:%s\n%s', resp.status_code, resp.headers,
                     resp.text)
    resp.raise_for_status()

    if parse_json:
        try:
            return resp.json()
        except ValueError:
            msg = "Couldn't parse response as JSON"
            logging.error(msg, exc_info=True)
            raise exc.HTTPBadRequest(msg)

    return resp


def error(handler, msg, status=400):
    logging.info(msg)
    handler.abort(status, msg)
