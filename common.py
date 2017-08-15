"""Misc common utilities.
"""
import json
import logging

import requests
from webob import exc


HEADERS = {
    'User-Agent': 'bridgy-federated (https://fed.brid.gy/)',
}


def requests_get(url, **kwargs):
    return _requests_fn(requests.get, url, **kwargs)


def requests_post(url, **kwargs):
    return _requests_fn(requests.post, url, **kwargs)


def _requests_fn(fn, url, json=False, **kwargs):
    """Wraps requests.* and adds raise_for_status() and User-Agent."""
    kwargs.setdefault('headers', {}).update(HEADERS)
    resp = fn(url, **kwargs)
    resp.raise_for_status()

    if json:
        try:
            return resp.json()
        except ValueError:
            msg = "Couldn't parse response as JSON"
            logging.error(msg, exc_info=True)
            raise exc.HTTPBadRequest(400, msg)

    return resp
