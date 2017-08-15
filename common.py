"""Misc common utilities.
"""
import json
import logging

import mf2py
import requests

HEADERS = {
    'User-Agent': 'bridgy-federated (https://fed.brid.gy/)',
}


def requests_get(url, **kwargs):
    kwargs.setdefault('headers', {}).update(HEADERS)
    resp = requests.get(url, **kwargs)
    resp.raise_for_status()
    return resp


# def fetch_mf2(url):
#     """Fetches a URL and parses and returns its mf2.

#     Args:
#       url: string

#     Returns: dict, parsed mf2
#     """
#     resp = requests.get(url=url, headers={'User-Agent': USER_AGENT})
#     resp.raise_for_status()
#     mf2 = mf2py.parse(resp.text, url=resp.url)
#     logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))
#     return mf2
