# coding=utf-8
"""Unit tests for webfinger.py.

TODO: test error handling
"""
import json
import unittest
import urllib

import mock
import requests

import webfinger
from webfinger import app
import common


class WebFingerTest(unittest.TestCase):

    def test_host_meta_handler_xrd(self):
        got = app.get_response('/.well-known/host-meta')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/xrd+xml; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('<?xml'), got.body)

    def test_host_meta_handler_xrds(self):
        got = app.get_response('/.well-known/host-meta.xrds')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/xrds+xml; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('<XRDS'), got.body)

    def test_host_meta_handler_jrd(self):
        got = app.get_response('/.well-known/host-meta.json')
        self.assertEquals(200, got.status_int)
        self.assertEquals('application/json; charset=utf-8',
                          got.headers['Content-Type'])
        self.assertTrue(got.body.startswith('{'), got.body)
