"""Handles inbound webmentions.

TODO: mastodon doesn't advertise salmon endpoint in their individual post atom?!
https://mastodon.technology/users/snarfed/updates/73978.atom
"""
import json
import logging
import urlparse

import appengine_config

from bs4 import BeautifulSoup
import django_salmon
from django_salmon import magicsigs, utils
import feedparser
from granary import atom, microformats2
import mf2py
import mf2util
from oauth_dropins.webutil import util
import requests
import webapp2

import activitypub
import common
import models


class WebmentionHandler(webapp2.RequestHandler):
    """Handles inbound webmention, converts to ActivityPub or Salmon."""

    def post(self):
        logging.info('Params: %s', self.request.params.items())
        source = util.get_required_param(self, 'source')
        target = util.get_required_param(self, 'target')

        # fetch source page, convert to ActivityStreams
        resp = common.requests_get(source)
        mf2 = mf2py.parse(resp.text, url=resp.url)
        logging.info('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))

        entry = mf2util.find_first_entry(mf2, ['h-entry'])
        logging.info('First entry: %s', json.dumps(entry, indent=2))
        source_obj = microformats2.json_to_object(entry)
        logging.info('Converted to AS: %s', json.dumps(source_obj, indent=2))

        # fetch target page as AS object
        try:
            resp = common.requests_get(target, headers=activitypub.CONNEG_HEADER)
        except requests.HTTPError as e:
            if e.response.status_code // 100 == 4:
                return self.send_salmon(source_obj, target_url=target)
            raise

        if resp.headers.get('Content-Type').startswith('text/html'):
            return self.send_salmon(source_obj, target_resp=resp)

        logging.info('Got %s', resp.headers.get('Content-Type'))
        target_obj = resp.json()
        logging.info(json.dumps(target_obj, indent=2))

        # find actor's inbox
        inbox_url = target_obj.get('inbox')

        if not inbox_url:
          # fetch actor as AS object
          actor = target_obj.get('actor') or target_obj.get('attributedTo') or {}
          actor_url = actor.get('url')
          if not actor_url:
              self.abort(400, 'Target object has no actor or attributedTo URL')

          actor = common.requests_get(actor_url, parse_json=True,
                                      headers=activitypub.CONNEG_HEADER)
          inbox_url = actor.get('inbox')

        if not inbox_url:
            # TODO: probably need a way to save errors like this so that we can
            # return them if ostatus fails too.
            # self.abort(400, 'Target actor has no inbox')
            return self.send_salmon(source_obj, target_url=target)

        # deliver source object to target actor's inbox and public
        source_obj.setdefault('cc', []).append(activitypub.PUBLIC_AUDIENCE)

        resp = common.requests_post(
            urlparse.urljoin(target, inbox_url), json=source_obj,
            headers={'Content-Type': activitypub.CONTENT_TYPE_AS})
        logging.info('Got: %s\n%s', resp.headers, resp.text)

    def send_salmon(self, source_obj, target_url=None, target_resp=None):
        # fetch target HTML page, extract Atom rel-alternate link
        if target_url:
            assert not target_resp
            target_resp = common.requests_get(target_url)
        else:
            assert target_resp
            # TODO: this could be different due to redirects
            target_url = target_resp.url

        parsed = BeautifulSoup(target_resp.content, from_encoding=target_resp.encoding)
        atom_url = parsed.find('link', rel='alternate', type=common.ATOM_CONTENT_TYPE)
        assert atom_url  # TODO
        assert atom_url['href']  # TODO

        # fetch Atom target post, extract id and salmon endpoint
        feed = common.requests_get(atom_url['href']).text
        parsed = feedparser.parse(feed)
        target_id = parsed.entries[0].id
        source_obj['inReplyTo'][0]['id'] = target_id

        logging.info('Discovering Salmon endpoint in %s', atom_url['href'])
        endpoint = django_salmon.discover_salmon_endpoint(feed)
        if not endpoint:
            common.error(self, 'No salmon endpoint found!', status=400)
        logging.info('Discovered Salmon endpoint %s', endpoint)

        # construct reply Atom object
        source_url = self.request.get('source')
        entry = atom.activity_to_atom({'object': source_obj}, xml_base=source_url)
        logging.info('Converted %s to Atom:\n%s', source_url, entry)

        # sign reply and wrap in magic envelope
        # TODO: use author h-card's u-url?
        domain = urlparse.urlparse(source_url).netloc.split(':')[0]
        key = models.MagicKey.get_or_create(domain)
        magic_envelope = magicsigs.magic_envelope(
            entry, common.ATOM_CONTENT_TYPE, key)

        logging.info('Sending Salmon slap to %s', endpoint)
        common.requests_post(
            endpoint, data=magic_envelope,
            headers={'Content-Type': common.MAGIC_ENVELOPE_CONTENT_TYPE})


app = webapp2.WSGIApplication([
    ('/webmention', WebmentionHandler),
], debug=appengine_config.DEBUG)
