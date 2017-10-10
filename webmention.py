"""Handles inbound webmentions.

TODO tests:
* actor/attributedTo could be string URL
* salmon rel via webfinger via author.name + domain
"""
import datetime
import json
import logging
import urlparse

import appengine_config

from bs4 import BeautifulSoup
import django_salmon
from django_salmon import magicsigs, utils
import feedparser
from granary import as2, atom, microformats2
from httpsig.requests_auth import HTTPSignatureAuth
import mf2py
import mf2util
from oauth_dropins.webutil import util
import requests
import webapp2

import activitypub
import common
from models import MagicKey, Response


class WebmentionHandler(webapp2.RequestHandler):
    """Handles inbound webmention, converts to ActivityPub or Salmon.

    Instance attributes:
      response: Response
    """

    def post(self):
        logging.info('Params: %s', self.request.params.items())
        source = util.get_required_param(self, 'source')
        target = util.get_required_param(self, 'target')

        # fetch source page, convert to ActivityStreams
        resp = common.requests_get(source)
        mf2 = mf2py.parse(resp.text, url=resp.url)
        # logging.debug('Parsed mf2 for %s: %s', resp.url, json.dumps(mf2, indent=2))
        source_url = resp.url or source

        entry = mf2util.find_first_entry(mf2, ['h-entry'])
        logging.info('First entry: %s', json.dumps(entry, indent=2))
        source_obj = microformats2.json_to_object(entry)
        logging.info('Converted to AS: %s', json.dumps(source_obj, indent=2))

        # fetch target page as AS object. (target is first in-reply-to, not
        # query param.)
        target = util.get_first(source_obj, 'inReplyTo')
        if isinstance(target, dict):
            target = target.get('url')
        if not target:
            self.abort(400, 'No u-in-reply-to found in %s' % source_url)

        try:
            resp = common.requests_get(target, headers=activitypub.CONNEG_HEADER,
                                       log=True)
            target_url = resp.url or target
        except requests.HTTPError as e:
            if e.response.status_code // 100 == 4:
                return self.send_salmon(source_obj, target_url=target_url)
            raise

        self.response = Response.get_or_insert('%s %s' % (source_url, target_url),
                                               direction='out')
        if resp.headers.get('Content-Type').startswith('text/html'):
            return self.send_salmon(source_obj, target_resp=resp)

        # find actor's inbox
        target_obj = resp.json()
        inbox_url = target_obj.get('inbox')

        if not inbox_url:
            # TODO: test actor/attributedTo and not, with/without inbox
            actor = target_obj.get('actor') or target_obj.get('attributedTo')
            if isinstance(actor, dict):
                inbox_url = actor.get('inbox')
                actor = actor.get('url')
            if not inbox_url and not actor:
                self.abort(400, 'Target object has no actor or attributedTo URL')

        if not inbox_url:
            # fetch actor as AS object
            actor = common.requests_get(actor, parse_json=True,
                                        headers=activitypub.CONNEG_HEADER)
            inbox_url = actor.get('inbox')

        if not inbox_url:
            # TODO: probably need a way to save errors like this so that we can
            # return them if ostatus fails too.
            # self.abort(400, 'Target actor has no inbox')
            return self.send_salmon(source_obj, target_url=target_url)

        # convert to AS2
        source_domain = urlparse.urlparse(source_url).netloc
        key = MagicKey.get_or_create(source_domain)
        source_activity = common.postprocess_as2(as2.from_as1(source_obj), key=key)

        # prepare HTTP Signature (required by Mastodon)
        # https://w3c.github.io/activitypub/#authorization-lds
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07
        # https://github.com/tootsuite/mastodon/issues/4906#issuecomment-328844846
        acct = 'acct:me@%s' % source_domain
        auth = HTTPSignatureAuth(secret=key.private_pem(), key_id=acct,
                                 algorithm='rsa-sha256')

        # deliver source object to target actor's inbox.
        headers = {
            'Content-Type': activitypub.CONTENT_TYPE_AS,
            # required for HTTP Signature
            # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
            'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        }
        common.requests_post(
            urlparse.urljoin(target_url, inbox_url), json=source_activity, auth=auth,
            headers=headers, log=True)

        self.response.status = 'complete'
        self.response.protocol = 'activitypub'
        self.response.put()

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
        if not atom_url or not atom_url['href']:
            common.error(self, 'Target post %s has no Atom link' % target_resp.url,
                         status=400)

        # fetch Atom target post, extract id and salmon endpoint
        feed = common.requests_get(atom_url['href']).text
        parsed = feedparser.parse(feed)
        logging.info('Parsed: %s', json.dumps(parsed, indent=2,
                                              default=lambda key: '-'))
        entry = parsed.entries[0]
        target_id = entry.id
        source_obj['inReplyTo'][0]['id'] = target_id

        # Mastodon (and maybe others?) require a rel-mentioned link to the
        # original post's author to make it show up as a reply:
        #   app/services/process_interaction_service.rb
        # ...so add them as a tag, which atom renders as a rel-mention link.
        authors = entry.get('authors', None)
        if authors:
            url = entry.authors[0].get('href')
            if url:
                source_obj.setdefault('tags', []).append({'url': url})

        logging.info('Discovering Salmon endpoint in %s', atom_url['href'])
        endpoint = django_salmon.discover_salmon_endpoint(feed)

        if not endpoint:
            # try webfinger
            parsed = urlparse.urlparse(target_url)
            # TODO: test missing email
            email = entry.author_detail.get('email') or '@'.join(
                (entry.author_detail.name, parsed.netloc))
            try:
                # TODO: always https?
                resp = common.requests_get(
                    '%s://%s/.well-known/webfinger?resource=acct:%s' %
                    (parsed.scheme, parsed.netloc, email),
                    log=True, verify=False)
                endpoint = django_salmon.get_salmon_replies_link(resp.json())
            except requests.HTTPError as e:
                pass

        if not endpoint:
            common.error(self, 'No salmon endpoint found!', status=400)
        logging.info('Discovered Salmon endpoint %s', endpoint)

        # construct reply Atom object
        source_url = self.request.get('source')
        entry = atom.activity_to_atom({'object': source_obj}, xml_base=source_url)
        logging.info('Converted %s to Atom:\n%s', source_url, entry)

        # sign reply and wrap in magic envelope
        domain = urlparse.urlparse(source_url).netloc
        key = MagicKey.get_or_create(domain)
        logging.info('Using key for %s: %s', domain, key)
        magic_envelope = magicsigs.magic_envelope(
            entry, common.ATOM_CONTENT_TYPE, key)

        logging.info('Sending Salmon slap to %s', endpoint)
        common.requests_post(
            endpoint, data=common.XML_UTF8 + magic_envelope, log=True,
            headers={'Content-Type': common.MAGIC_ENVELOPE_CONTENT_TYPE})

        self.response.status = 'complete'
        self.response.protocol = 'ostatus'
        self.response.put()


app = webapp2.WSGIApplication([
    ('/webmention', WebmentionHandler),
], debug=appengine_config.DEBUG)
