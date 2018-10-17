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
from google.appengine.api import mail
from granary import as2, atom, microformats2, source
from httpsig.requests_auth import HTTPSignatureAuth
import mf2py
import mf2util
from oauth_dropins.webutil import util
import requests
import webapp2
from webob import exc

import activitypub
import common
from models import MagicKey, Response

SKIP_EMAIL_DOMAINS = frozenset(('localhost', 'snarfed.org'))


class WebmentionHandler(webapp2.RequestHandler):
    """Handles inbound webmention, converts to ActivityPub or Salmon.

    Instance attributes:
      resp: Response
    """

    def post(self):
        logging.info('(Params: %s )', self.request.params.items())

        self.resp = None
        try:
            self.try_activitypub()
            if self.resp:
                self.resp.status = 'complete'
        except:
            if self.resp:
                self.resp.status = 'error'
            raise
        finally:
            if self.resp:
                self.resp.put()

        source = util.get_required_param(self, 'source')
        if urlparse.urlparse(source).netloc.split(':')[0] not in SKIP_EMAIL_DOMAINS:
          try:
              msg = 'Bridgy Fed: new webmention from %s' % source
              mail.send_mail(
                  sender='admin@bridgy-federated.appspotmail.com',
                  to='bridgy-fed@ryanb.org',
                  subject=msg, body=msg)
          except BaseException:
              logging.warning('Error sending email', exc_info=True)

    def try_activitypub(self):
        source = util.get_required_param(self, 'source')

        # fetch source page, convert to ActivityStreams
        source_resp = common.requests_get(source)
        source_url = source_resp.url or source
        source_mf2 = mf2py.parse(source_resp.text, url=source_url, img_with_alt=True)
        # logging.debug('Parsed mf2 for %s: %s', source_resp.url, json.dumps(source_mf2, indent=2))

        entry = mf2util.find_first_entry(source_mf2, ['h-entry'])
        if not entry:
            common.error(self, 'No microformats2 found on %s' % source_url)

        logging.info('First entry: %s', json.dumps(entry, indent=2))
        # make sure it has url, since we use that for AS2 id, which is required
        # for ActivityPub.
        props = entry.setdefault('properties', {})
        if not props.get('url'):
            props['url'] = [source_url]

        source_obj = microformats2.json_to_object(entry, fetch_mf2=True)
        logging.info('Converted to AS: %s', json.dumps(source_obj, indent=2))

        # fetch target page as AS object. target is first in-reply-to, like-of,
        # or repost-of, *not* target query param.)
        target = util.get_url(util.get_first(source_obj, 'inReplyTo') or
                              util.get_first(source_obj, 'object'))
        if not target:
            common.error(self, 'No u-in-reply-to, u-like-of, or u-repost-of '
                         'found in %s' % source_url)

        try:
            target_resp = common.get_as2(target)
        except (requests.HTTPError, exc.HTTPBadGateway) as e:
            if (e.response.status_code // 100 == 2 and
                common.content_type(e.response).startswith('text/html')):
                self.resp = Response.get_or_create(
                    source=source_url, target=e.response.url or target,
                    direction='out', source_mf2=json.dumps(source_mf2))
                return self.send_salmon(source_obj, target_resp=e.response)
            raise

        target_url = target_resp.url or target
        self.resp = Response.get_or_create(
            source=source_url, target=target_url, direction='out',
            protocol='activitypub', source_mf2=json.dumps(source_mf2))

        # find actor's inbox
        target_obj = target_resp.json()
        inbox_url = target_obj.get('inbox')

        if not inbox_url:
            # TODO: test actor/attributedTo and not, with/without inbox
            actor = target_obj.get('actor') or target_obj.get('attributedTo')
            if isinstance(actor, dict):
                inbox_url = actor.get('inbox')
                actor = actor.get('url')
            if not inbox_url and not actor:
                common.error(self, 'Target object has no actor or attributedTo URL')

        if not inbox_url:
            # fetch actor as AS object
            actor = common.get_as2(actor).json()
            inbox_url = actor.get('inbox')

        if not inbox_url:
            # TODO: probably need a way to save errors like this so that we can
            # return them if ostatus fails too.
            # common.error(self, 'Target actor has no inbox')
            return self.send_salmon(source_obj, target_resp=target_resp)

        # convert to AS2
        source_domain = urlparse.urlparse(source_url).netloc
        key = MagicKey.get_or_create(source_domain)
        source_activity = common.postprocess_as2(
            as2.from_as1(source_obj), target=target_obj, key=key)

        if self.resp.status == 'complete':
            source_activity['type'] = 'Update'

        # prepare HTTP Signature (required by Mastodon)
        # https://w3c.github.io/activitypub/#authorization-lds
        # https://tools.ietf.org/html/draft-cavage-http-signatures-07
        # https://github.com/tootsuite/mastodon/issues/4906#issuecomment-328844846
        acct = 'acct:%s@%s' % (source_domain, source_domain)
        auth = HTTPSignatureAuth(secret=key.private_pem(), key_id=acct,
                                 algorithm='rsa-sha256')

        # deliver source object to target actor's inbox.
        headers = {
            'Content-Type': common.CONTENT_TYPE_AS2,
            # required for HTTP Signature
            # https://tools.ietf.org/html/draft-cavage-http-signatures-07#section-2.1.3
            'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        }
        inbox_url = urlparse.urljoin(target_url, inbox_url)
        resp = common.requests_post(inbox_url, json=source_activity, auth=auth,
                                    headers=headers)
        self.response.status_int = resp.status_code
        self.response.write(resp.text)

    def send_salmon(self, source_obj, target_resp=None):
        self.resp.protocol = 'ostatus'

        # fetch target HTML page, extract Atom rel-alternate link
        if not target_resp:
            target_resp = common.requests_get(self.resp.target())

        parsed = common.beautifulsoup_parse(target_resp.content, from_encoding=target_resp.encoding)
        atom_url = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        if not atom_url or not atom_url.get('href'):
            common.error(self, 'Target post %s has no Atom link' % self.resp.target(),
                         status=400)

        # fetch Atom target post, extract and inject id into source object
        feed = common.requests_get(atom_url['href']).text
        parsed = feedparser.parse(feed)
        logging.info('Parsed: %s', json.dumps(parsed, indent=2,
                                              default=lambda key: '-'))
        entry = parsed.entries[0]
        target_id = entry.id
        in_reply_to = source_obj.get('inReplyTo')
        source_obj_obj = source_obj.get('object')
        if in_reply_to:
            in_reply_to[0]['id'] = target_id
        elif isinstance(source_obj_obj, dict):
            source_obj_obj['id'] = target_id

        # Mastodon (and maybe others?) require a rel-mentioned link to the
        # original post's author to make it show up as a reply:
        #   app/services/process_interaction_service.rb
        # ...so add them as a tag, which atom renders as a rel-mention link.
        authors = entry.get('authors', None)
        if authors:
            url = entry.authors[0].get('href')
            if url:
                source_obj.setdefault('tags', []).append({'url': url})

        # extract and discover salmon endpoint
        logging.info('Discovering Salmon endpoint in %s', atom_url['href'])
        endpoint = django_salmon.discover_salmon_endpoint(feed)

        if not endpoint:
            # try webfinger
            parsed = urlparse.urlparse(self.resp.target())
            # TODO: test missing email
            email = entry.author_detail.get('email') or '@'.join(
                (entry.author_detail.name, parsed.netloc))
            try:
                # TODO: always https?
                resp = common.requests_get(
                    '%s://%s/.well-known/webfinger?resource=acct:%s' %
                    (parsed.scheme, parsed.netloc, email), verify=False)
                endpoint = django_salmon.get_salmon_replies_link(resp.json())
            except requests.HTTPError as e:
                pass

        if not endpoint:
            common.error(self, 'No salmon endpoint found!', status=400)
        logging.info('Discovered Salmon endpoint %s', endpoint)

        # construct reply Atom object
        source_url = self.resp.source()
        activity = (source_obj if source_obj.get('verb') in source.VERBS_WITH_OBJECT
                    else {'object': source_obj})
        entry = atom.activity_to_atom(activity, xml_base=source_url)
        logging.info('Converted %s to Atom:\n%s', source_url, entry)

        # sign reply and wrap in magic envelope
        domain = urlparse.urlparse(source_url).netloc
        key = MagicKey.get_or_create(domain)
        logging.info('Using key for %s: %s', domain, key)
        magic_envelope = magicsigs.magic_envelope(
            entry, common.CONTENT_TYPE_ATOM, key)

        logging.info('Sending Salmon slap to %s', endpoint)
        common.requests_post(
            endpoint, data=common.XML_UTF8 + magic_envelope,
            headers={'Content-Type': common.CONTENT_TYPE_MAGIC_ENVELOPE})


app = webapp2.WSGIApplication([
    ('/webmention', WebmentionHandler),
], debug=appengine_config.DEBUG)
