"""Handles inbound webmentions.

TODO tests:
* actor/attributedTo could be string URL
* salmon rel via webfinger via author.name + domain
"""
import logging
import urllib.parse
from  urllib.parse import urlencode

import django_salmon
from django_salmon import magicsigs
import feedparser
from google.cloud.ndb import Key
from granary import as2, atom, microformats2, source
import mf2util
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
import webapp2
from webob import exc

import activitypub
import common
from models import Follower, MagicKey, Response

SKIP_EMAIL_DOMAINS = frozenset(('localhost', 'snarfed.org'))


class WebmentionHandler():
    """Handles inbound webmention, converts to ActivityPub or Salmon."""
    source_url = None     # string
    source_domain = None  # string
    source_mf2 = None     # parsed mf2 dict
    source_obj = None     # parsed AS1 dict
    target_resp = None    # requests.Response

    def post(self):
        logging.info('Params: %s', list(self.request.params.items()))

        # fetch source page
        source = util.get_required_param(self, 'source')
        source_resp = common.requests_get(source)
        self.source_url = source_resp.url or source
        self.source_domain = urllib.parse.urlparse(self.source_url).netloc.split(':')[0]
        self.source_mf2 = util.parse_mf2(source_resp)

        # logging.debug('Parsed mf2 for %s: %s', source_resp.url, json_dumps(self.source_mf2 indent=2))

        # check for backlink to bridgy fed (for webmention spec and to confirm
        # source's intent to federate to mastodon)
        if (self.request.host_url not in source_resp.text and
            urllib.parse.quote(self.request.host_url, safe='') not in source_resp.text):
            self.error("Couldn't find link to {request.host_url}")

        # convert source page to ActivityStreams
        entry = mf2util.find_first_entry(self.source_mf2, ['h-entry'])
        if not entry:
            self.error('No microformats2 found on %s' % self.source_url)

        logging.info('First entry: %s', json_dumps(entry, indent=2))
        # make sure it has url, since we use that for AS2 id, which is required
        # for ActivityPub.
        props = entry.setdefault('properties', {})
        if not props.get('url'):
            props['url'] = [self.source_url]

        self.source_obj = microformats2.json_to_object(entry, fetch_mf2=True)
        logging.info('Converted to AS1: %s', json_dumps(self.source_obj, indent=2))

        tried_ap = self.try_activitypub()
        if tried_ap is None:
            self.try_salmon()

    def try_activitypub(self):
        """Attempts ActivityPub delivery.

        Returns True if we succeeded, False if we failed, None if ActivityPub
        was not available.
        """
        targets = self._activitypub_targets()
        if not targets:
            return None

        key = MagicKey.get_or_create(self.source_domain)
        error = None
        last_success = None

        # TODO: collect by inbox, add 'to' fields, de-dupe inboxes and recipients

        for resp, inbox in targets:
            target_obj = json_loads(resp.target_as2) if resp.target_as2 else None
            source_activity = self.postprocess_as2(
                as2.from_as1(self.source_obj), target=target_obj, key=key)

            if resp.status == 'complete':
                source_activity['type'] = 'Update'

            try:
                last = activitypub.send(source_activity, inbox, self.source_domain)
                resp.status = 'complete'
                last_success = last
            except BaseException as e:
                error = e
                resp.status = 'error'

            resp.put()

        # Pass the AP response status code and body through as our response
        if last_success:
            self.response.status_int = last_success.status_code
            self.response.write(last_success.text)
        elif isinstance(error, (requests.HTTPError, exc.HTTPBadGateway)):
            self.response.status_int = error.status_code
            self.response.write(str(error))
        else:
            self.response.write(str(error))

        return bool(last_success)

    def _targets(self):
        """
        Returns: list of string URLs, the source's inReplyTos or objects
          (if appropriate)
        """
        targets = util.get_urls(self.source_obj, 'inReplyTo')
        if targets:
            return targets

        if self.source_obj.get('verb') in source.VERBS_WITH_OBJECT:
            return util.get_urls(self.source_obj, 'object')

    def _activitypub_targets(self):
        """
        Returns: list of (Response, string inbox URL)
        """
        # if there's in-reply-to, like-of, or repost-of, they're the targets.
        # otherwise, it's all followers' inboxes.
        targets = self._targets()

        if not targets:
            # interpret this as a Create or Update, deliver it to followers
            inboxes = set()
            for follower in Follower.query().filter(
                Follower.key > Key('Follower', self.source_domain + ' '),
                Follower.key < Key('Follower', self.source_domain + chr(ord(' ') + 1))):
                if follower.status != 'inactive' and follower.last_follow:
                    actor = json_loads(follower.last_follow).get('actor')
                    if actor and isinstance(actor, dict):
                        inboxes.add(actor.get('endpoints', {}).get('sharedInbox') or
                                    actor.get('publicInbox')or
                                    actor.get('inbox'))
            return [(Response.get_or_create(
                        source=self.source_url, target=inbox, direction='out',
                        protocol='activitypub', source_mf2=json_dumps(self.source_mf2)),
                     inbox)
                    for inbox in sorted(inboxes) if inbox]

        resps_and_inbox_urls = []
        for target in targets:
          # fetch target page as AS2 object
          try:
              self.target_resp = common.get_as2(target)
          except (requests.HTTPError, exc.HTTPBadGateway) as e:
              self.target_resp = getattr(e, 'response', None)
              if self.target_resp and self.target_resp.status_code // 100 == 2:
                  content_type = common.content_type(self.target_resp) or ''
                  if content_type.startswith('text/html'):
                      # TODO: pass e.response to try_salmon()'s target_resp
                      continue  # give up
              raise
          target_url = self.target_resp.url or target

          resp = Response.get_or_create(
              source=self.source_url, target=target_url, direction='out',
              protocol='activitypub', source_mf2=json_dumps(self.source_mf2))

          # find target's inbox
          target_obj = self.target_resp.json()
          resp.target_as2 = json_dumps(target_obj)
          inbox_url = target_obj.get('inbox')

          if not inbox_url:
              # TODO: test actor/attributedTo and not, with/without inbox
              actor = (util.get_first(target_obj, 'actor') or
                       util.get_first(target_obj, 'attributedTo'))
              if isinstance(actor, dict):
                  inbox_url = actor.get('inbox')
                  actor = actor.get('url') or actor.get('id')
              if not inbox_url and not actor:
                  self.error('Target object has no actor or attributedTo with URL or id.')
              elif not isinstance(actor, str):
                  self.error('Target actor or attributedTo has unexpected url or id object: %r' % actor)

          if not inbox_url:
              # fetch actor as AS object
              actor = common.get_as2(actor).json()
              inbox_url = actor.get('inbox')

          if not inbox_url:
              # TODO: probably need a way to save errors like this so that we can
              # return them if ostatus fails too.
              # self.error('Target actor has no inbox')
              continue

          inbox_url = urllib.parse.urljoin(target_url, inbox_url)
          resps_and_inbox_urls.append((resp, inbox_url))

        return resps_and_inbox_urls

    def try_salmon(self):
        """Returns True if we attempted OStatus delivery. Raises otherwise."""
        target = None
        if self.target_resp:
            target = self.target_resp.url
        else:
            targets = self._targets()
            if targets:
                target = targets[0]
        if not target:
            logging.warning("No targets or followers. Ignoring.")
            return False

        resp = Response.get_or_create(
            source=self.source_url, target=target, direction='out',
            source_mf2=json_dumps(self.source_mf2))
        resp.protocol = 'ostatus'

        try:
            ret = self._try_salmon(resp)
            resp.status = 'complete'
            return ret
        except:
            resp.status = 'error'
            raise
        finally:
            resp.put()

    def _try_salmon(self, resp):
        """
        Args:
          resp: Response
        """
        # fetch target HTML page, extract Atom rel-alternate link
        target = resp.target()
        if not self.target_resp:
            self.target_resp = common.requests_get(target)

        parsed = util.parse_html(self.target_resp)
        atom_url = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        if not atom_url or not atom_url.get('href'):
            self.error('Target post %s has no Atom link' % resp.target(), status=400)

        # fetch Atom target post, extract and inject id into source object
        base_url = ''
        base = parsed.find('base')
        if base and base.get('href'):
            base_url = base['href']
        atom_link = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        atom_url = urllib.parse.urljoin(
            resp.target(), urllib.parse.urljoin(base_url, atom_link['href']))

        feed = common.requests_get(atom_url).text
        parsed = feedparser.parse(feed)
        logging.info('Parsed: %s', json_dumps(parsed, indent=2))
        entry = parsed.entries[0]
        target_id = entry.id
        in_reply_to = self.source_obj.get('inReplyTo')
        source_obj_obj = self.source_obj.get('object')
        if in_reply_to:
            for elem in in_reply_to:
                if elem.get('url') == target:
                    elem['id'] = target_id
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
                self.source_obj.setdefault('tags', []).append({'url': url})

        # extract and discover salmon endpoint
        logging.info('Discovering Salmon endpoint in %s', atom_url)
        endpoint = django_salmon.discover_salmon_endpoint(feed)

        if not endpoint:
            # try webfinger
            parsed = urllib.parse.urlparse(resp.target())
            # TODO: test missing email
            author = entry.get('author_detail', {})
            email = author.get('email') or '@'.join(
                (author.get('name', ''), parsed.netloc))
            try:
                # TODO: always https?
                profile = common.requests_get(
                    '%s://%s/.well-known/webfinger?resource=acct:%s' %
                    (parsed.scheme, parsed.netloc, email), parse_json=True)
                endpoint = django_salmon.get_salmon_replies_link(profile)
            except requests.HTTPError as e:
                pass

        if not endpoint:
            self.error('No salmon endpoint found!', status=400)
        logging.info('Discovered Salmon endpoint %s', endpoint)

        # construct reply Atom object
        self.source_url = resp.source()
        activity = self.source_obj
        if self.source_obj.get('verb') not in source.VERBS_WITH_OBJECT:
            activity = {'object': self.source_obj}
        entry = atom.activity_to_atom(activity, xml_base=self.source_url)
        logging.info('Converted %s to Atom:\n%s', self.source_url, entry)

        # sign reply and wrap in magic envelope
        domain = urllib.parse.urlparse(self.source_url).netloc
        key = MagicKey.get_or_create(domain)
        logging.info('Using key for %s: %s', domain, key)
        magic_envelope = magicsigs.magic_envelope(
            entry, common.CONTENT_TYPE_ATOM, key).decode()

        logging.info('Sending Salmon slap to %s', endpoint)
        common.requests_post(
            endpoint, data=common.XML_UTF8 + magic_envelope,
            headers={'Content-Type': common.CONTENT_TYPE_MAGIC_ENVELOPE})
        return True


ROUTES = [
    ('/webmention', WebmentionHandler),
]
