"""Handles inbound webmentions.

TODO tests:
* actor/attributedTo could be string URL
* salmon rel via webfinger via author.name + domain
"""
import logging
import urllib.parse
from urllib.parse import urlencode

import django_salmon
from django_salmon import magicsigs
import feedparser
from flask import request
from flask.views import View
from google.cloud.ndb import Key
from granary import as1, as2, atom, microformats2
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

import activitypub
from app import app
import common
from models import Follower, User, Activity

logger = logging.getLogger(__name__)

SKIP_EMAIL_DOMAINS = frozenset(('localhost', 'snarfed.org'))


class Webmention(View):
    """Handles inbound webmention, converts to ActivityPub or Salmon."""
    source_url = None     # string
    source_domain = None  # string
    source_mf2 = None     # parsed mf2 dict
    source_obj = None     # parsed AS1 dict
    target_resp = None    # requests.Response

    def dispatch_request(self):
        logger.info(f'Params: {list(request.form.items())}')

        # fetch source page
        source = flask_util.get_required_param('source')
        source_resp = common.requests_get(source)
        self.source_url = source_resp.url or source
        self.source_domain = urllib.parse.urlparse(self.source_url).netloc.split(':')[0]
        fragment = urllib.parse.urlparse(self.source_url).fragment
        self.source_mf2 = util.parse_mf2(source_resp, id=fragment)

        # logger.debug(f'Parsed mf2 for {source_resp.url} : {json_dumps(self.source_mf2 indent=2)}')

        # check for backlink to bridgy fed (for webmention spec and to confirm
        # source's intent to federate to mastodon)
        host_url = request.host_url.rstrip('/')  # don't require / path
        if (host_url not in source_resp.text and
            urllib.parse.quote(host_url, safe='') not in source_resp.text):
            error(f"Couldn't find link to {host_url}")

        # convert source page to ActivityStreams
        entry = mf2util.find_first_entry(self.source_mf2, ['h-entry'])
        if not entry:
            error(f'No microformats2 found on {self.source_url}')

        logger.info(f'First entry (id={fragment}: {json_dumps(entry, indent=2)}')
        # make sure it has url, since we use that for AS2 id, which is required
        # for ActivityPub.
        props = entry.setdefault('properties', {})
        if not props.get('url'):
            props['url'] = [self.source_url]

        self.source_obj = microformats2.json_to_object(entry, fetch_mf2=True)
        logger.info(f'Converted to AS1: {json_dumps(self.source_obj, indent=2)}')

        for method in self.try_activitypub, self.try_salmon:
            ret = method()
            if ret:
                return ret

        return ''

    def try_activitypub(self):
        """Attempts ActivityPub delivery.

        Returns Flask response (string body or tuple) if we succeeded or failed,
        None if ActivityPub was not available.
        """
        targets = self._activitypub_targets()
        if not targets:
            return None

        user = User.get_or_create(self.source_domain)
        error = None
        last_success = None

        # TODO: collect by inbox, add 'to' fields, de-dupe inboxes and recipients

        if self.source_obj.get('verb') == 'follow':
            dest_url = self.source_obj.get('object', {}).get('url')
            if dest_url:
                Follower.get_or_create(dest=dest_url, src=self.source_domain,
                                       last_follow=json_dumps(self.source_obj))

        for resp, inbox in targets:
            target_obj = json_loads(resp.target_as2) if resp.target_as2 else None
            source_activity = common.postprocess_as2(
                as2.from_as1(self.source_obj), target=target_obj, user=user)

            if resp.status == 'complete':
                if resp.source_mf2:
                    def content(mf2):
                        items = mf2.get('items')
                        if items:
                            return microformats2.first_props(
                                items[0].get('properties')
                            ).get('content')

                    orig_content = content(json_loads(resp.source_mf2))
                    new_content = content(self.source_mf2)
                    if orig_content and new_content and orig_content == new_content:
                        logger.info(f'Skipping; new content is same as content published before at {resp.updated}')
                        continue

                if source_activity.get('type') == 'Create':
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
            return last_success.text or 'Sent!', last_success.status_code
        elif isinstance(error, BadGateway):
            raise error
        elif isinstance(error, requests.HTTPError):
            return str(error), error.status_code
        else:
            return str(error)

    def _targets(self):
        """
        Returns: list of string URLs, the source's inReplyTos or objects
          (if appropriate)
        """
        targets = util.get_urls(self.source_obj, 'inReplyTo')
        if targets:
            logger.info(f'targets from inReplyTo: {targets}')
            return targets

        if self.source_obj.get('verb') in as1.VERBS_WITH_OBJECT:
            targets = util.get_urls(self.source_obj, 'object')
            logger.info(f'targets from object: {targets}')
            return targets

    def _activitypub_targets(self):
        """
        Returns: list of (Activity, string inbox URL)
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
            inboxes = [(Activity.get_or_create(
                          source=self.source_url, target=inbox,
                          domain=[self.source_domain], direction='out',
                          protocol='activitypub', source_mf2=json_dumps(self.source_mf2)),
                        inbox) for inbox in sorted(inboxes) if inbox]
            logger.info(f"Delivering to followers' inboxes: {[i for _, i in inboxes]}")
            return inboxes

        targets = common.remove_blocklisted(targets)
        if not targets:
            error(f"Silo responses are not yet supported.")

        activities_and_inbox_urls = []
        for target in targets:
            # fetch target page as AS2 object
            try:
                self.target_resp = common.get_as2(target)
            except (requests.HTTPError, BadGateway) as e:
                self.target_resp = getattr(e, 'requests_response', None)
                if self.target_resp and self.target_resp.status_code // 100 == 2:
                    content_type = common.content_type(self.target_resp) or ''
                    if content_type.startswith('text/html'):
                        # TODO: pass e.requests_response to try_salmon's target_resp
                        continue  # give up
                raise
            target_url = self.target_resp.url or target

            activity = Activity.get_or_create(
                source=self.source_url, target=target_url, domain=[self.source_domain],
                direction='out', protocol='activitypub',
                source_mf2=json_dumps(self.source_mf2))

            # find target's inbox
            target_obj = self.target_resp.json()
            activity.target_as2 = json_dumps(target_obj)
            inbox_url = target_obj.get('inbox')

            if not inbox_url:
                # TODO: test actor/attributedTo and not, with/without inbox
                actor = (util.get_first(target_obj, 'actor') or
                         util.get_first(target_obj, 'attributedTo'))
                if isinstance(actor, dict):
                    inbox_url = actor.get('inbox')
                    actor = actor.get('url') or actor.get('id')
                if not inbox_url and not actor:
                    error('Target object has no actor or attributedTo with URL or id.')
                elif not isinstance(actor, str):
                    error(f'Target actor or attributedTo has unexpected url or id object: {actor}')

            if not inbox_url:
                # fetch actor as AS object
                actor = common.get_as2(actor).json()
                inbox_url = actor.get('inbox')

            if not inbox_url:
                # TODO: probably need a way to save errors like this so that we can
                # return them if ostatus fails too.
                # error('Target actor has no inbox')
                continue

            inbox_url = urllib.parse.urljoin(target_url, inbox_url)
            activities_and_inbox_urls.append((activity, inbox_url))

        logger.info(f"Delivering to targets' inboxes: {[i for _, i in activities_and_inbox_urls]}")
        return activities_and_inbox_urls

    def try_salmon(self):
        """
        Returns Flask response (string body or tuple) if we attempted OStatus
        delivery (whether successful or not), None if we didn't attempt, raises
        an exception otherwise.
        """
        target = None
        if self.target_resp:
            target = self.target_resp.url
        else:
            targets = self._targets()
            if targets:
                target = targets[0]
        if not target:
            logger.warning("No targets or followers. Ignoring.")
            return

        status = None
        try:
            ret = self._try_salmon(target)
            if isinstance(ret, str):
                status = 'complete'
            return ret
        except:
            status = 'error'
            raise
        finally:
            if status:
                Activity(source=self.source_url, target=target, status=status,
                         domain=[self.source_domain], direction='out',
                         protocol = 'ostatus',
                         source_mf2=json_dumps(self.source_mf2)).put()

    def _try_salmon(self, target):
        """
        Args:
          target: string
        """
        # fetch target HTML page, extract Atom rel-alternate link
        if not self.target_resp:
            self.target_resp = common.requests_get(target)

        parsed = util.parse_html(self.target_resp)
        atom_url = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        if not atom_url or not atom_url.get('href'):
            error(f'Target post {target} has no Atom link')

        # fetch Atom target post, extract and inject id into source object
        base_url = ''
        base = parsed.find('base')
        if base and base.get('href'):
            base_url = base['href']
        atom_link = parsed.find('link', rel='alternate', type=common.CONTENT_TYPE_ATOM)
        atom_url = urllib.parse.urljoin(
            target, urllib.parse.urljoin(base_url, atom_link['href']))

        feed = common.requests_get(atom_url).text
        parsed = feedparser.parse(feed)
        entry = parsed.entries[0]
        logger.info(f'Parsed: {json_dumps(entry, indent=2)}')
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
        logger.info(f'Discovering Salmon endpoint in {atom_url}')
        endpoint = django_salmon.discover_salmon_endpoint(feed)

        if not endpoint:
            # try webfinger
            parsed = urllib.parse.urlparse(target)
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
            error('No salmon endpoint found!')
        logger.info(f'Discovered Salmon endpoint {endpoint}')

        # construct reply Atom object
        activity = self.source_obj
        if self.source_obj.get('verb') not in as1.VERBS_WITH_OBJECT:
            activity = {'object': self.source_obj}
        entry = atom.activity_to_atom(activity, xml_base=self.source_url)
        logger.info(f'Converted {self.source_url} to Atom:\n{entry}')

        # sign reply and wrap in magic envelope
        domain = urllib.parse.urlparse(self.source_url).netloc
        user = User.get_or_create(domain)
        logger.info(f'Using key for {domain}: {user}')
        magic_envelope = magicsigs.magic_envelope(
            entry, common.CONTENT_TYPE_ATOM, user).decode()

        logger.info(f'Sending Salmon slap to {endpoint}')
        common.requests_post(
            endpoint, data=common.XML_UTF8 + magic_envelope,
            headers={'Content-Type': common.CONTENT_TYPE_MAGIC_ENVELOPE})

        return 'Sent!'


app.add_url_rule('/webmention', view_func=Webmention.as_view('webmention'),
                 methods=['POST'])
