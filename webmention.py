"""Handles inbound webmentions.

TODO tests:
* actor/attributedTo could be string URL
"""
import logging
import urllib.parse
from urllib.parse import urlencode

import feedparser
from flask import request
from flask.views import View
from google.cloud.ndb import Key
from granary import as1, as2, atom, microformats2
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.flask_util import error
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway

import activitypub
from app import app
import common
from models import Activity, Follower, User

logger = logging.getLogger(__name__)

SKIP_EMAIL_DOMAINS = frozenset(('localhost', 'snarfed.org'))

# https://cloud.google.com/appengine/docs/locations
TASKS_LOCATION = 'us-central1'


class Webmention(View):
    """Handles inbound webmention, converts to ActivityPub."""
    IS_TASK = False

    source_url = None     # string
    source_domain = None  # string
    source_mf2 = None     # parsed mf2 dict
    source_obj = None     # parsed AS1 dict
    target_resp = None    # requests.Response
    user = None           # User

    def dispatch_request(self):
        logger.info(f'Params: {list(request.form.items())}')

        # fetch source page
        source = flask_util.get_required_param('source')
        logger.info(f'webmention from {util.domain_from_link(source, minimize=False)}')
        try:
            source_resp = util.requests_get(source, gateway=True)
        except ValueError as e:
            error(f'Bad source URL: {source}: {e}')
        self.source_url = source_resp.url or source
        self.source_domain = urllib.parse.urlparse(self.source_url).netloc.split(':')[0]
        fragment = urllib.parse.urlparse(self.source_url).fragment
        self.source_mf2 = util.parse_mf2(source_resp, id=fragment)

        if id and self.source_mf2 is None:
            error(f'id {fragment} not found in {self.source_url}')

        # logger.debug(f'Parsed mf2 for {source_resp.url} : {json_dumps(self.source_mf2 indent=2)}')

        # check for backlink to bridgy fed (for webmention spec and to confirm
        # source's intent to federate to mastodon)
        for domain in common.DOMAINS:
            if domain in source_resp.text:
                break
        else:
            error(f"Couldn't find link to {common.host_url().rstrip('/')}")

        # convert source page to ActivityStreams
        entry = mf2util.find_first_entry(self.source_mf2, ['h-entry'])
        if not entry:
            error(f'No microformats2 found on {self.source_url}')

        logger.info(f'First entry (id={fragment}): {json_dumps(entry, indent=2)}')
        # make sure it has url, since we use that for AS2 id, which is required
        # for ActivityPub.
        props = entry.setdefault('properties', {})
        if not props.get('url'):
            props['url'] = [self.source_url]

        self.source_obj = microformats2.json_to_object(entry, fetch_mf2=True)
        type_label = ' '.join((
            self.source_obj.get('verb', ''),
            self.source_obj.get('objectType', ''),
            util.get_first(self.source_obj, 'object', {}).get('objectType', ''),
        ))
        logger.info(f'Converted webmention to AS1: {type_label}: {json_dumps(self.source_obj, indent=2)}')

        self.user = User.get_or_create(self.source_domain)
        ret = self.try_activitypub()
        return ret or 'No ActivityPub targets'

    def try_activitypub(self):
        """Attempts ActivityPub delivery.

        Returns Flask response (string body or tuple) if we succeeded or failed,
        None if ActivityPub was not available.
        """
        targets = self._activitypub_targets()
        if not targets:
            return None

        error = None
        last_success = None

        # TODO: collect by inbox, add 'to' fields, de-dupe inboxes and recipients

        for activity, inbox in targets:
            target_obj = json_loads(activity.target_as2) if activity.target_as2 else None

            source_activity = common.postprocess_as2(
                as2.from_as1(self.source_obj), target=target_obj, user=self.user)
            if not source_activity.get('actor'):
                source_activity['actor'] = common.host_url(self.source_domain)

            if activity.status == 'complete':
                if activity.source_mf2:
                    def content(mf2):
                        items = mf2.get('items')
                        if items:
                            return microformats2.first_props(
                                items[0].get('properties')
                            ).get('content')

                    orig_content = content(json_loads(activity.source_mf2))
                    new_content = content(self.source_mf2)
                    if orig_content and new_content and orig_content == new_content:
                        logger.info(f'Skipping; new content is same as content published before at {activity.updated}')
                        continue

                if source_activity.get('type') == 'Create':
                    source_activity['type'] = 'Update'
                    # Mastodon requires the updated field for Updates, so
                    # generate it if it's not already there.
                    # https://docs.joinmastodon.org/spec/activitypub/#supported-activities-for-statuses
                    # https://socialhub.activitypub.rocks/t/what-could-be-the-reason-that-my-update-activity-does-not-work/2893/4
                    # https://github.com/mastodon/documentation/pull/1150
                    source_activity.get('object', {}).setdefault(
                        'updated', util.now().isoformat())

            if self.source_obj.get('verb') == 'follow':
                # prefer AS2 id or url, if available
                # https://github.com/snarfed/bridgy-fed/issues/307
                dest = ((target_obj.get('id') or util.get_first(target_obj, 'url'))
                        if target_obj else util.get_url(self.source_obj, 'object'))
                Follower.get_or_create(dest=dest, src=self.source_domain,
                                       last_follow=json_dumps(source_activity))

            try:
                last = common.signed_post(inbox, data=source_activity, user=self.user)
                activity.status = 'complete'
                last_success = last
            except BaseException as e:
                error = e
                activity.status = 'error'

            activity.put()

        # Pass the AP response status code and body through as our response
        if last_success:
            return last_success.text or 'Sent!', last_success.status_code
        elif isinstance(error, BadGateway):
            raise error
        elif isinstance(error, requests.HTTPError):
            return str(error), error.status_code
        else:
            return str(error)

    def _activitypub_targets(self):
        """
        Returns: list of (Activity, string inbox URL)
        """
        # if there's in-reply-to, like-of, or repost-of, they're the targets.
        # otherwise, it's all followers' inboxes.
        targets = util.get_urls(self.source_obj, 'inReplyTo')
        if targets:
            logger.info(f'targets from inReplyTo: {targets}')
        elif self.source_obj.get('verb') in as1.VERBS_WITH_OBJECT:
            targets = util.get_urls(self.source_obj, 'object')
            logger.info(f'targets from object: {targets}')

        if not targets:
            # interpret this as a Create or Update, deliver it to followers. use
            # task queue since we send to each inbox in serial, which can take a
            # long time with many followers/instances.
            if not self.IS_TASK:
                queue_path= tasks_client.queue_path(APP_ID, TASKS_LOCATION, 'webmention')
                tasks_client.create_task(
                    parent=queue_path,
                    task={
                        'app_engine_http_request': {
                            'http_method': 'POST',
                            'relative_uri': '/_ah/queue/webmention',
                            'body': urlencode({'source': self.source_url}).encode(),
                            # https://googleapis.dev/python/cloudtasks/latest/gapic/v2/types.html#google.cloud.tasks_v2.types.AppEngineHttpRequest.headers
                            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                        },
                    },
                )
                # not actually an error
                error('Delivering to followers in the background', status=202)

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
                    actor = util.get_first(actor, 'url') or actor.get('id')
                if not inbox_url and not actor:
                    error('Target object has no actor or attributedTo with URL or id.')
                elif not isinstance(actor, str):
                    error(f'Target actor or attributedTo has unexpected url or id object: {actor}')

            if not inbox_url:
                # fetch actor as AS object
                actor = common.get_as2(actor).json()
                inbox_url = actor.get('inbox')

            if not inbox_url:
                # TODO: probably need a way to surface errors like this
                logging.error('Target actor has no inbox')
                continue

            inbox_url = urllib.parse.urljoin(target_url, inbox_url)
            activities_and_inbox_urls.append((activity, inbox_url))

        logger.info(f"Delivering to targets' inboxes: {[i for _, i in activities_and_inbox_urls]}")
        return activities_and_inbox_urls


class WebmentionTask(Webmention):
    IS_TASK = True


app.add_url_rule('/webmention', view_func=Webmention.as_view('webmention'),
                 methods=['POST'])
app.add_url_rule('/_ah/queue/webmention',
                 view_func=WebmentionTask.as_view('webmention-task'),
                 methods=['POST'])
