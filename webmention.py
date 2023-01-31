"""Handles inbound webmentions.

TODO tests:
* actor/attributedTo could be string URL
"""
import logging
import urllib.parse
from urllib.parse import urlencode

import feedparser
from flask import redirect, request
from flask.views import View
from google.cloud.ndb import Key
from granary import as1, as2, atom, microformats2
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.flask_util import error, flash
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadGateway, HTTPException

import activitypub
from app import app
import common
from models import Follower, Object, User

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
    source_as1 = None     # AS1 dict
    source_as2 = None     # AS2 dict
    target_resp = None    # requests.Response
    user = None           # User

    def dispatch_request(self):
        logger.info(f'Params: {list(request.form.items())}')

        source = flask_util.get_required_param('source').strip()
        self.source_domain = util.domain_from_link(source, minimize=False)
        logger.info(f'webmention from {self.source_domain}')

        # if source is home page, send an actor Update to followers' instances
        if source.strip('/') == f'https://{self.source_domain}':
            self.source_url = source
            self.source_mf2, actor_as1, actor_as2, self.user = \
                common.actor(self.source_domain)
            id = common.host_url(f'{source}#update-{util.now().isoformat()}')
            self.source_as1 = {
                'objectType': 'activity',
                'verb': 'update',
                'id': id,
                'object': actor_as1,
            }
            self.source_as2 = common.postprocess_as2({
                '@context': 'https://www.w3.org/ns/activitystreams',
                'type': 'Update',
                'id': common.host_url(f'{source}#update-{util.now().isoformat()}'),
                'object': actor_as2,
            }, user=self.user)
            return self.try_activitypub() or 'No ActivityPub targets'

        # fetch source page
        try:
            source_resp = util.requests_get(source, gateway=True)
        except ValueError as e:
            error(f'Bad source URL: {source}: {e}')
        self.source_url = source_resp.url or source
        self.source_domain = urllib.parse.urlparse(self.source_url).netloc.split(':')[0]
        fragment = urllib.parse.urlparse(self.source_url).fragment
        self.source_mf2 = util.parse_mf2(source_resp, id=fragment)

        if fragment and self.source_mf2 is None:
            error(f'#{fragment} not found in {self.source_url}')

        # logger.debug(f'Parsed mf2 for {source_resp.url} : {json_dumps(self.source_mf2 indent=2)}')

        # check for backlink for webmention spec and to confirm source's intent
        # to federate
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

        self.source_as1 = microformats2.json_to_object(entry, fetch_mf2=True)
        type_label = ' '.join((
            self.source_as1.get('verb', ''),
            self.source_as1.get('objectType', ''),
            util.get_first(self.source_as1, 'object', {}).get('objectType', ''),
        ))
        logger.info(f'Converted webmention to AS1: {type_label}: {json_dumps(self.source_as1, indent=2)}')

        self.user = User.get_or_create(self.source_domain)
        ret = self.try_activitypub()
        return ret or 'No ActivityPub targets'

    def try_activitypub(self):
        """Attempts ActivityPub delivery.

        Returns Flask response (string body or tuple) if we succeeded or failed,
        None if ActivityPub was not available.
        """
        inboxes_to_targets = self._activitypub_targets()
        if not inboxes_to_targets:
            return None

        error = None
        last_success = None
        log_data = True

        type = as1.object_type(self.source_as1)
        obj = Object.get_by_id(self.source_url)
        changed = False

        if obj:
            logging.info(f'Resuming existing {obj}')
            obj.ap_failed = []
            seen = obj.ap_delivered + obj.ap_undelivered + obj.ap_failed
            new_inboxes = [i for i in inboxes_to_targets.keys() if i not in seen]
            if new_inboxes:
                logging.info(f'Adding new inboxes: {new_inboxes}')
                obj.ap_undelivered += new_inboxes
            if type in ('note', 'article', 'comment'):
                changed = as1.activity_changed(json_loads(obj.as1), self.source_as1)
                if changed:
                    obj.ap_undelivered += obj.ap_delivered
                    obj.ap_delivered = []
                    logger.info(f'Content has changed from last time at {obj.updated}! Redelivering to all inboxes: {obj.ap_undelivered}')

        else:
            obj = Object(id=self.source_url,
                         ap_undelivered=list(inboxes_to_targets.keys()),
                         ap_delivered=[],
                         ap_failed=[])
            logging.info(f'Storing new {obj}')

        obj.domains = [self.source_domain]
        obj.source_protocol = 'activitypub'
        obj.mf2 = json_dumps(self.source_mf2)
        obj.as1 = json_dumps(self.source_as1)
        obj.type = type
        obj.object_ids = as1.get_ids(self.source_as1, 'object')
        obj.put()

        # TODO: collect by inbox, add 'to' fields, de-dupe inboxes and recipients
        #
        # make copy of ap_undelivered because we modify it below
        logger.info(f'Delivering to inboxes: {sorted(obj.ap_undelivered)}')
        for inbox in list(obj.ap_undelivered):
            if inbox in inboxes_to_targets:
                target_as2 = inboxes_to_targets[inbox]
            else:
                logging.warning(f'Missing target_as2 for inbox {inbox}!')
                target_as2 = None

            if not self.source_as2:
                self.source_as2 = common.postprocess_as2(
                    as2.from_as1(self.source_as1), target=target_as2, user=self.user)
            if not self.source_as2.get('actor'):
                self.source_as2['actor'] = common.host_url(self.source_domain)
            if changed:
                self.source_as2['type'] = 'Update'

            if self.source_as2.get('type') == 'Update':
                # Mastodon requires the updated field for Updates, so
                # generate it if it's not already there.
                # https://docs.joinmastodon.org/spec/activitypub/#supported-activities-for-statuses
                # https://socialhub.activitypub.rocks/t/what-could-be-the-reason-that-my-update-activity-does-not-work/2893/4
                # https://github.com/mastodon/documentation/pull/1150
                self.source_as2.get('object', {}).setdefault(
                    'updated', util.now().isoformat())

            if self.source_as2.get('type') == 'Follow':
                # prefer AS2 id or url, if available
                # https://github.com/snarfed/bridgy-fed/issues/307
                dest = ((target_as2.get('id') or util.get_first(target_as2, 'url'))
                        if target_as2 else util.get_url(self.source_as1, 'object'))
                Follower.get_or_create(dest=dest, src=self.source_domain,
                                       last_follow=json_dumps(self.source_as2))

            try:
                last = common.signed_post(inbox, data=self.source_as2,
                                          log_data=log_data, user=self.user)
                obj.ap_delivered.append(inbox)
                last_success = last
            except BaseException as e:
                obj.ap_failed.append(inbox)
                error = e
            finally:
                log_data = False

            obj.ap_undelivered.remove(inbox)
            obj.put()

        obj.status = 'complete' if obj.ap_delivered else 'failed'
        obj.put()

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
        Returns: dict of {str inbox URL: dict target AS2 object}
        """
        # if there's in-reply-to, like-of, or repost-of, they're the targets.
        # otherwise, it's all followers' inboxes.
        targets = util.get_urls(self.source_as1, 'inReplyTo')
        if targets:
            logger.info(f'targets from inReplyTo: {targets}')
        elif self.source_as1.get('verb') in as1.VERBS_WITH_OBJECT:
            targets = util.get_urls(self.source_as1, 'object')
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
                msg = ("Updating profile on followers' instances..."
                       if self.source_url.strip('/') == f'https://{self.source_domain}'
                       else 'Delivering to followers...')
                error(msg, status=202)

            inboxes = set()
            for follower in Follower.query().filter(
                Follower.key > Key('Follower', self.source_domain + ' '),
                Follower.key < Key('Follower', self.source_domain + chr(ord(' ') + 1))):
                if follower.status != 'inactive' and follower.last_follow:
                    actor = json_loads(follower.last_follow).get('actor')
                    if actor and isinstance(actor, dict):
                        inboxes.add(actor.get('endpoints', {}).get('sharedInbox') or
                                    actor.get('publicInbox') or
                                    actor.get('inbox'))
            logger.info('Delivering to followers')
            return {inbox: None for inbox in inboxes}

        targets = common.remove_blocklisted(targets)
        if not targets:
            error(f"Silo responses are not yet supported.")

        inboxes_to_targets = {}
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

            # find target's inbox
            target_obj = self.target_resp.json()
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
            inboxes_to_targets[inbox_url] = target_obj

        logger.info(f"Delivering to targets' inboxes: {inboxes_to_targets.keys()}")
        return inboxes_to_targets


class WebmentionTask(Webmention):
    """Handler that runs tasks, not external HTTP requests."""
    IS_TASK = True


class WebmentionInteractive(Webmention):
    """Handler that runs interactive webmention-based requests from the web UI.

    ...eg the update profile button on user pages.
    """
    def dispatch_request(self):
        try:
            super().dispatch_request()
            flash('OK')
        except HTTPException as e:
            flash(util.linkify(str(e.description), pretty=True))
            return redirect(f'/user/{self.source_domain}', code=302)


app.add_url_rule('/webmention', view_func=Webmention.as_view('webmention'),
                 methods=['POST'])
app.add_url_rule('/webmention-interactive',
                 view_func=WebmentionInteractive.as_view('webmention-interactive'),
                 methods=['POST'])
app.add_url_rule('/_ah/queue/webmention',
                 view_func=WebmentionTask.as_view('webmention-task'),
                 methods=['POST'])
