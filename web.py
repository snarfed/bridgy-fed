"""Handles inbound webmentions."""
import datetime
import difflib
import logging
from urllib.parse import urlencode, urljoin, urlparse

import feedparser
from flask import g, redirect, render_template, request
from flask.views import View
from google.cloud.ndb import Key
from granary import as1, as2, microformats2
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil.appengine_info import APP_ID
from oauth_dropins.webutil.flask_util import error, flash
from oauth_dropins.webutil.util import json_dumps, json_loads
from oauth_dropins.webutil import webmention
from requests import HTTPError, RequestException, URLRequired
from werkzeug.exceptions import BadGateway, BadRequest, HTTPException, NotFound

import activitypub
import common
from flask_app import app, cache
from models import Follower, Object, PROTOCOLS, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)

# https://cloud.google.com/appengine/docs/locations
TASKS_LOCATION = 'us-central1'

CHAR_AFTER_SPACE = chr(ord(' ') + 1)

# https://github.com/snarfed/bridgy-fed/issues/314
WWW_DOMAINS = frozenset((
    'www.jvt.me',
))


class Web(User, Protocol):
    """Web user and webmention protocol implementation.

    The key name is the domain.
    """
    LABEL = 'web'

    @classmethod
    def _get_kind(cls):
        return 'MagicKey'

    def label_id(self):
        # prettify if domain, noop if username
        return util.domain_from_link(self.username(), minimize=False)

    def web_url(self):
        """Returns this user's web URL aka web_url, eg 'https://foo.com/'."""
        return f'https://{self.key.id()}/'

    def ap_address(self):
        """Returns this user's ActivityPub address, eg '@foo.com@foo.com'.

        Uses the user's domain if they're direct, fed.brid.gy if they're not.
        """
        if self.direct:
            return f'@{self.username()}@{self.key.id()}'
        else:
            return f'@{self.key.id()}@{request.host}'

    def ap_actor(self, rest=None):
        """Returns this user's ActivityPub/AS2 actor id.

        Eg 'https://fed.brid.gy/foo.com'

        Web users are special cased to not have an /ap/web/ prefix, for backward
        compatibility.
        """
        if self.direct or rest:
            url = common.host_url(self.key.id())
            if rest:
                url += f'/{rest}'
            return url

        # TODO(#512): drop once we fetch site if web user doesn't already exist
        return common.redirect_wrap(self.web_url())

    def verify(self):
        """Fetches site a couple ways to check for redirects and h-card.


        Returns: :class:`Web` that was verified. May be different than
          self! eg if self's domain started with www and we switch to the root
          domain.
        """
        domain = self.key.id()
        logger.info(f'Verifying {domain}')

        if domain.startswith('www.') and domain not in WWW_DOMAINS:
            # if root domain redirects to www, use root domain instead
            # https://github.com/snarfed/bridgy-fed/issues/314
            root = domain.removeprefix("www.")
            root_site = f'https://{root}/'
            try:
                resp = util.requests_get(root_site, gateway=False)
                if resp.ok and self.is_web_url(resp.url):
                    logger.info(f'{root_site} redirects to {resp.url} ; using {root} instead')
                    root_user = Web.get_or_create(root)
                    self.use_instead = root_user.key
                    self.put()
                    return root_user.verify()
            except RequestException:
                pass

        # check webfinger redirect
        path = f'/.well-known/webfinger?resource=acct:{domain}@{domain}'
        self.has_redirects = False
        self.redirects_error = None
        try:
            url = urljoin(self.web_url(), path)
            resp = util.requests_get(url, gateway=False)
            domain_urls = ([f'https://{domain}/' for domain in common.DOMAINS] +
                           [common.host_url()])
            expected = [urljoin(url, path) for url in domain_urls]
            if resp.ok:
                if resp.url in expected:
                    self.has_redirects = True
                elif resp.url:
                    diff = '\n'.join(difflib.Differ().compare([resp.url], [expected[0]]))
                    self.redirects_error = f'Current vs expected:<pre>{diff}</pre>'
            else:
                lines = [url, f'  returned HTTP {resp.status_code}']
                if resp.url != url:
                    lines[1:1] = ['  redirected to:', resp.url]
                self.redirects_error = '<pre>' + '\n'.join(lines) + '</pre>'
        except RequestException:
            pass

        # check home page
        try:
            obj = Web.load(self.web_url(), gateway=True)
            self.actor_as2 = activitypub.postprocess_as2(as2.from_as1(obj.as1))
            self.has_hcard = True
        except (BadRequest, NotFound):
            self.actor_as2 = None
            self.has_hcard = False

        return self

    @classmethod
    def send(cls, obj, url):
        """Sends a webmention to a given target URL.

        See :meth:`Protocol.send` for details.
        """
        source_url = obj.proxy_url()
        logger.info(f'Sending webmention from {source_url} to {url}')

        endpoint = common.webmention_discover(url).endpoint
        if endpoint:
            webmention.send(endpoint, source_url, url)
            return True

    @classmethod
    def fetch(cls, obj, gateway=False, check_backlink=None):
        """Fetches a URL over HTTP and extracts its microformats2.

        Follows redirects, but doesn't change the original URL in obj's id! The
        :class:`Model` class doesn't allow that anyway, but more importantly, we
        want to preserve that original URL becase other objects may refer to it
        instead of the final redirect destination URL.

        See :meth:`Protocol.fetch` for other background.

        Args:
          gateway: passed through to :func:`webutil.util.fetch_mf2`
          check_backlink: bool, optional, whether to require a link to Bridgy Fed
        """
        url = obj.key.id()
        is_web_url = ((g.user and g.user.is_web_url(url)) or
                       (g.external_user and g.external_user == url))


        require_backlink = None
        if check_backlink or (check_backlink is None and not is_web_url):
            require_backlink = common.host_url().rstrip('/')

        try:
            parsed = util.fetch_mf2(url, gateway=gateway,
                                    require_backlink=require_backlink)
        except (ValueError, URLRequired) as e:
            error(str(e))

        if parsed is None:
            error(f'id {urlparse(url).fragment} not found in {url}')

        # find mf2 item
        if is_web_url:
            logger.info(f"{url} is user's web url")
            entry = mf2util.representative_hcard(parsed, parsed['url'])
            logger.info(f'Representative h-card: {json_dumps(entry, indent=2)}')
            if not entry:
                error(f"Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on {parsed['url']}")
        else:
            entry = mf2util.find_first_entry(parsed, ['h-entry'])
            if not entry:
                error(f'No microformats2 found in {url}')

        # store final URL in mf2 object, and also default url property to it,
        # since that's the fallback for AS1/AS2 id
        entry['url'] = parsed['url']
        if is_web_url:
            entry.setdefault('rel-urls', {}).update(parsed.get('rel-urls', {}))
        props = entry.setdefault('properties', {})
        props.setdefault('url', [parsed['url']])
        logger.info(f'Extracted microformats2 entry: {json_dumps(entry, indent=2)}')

        # run full authorship algorithm if necessary: https://indieweb.org/authorship
        # duplicated in microformats2.json_to_object
        author = util.get_first(props, 'author')
        if not isinstance(author, dict) and not is_web_url:
            logger.info(f'Fetching full authorship for author {author}')
            author = mf2util.find_author({'items': [entry]}, hentry=entry,
                                         fetch_mf2_func=util.fetch_mf2)
            logger.info(f'Got: {author}')
            if author:
                props['author'] = util.trim_nulls([{
                    "type": ["h-card"],
                    'properties': {
                        field: [author[field]] if author.get(field) else []
                        for field in ('name', 'photo', 'url')
                    },
                }])

        obj.mf2 = entry
        return obj

    @classmethod
    def serve(cls, obj):
        """Serves an :class:`Object` as HTML."""
        obj_as1 = obj.as1

        from_proto = PROTOCOLS.get(obj.source_protocol)
        if from_proto:
            # fill in author/actor if available
            for field in 'author', 'actor':
                val = as1.get_object(obj.as1, field)
                if val.keys() == set(['id']) and val['id']:
                    loaded = from_proto.load(val['id'])
                    if loaded and loaded.as1:
                        obj_as1 = {**obj_as1, field: loaded.as1}
        else:
            logger.debug(f'Not hydrating actor or author due to source_protocol {obj.source_protocol}')

        html = microformats2.activities_to_html([obj_as1])

        # add HTML meta redirect to source page. should trigger for end users in
        # browsers but not for webmention receivers (hopefully).
        url = util.get_url(obj_as1)
        if url:
            utf8 = '<meta charset="utf-8">'
            refresh = f'<meta http-equiv="refresh" content="0;url={url}">'
            html = html.replace(utf8, utf8 + '\n' + refresh)

        return html, {'Content-Type': common.CONTENT_TYPE_HTML}

# 'webmention' is an old LABEL alias for 'web'
PROTOCOLS['webmention'] = Web


@app.get('/web-site')
@flask_util.cached(cache, datetime.timedelta(days=1))
def enter_web_site():
    return render_template('enter_web_site.html')


@app.post('/web-site')
def check_web_site():
    url = request.values['url']
    domain = util.domain_from_link(url, minimize=False)
    if not domain:
        flash(f'No domain found in {url}')
        return render_template('enter_web_site.html')

    g.user = Web.get_or_create(domain, direct=True)
    try:
        g.user = g.user.verify()
    except BaseException as e:
        code, body = util.interpret_http_exception(e)
        if code:
            flash(f"Couldn't connect to {url}: {e}")
            return render_template('enter_web_site.html')
        raise

    g.user.put()
    return redirect(g.user.user_page_path())


@app.post('/webmention')
def webmention_external():
    """Handles inbound webmention, enqueue task to process.

    Use a task queue to deliver to followers because we send to each inbox in
    serial, which can take a long time with many followers/instances.
    """
    source = flask_util.get_required_param('source').strip()
    if not util.is_web(source):
        error(f'Bad URL {source}')

    domain = util.domain_from_link(source, minimize=False)
    g.user = Web.get_by_id(domain)
    if not g.user:
        error(f'No user found for domain {domain}')

    queue_path = tasks_client.queue_path(APP_ID, TASKS_LOCATION, 'webmention')
    task = tasks_client.create_task(
        parent=queue_path,
        task={
            'app_engine_http_request': {
                'http_method': 'POST',
                'relative_uri': '/_ah/queue/webmention',
                'body': urlencode(request.form).encode(),
                # https://googleapis.dev/python/cloudtasks/latest/gapic/v2/types.html#google.cloud.tasks_v2.types.AppEngineHttpRequest.headers
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            },
        },
    )
    msg = f'Enqueued task {task.name}.'
    logger.info(msg)
    return msg, 202


@app.post('/webmention-interactive')
def webmention_interactive():
    """Handler that runs interactive webmention-based requests from the web UI.

    ...eg the update profile button on user pages.
    """
    try:
        webmention_external()
        flash(f'Updating fediverse profile from <a href="{g.user.web_url()}">{g.user.key.id()}</a>...')
    except HTTPException as e:
        flash(util.linkify(str(e.description), pretty=True))

    path = f'/user/{g.user.key.id()}' if g.user else '/'
    return redirect(path, code=302)


@app.post('/_ah/queue/webmention')
def webmention_task():
    """Handles webmention task, converts to ActivityPub and delivers."""
    logger.info(f'Params: {list(request.form.items())}')

    # load user
    source = flask_util.get_required_param('source').strip()
    domain = util.domain_from_link(source, minimize=False)
    logger.info(f'webmention from {domain}')

    g.user = Web.get_by_id(domain)
    if not g.user:
        error(f'No user found for domain {domain}', status=304)

    # fetch source page
    try:
        obj = Web.load(source, refresh=True)
    except BadRequest as e:
        error(str(e.description), status=304)
    except HTTPError as e:
        if e.response.status_code not in (410, 404):
            error(f'{e} ; {e.response.text if e.response else ""}', status=502)

        create_id = f'{source}#bridgy-fed-create'
        logger.info(f'Interpreting as Delete. Looking for {create_id}')
        create = Object.get_by_id(create_id)
        if not create or create.status != 'complete':
            error(f"Bridgy Fed hasn't successfully published {source}", status=304)

        id = f'{source}#bridgy-fed-delete'
        obj = Object(id=id, our_as1={
            'id': id,
            'objectType': 'activity',
            'verb': 'delete',
            'actor': g.user.ap_actor(),
            'object': source,
        })

    if obj.mf2:
        # set actor to user
        props = obj.mf2['properties']
        author_urls = microformats2.get_string_urls(props.get('author', []))
        if author_urls and not g.user.is_web_url(author_urls[0]):
            logger.info(f'Overriding author {author_urls[0]} with {g.user.ap_actor()}')
            props['author'] = [g.user.ap_actor()]

    logger.info(f'Converted to AS1: {obj.type}: {json_dumps(obj.as1, indent=2)}')

    # if source is home page, send an actor Update to followers' instances
    if g.user.is_web_url(obj.key.id()):
        obj.put()
        actor_as1 = {
            **obj.as1,
            'id': g.user.ap_actor(),
            'updated': util.now().isoformat(),
        }
        id = common.host_url(f'{obj.key.id()}#update-{util.now().isoformat()}')
        obj = Object(id=id, our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': g.user.ap_actor(),
            'object': actor_as1,
        })

    inboxes_to_targets = _activitypub_targets(obj)

    obj.populate(
        domains=[g.user.key.id()],
        source_protocol='web',
    )
    if not inboxes_to_targets:
        obj.labels.append('user')
        obj.status = 'ignored'
        obj.put()
        return 'No ActivityPub targets'

    err = None
    last_success = None
    log_data = True

    if obj.type in ('note', 'article', 'comment'):
        # have we already seen this object? has it changed? or is it new?
        if obj.changed:
            logger.info(f'Content has changed from last time at {obj.updated}! Redelivering to all inboxes')
            updated = util.now().isoformat()
            id = f'{obj.key.id()}#bridgy-fed-update-{updated}'
            logger.info(f'Wrapping in update activity {id}')
            obj.put()
            update_as1 = {
                'objectType': 'activity',
                'verb': 'update',
                'id': id,
                'actor': g.user.ap_actor(),
                'object': {
                    # Mastodon requires the updated field for Updates, so
                    # add a default value.
                    # https://docs.joinmastodon.org/spec/activitypub/#supported-activities-for-statuses
                    # https://socialhub.activitypub.rocks/t/what-could-be-the-reason-that-my-update-activity-does-not-work/2893/4
                    # https://github.com/mastodon/documentation/pull/1150
                    'updated': updated,
                    **obj.as1,
                },
            }
            obj = Object(id=id, mf2=obj.mf2, our_as1=update_as1, labels=['user'],
                         domains=[g.user.key.id()], source_protocol='web')

        elif obj.new:
            logger.info(f'New Object {obj.key.id()}')
            id = f'{obj.key.id()}#bridgy-fed-create'
            logger.info(f'Wrapping in post activity {id}')
            obj.put()
            create_as1 = {
                'objectType': 'activity',
                'verb': 'post',
                'id': id,
                'actor': g.user.ap_actor(),
                'object': obj.as1,
            }
            obj = Object(id=id, mf2=obj.mf2, our_as1=create_as1,
                         domains=[g.user.key.id()], labels=['user'],
                         source_protocol='web')

        else:
            msg = f'{obj.key.id()} is unchanged, nothing to do'
            logger.info(msg)
            return msg, 204

    # TODO: collect by inbox, add 'to' fields, de-dupe inboxes and recipients
    #
    # make copy of undelivered because we modify it below
    obj.populate(
        status='in progress',
        labels=['user'],
        delivered=[],
        failed=[],
        undelivered=[Target(uri=uri, protocol='activitypub')
                     for uri in inboxes_to_targets.keys()],
    )

    logger.info(f'Delivering to inboxes: {sorted(t.uri for t in obj.undelivered)}')
    for target in list(obj.undelivered):
        inbox = target.uri
        if inbox in inboxes_to_targets:
            target_as2 = inboxes_to_targets[inbox]
        else:
            logger.warning(f'Missing target_as2 for inbox {inbox}!')
            target_as2 = None

        if obj.type == 'follow':
            # prefer AS2 id or url, if available
            # https://github.com/snarfed/bridgy-fed/issues/307
            dest = target_as2 or as1.get_object(obj.as1)
            dest_id = dest.get('id') or dest.get('url')
            if not dest_id:
                error('follow missing target ')
            Follower.get_or_create(dest=dest_id,
                                   src=g.user.key.id(),
                                   last_follow=as2.from_as1({
                                       **obj.as1,
                                       'object': dest_id,
                                   }))

        # this is reused later in ActivityPub.send()
        # TODO: find a better way
        obj.target_as2 = target_as2

        try:
            last = activitypub.ActivityPub.send(obj, inbox, log_data=log_data)
            obj.delivered.append(target)
            last_success = last
        except BaseException as e:
            code, body = util.interpret_http_exception(e)
            if not code and not body:
                raise
            obj.failed.append(target)
            err = e
        finally:
            log_data = False

        obj.undelivered.remove(target)
        obj.put()

    obj.status = ('complete' if obj.delivered
                  else 'failed' if obj.failed
                  else 'ignored')
    obj.put()

    # Pass the AP response status code and body through as our response
    if last_success:
        return last_success.text or 'Sent!', last_success.status_code
    elif isinstance(err, BadGateway):
        raise err
    elif isinstance(err, HTTPError):
        return str(err), err.status_code
    else:
        return str(err)


def _activitypub_targets(obj):
    """
    Args:
      obj: :class:`models.Object`

    Returns: dict of {str inbox URL: dict target AS2 object}
    """
    # if there's in-reply-to, like-of, or repost-of, they're the targets.
    # otherwise, it's all followers' inboxes.
    targets = util.get_urls(obj.as1, 'inReplyTo')
    verb = obj.as1.get('verb')
    if targets:
        logger.info(f'targets from inReplyTo: {targets}')
    elif verb in as1.VERBS_WITH_OBJECT:
        targets = util.get_urls(obj.as1, 'object')
        logger.info(f'targets from object: {targets}')

    targets = common.remove_blocklisted(targets)

    inboxes_to_targets = {}
    target_obj = None
    for target in targets:
        # fetch target page as AS2 object
        try:
            # TODO: make this generic across protocols
            target_stored = activitypub.ActivityPub.load(target)
            target_obj = target_stored.as2 or as2.from_as1(target_stored.as1)
        except (HTTPError, BadGateway) as e:
            resp = getattr(e, 'requests_response', None)
            if resp and resp.ok:
                type = common.content_type(resp)
                if type and type.startswith('text/html'):
                    continue  # give up
            raise

        inbox_url = target_obj.get('inbox')
        if not inbox_url:
            # TODO: test actor/attributedTo and not, with/without inbox
            actor = (util.get_first(target_obj, 'actor') or
                     util.get_first(target_obj, 'attributedTo'))
            if isinstance(actor, dict):
                inbox_url = actor.get('inbox')
                actor = util.get_first(actor, 'url') or actor.get('id')
            if not inbox_url and not actor:
                error('Target object has no actor or attributedTo with URL or id.', status=304)
            elif not isinstance(actor, str):
                error(f'Target actor or attributedTo has unexpected url or id object: {actor}', status=304)

        if not inbox_url:
            # fetch actor as AS object
            # TODO: make this generic across protocols
            actor_obj = activitypub.ActivityPub.load(actor)
            actor = actor_obj.as2 or as2.from_as1(actor_obj.as1)
            inbox_url = actor.get('inbox')

        if not inbox_url:
            # TODO: probably need a way to surface errors like this
            logger.error('Target actor has no inbox')
            continue

        inbox_url = urljoin(target, inbox_url)
        inboxes_to_targets[inbox_url] = target_obj

    if not targets or verb == 'share':
        logger.info('Delivering to followers')
        domain = g.user.key.id()
        for follower in Follower.query().filter(
            Follower.key > Key('Follower', domain + ' '),
            Follower.key < Key('Follower', domain + CHAR_AFTER_SPACE)):
            if follower.status != 'inactive' and follower.last_follow:
                actor = follower.last_follow.get('actor')
                if actor and isinstance(actor, dict):
                    inbox = (actor.get('endpoints', {}).get('sharedInbox') or
                             actor.get('publicInbox') or
                             actor.get('inbox'))
                    # HACK: use last target object from above for reposts, which
                    # has its resolved id
                    inboxes_to_targets[inbox] = (target_obj if verb == 'share' else None)

    return inboxes_to_targets
