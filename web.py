"""Webmention protocol with microformats2 in HTML, aka the IndieWeb stack."""
from datetime import timedelta, timezone
import difflib
import logging
import re
import statistics
import urllib.parse
from urllib.parse import quote, urlencode, urljoin, urlparse

from flask import g, redirect, render_template, request
from google.cloud import ndb
from google.cloud.ndb import ComputedProperty
from granary import as1, as2, atom, microformats2, rss
import mf2util
from oauth_dropins.webutil import flask_util, util
from oauth_dropins.webutil.appengine_config import tasks_client
from oauth_dropins.webutil import appengine_info
from oauth_dropins.webutil.flask_util import cloud_tasks_only, error, flash
from oauth_dropins.webutil.util import json_dumps, json_loads
from oauth_dropins.webutil import webmention
from requests import HTTPError, RequestException
from requests.auth import HTTPBasicAuth
from werkzeug.exceptions import BadGateway, BadRequest, HTTPException, NotFound

import common
from common import add, DOMAIN_RE, SUPERDOMAIN
from flask_app import app, cache
from ids import translate_handle, translate_object_id, translate_user_id
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
NON_TLDS = frozenset((
    'gz',
    'html',
    'ini',
    'jpg',
    'json',
    'php',
    'png',
    'sql',
    'tgz',
    'txt',
    'xml',
    'yaml',
    'yml',
))

FEED_TYPES = {
    atom.CONTENT_TYPE.split(';')[0]: 'atom',
    rss.CONTENT_TYPE.split(';')[0]: 'rss',
}
MIN_FEED_POLL_PERIOD = timedelta(hours=2)
MAX_FEED_POLL_PERIOD = timedelta(weeks=1)


def is_valid_domain(domain):
    """Returns True if this is a valid domain we can use, False otherwise.

    Valid means TLD is ok, not blacklisted, etc.
    """
    if not re.match(DOMAIN_RE, domain):
        logger.debug(f"{domain} doesn't look like a domain")
        return False

    if Web.is_blocklisted(domain):
        logger.debug(f'{domain} is blocklisted')
        return False

    tld = domain.split('.')[-1]
    if tld in NON_TLDS:
        logger.info(f"{domain} looks like a domain but {tld} isn't a TLD")
        return False

    return True


class Web(User, Protocol):
    """Web user and webmention protocol implementation.

    The key name is the domain.
    """
    ABBREV = 'web'
    OTHER_LABELS = ('webmention',)
    LOGO_HTML = '🌐'  # used to be 🕸️
    CONTENT_TYPE = common.CONTENT_TYPE_HTML

    has_redirects = ndb.BooleanProperty()
    redirects_error = ndb.TextProperty()
    has_hcard = ndb.BooleanProperty()
    last_webmention_in = ndb.DateTimeProperty(tzinfo=timezone.utc)
    superfeedr_subscribed = ndb.DateTimeProperty(tzinfo=timezone.utc)
    superfeedr_subscribed_feed = ndb.StringProperty()

    # Originally, BF served Web users' AP actor ids on fed.brid.gy, eg
    # https://fed.brid.gy/snarfed.org . When we started adding new protocols, we
    # switched to per-protocol subdomains, eg https://web.brid.gy/snarfed.org .
    # However, we need to preserve the old users' actor ids as is. So, this
    # property tracks which subdomain a given Web user's AP actor uses.
    ap_subdomain = ndb.StringProperty(choices=['fed', 'web'], default='web')

    @classmethod
    def _get_kind(cls):
        return 'MagicKey'

    def _pre_put_hook(self):
        """Validate domain id, don't allow upper case or invalid characters."""
        super()._pre_put_hook()
        id = self.key.id()
        assert is_valid_domain(id), id
        assert id.lower() == id, f'upper case is not allowed in Web key id: {id}'

    @classmethod
    def get_or_create(cls, id, **kwargs):
        """Normalize domain, pass through, then subscribe in Superfeedr.

        Normalizing currently consists of lower casing and removing leading and
        trailing dots.
        """
        key = cls.key_for(id)
        if not key:
            return None  # opted out

        domain = key.id().lower().strip('.')
        user = super().get_or_create(domain, **kwargs)

        # TODO
        # maybe_superfeedr_subscribe(user)

        return user

    @ndb.ComputedProperty
    def handle(self):
        """Returns this user's chosen username or domain, eg ``user.com``."""
        # prettify if domain, noop if username
        username = self.username()
        if username != self.key.id():
            return util.domain_from_link(username, minimize=False)
        return username

    def handle_as(self, to_proto):
        """Special case ActivityPub to use custom username."""
        if to_proto in ('activitypub', 'ap', PROTOCOLS['ap']):
            return (f'@{self.username()}@{self.key.id()}' if self.has_redirects
                    else f'@{self.key.id()}@{self.ap_subdomain}{SUPERDOMAIN}')

        return super().handle_as(to_proto)

    def id_as(self, to_proto):
        """Special case ActivityPub to use ``ap_subdomain``."""
        if isinstance(to_proto, str):
            to_proto = PROTOCOLS[to_proto]

        converted = translate_user_id(id=self.key.id(), from_proto=self,
                                      to_proto=to_proto)

        if to_proto.LABEL == 'activitypub':
            other = 'web' if self.ap_subdomain == 'fed' else 'fed'
            converted = converted.replace(f'https://{other}.brid.gy/',
                                          f'https://{self.ap_subdomain}.brid.gy/')

        return converted

    def web_url(self):
        """Returns this user's web URL aka web_url, eg ``https://foo.com/``."""
        return f'https://{self.key.id()}/'

    profile_id = web_url

    def is_web_url(self, url):
        return super().is_web_url(url, ignore_www=True)

    def user_page_path(self, rest=None):
        """Always use domain."""
        path = f'/{self.ABBREV}/{self.key.id()}'

        if rest:
            if not rest.startswith('?'):
                path += '/'
            path += rest.lstrip('/')

        return path

    def username(self):
        """Returns the user's preferred username.

        Uses stored representative h-card if available, falls back to id.

        Returns:
          str:
        """
        id = self.key.id()

        if self.obj and self.obj.as1 and self.direct:
            for url in (util.get_list(self.obj.as1, 'url') +
                        util.get_list(self.obj.as1, 'urls')):
                url = url.get('value') if isinstance(url, dict) else url
                if url and url.startswith('acct:'):
                    try:
                        urluser, urldomain = util.parse_acct_uri(url)
                    except ValueError as e:
                        continue
                    if urldomain == id:
                        logger.info(f'Found custom username: {urluser}')
                        return urluser

        logger.info(f'Defaulting username to key id {id}')
        return id

    def verify(self):
        """Fetches site a couple ways to check for redirects and h-card.

        Returns:
          web.Web: user that was verified. May be different than self! eg if
          self 's domain started with www and we switch to the root domain.
        """
        domain = self.key.id()
        logger.info(f'Verifying {domain}')

        if domain.startswith('www.') and domain not in WWW_DOMAINS:
            # if root domain serves ok, use it instead
            # https://github.com/snarfed/bridgy-fed/issues/314
            root = domain.removeprefix("www.")
            root_site = f'https://{root}/'
            try:
                resp = util.requests_get(root_site, gateway=False)
                if resp.ok and self.is_web_url(resp.url):
                    logger.info(f'{root_site} serves ok ; using {root} instead')
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
            if resp.ok and resp.url:
                got = urllib.parse.unquote(resp.url)
                if got in expected:
                    self.has_redirects = True
                elif got:
                    diff = '\n'.join(difflib.Differ().compare([got], [expected[0]]))
                    self.redirects_error = f'Current vs expected:<pre>{diff}</pre>'
            else:
                lines = [url, f'  returned HTTP {resp.status_code}']
                if resp.url and resp.url != url:
                    lines[1:1] = ['  redirected to:', resp.url]
                self.redirects_error = '<pre>' + '\n'.join(lines) + '</pre>'
        except RequestException:
            pass

        # check home page
        self.obj = None
        self.has_hcard = False
        try:
            self.obj = Web.load(self.web_url(), remote=True, gateway=True)
            if self.obj:
                self.has_hcard = True
        except (BadRequest, NotFound):
            pass

        self.put()
        return self

    @classmethod
    def key_for(cls, id):
        """Returns the :class:`ndb.Key` for a given id.

        If id is a domain, uses it as is. If it's a home page URL or fed.brid.gy
        or web.brid.gy AP actor URL, extracts the domain and uses that.
        Otherwise, returns None.

        Args:
          id (str)

        Returns:
        ndb.Key or None:
        """
        if not id:
            return None

        if util.is_web(id):
            parsed = urlparse(id)
            if parsed.path in ('', '/'):
                id = parsed.netloc

        if is_valid_domain(id):
            return super().key_for(id)

        logger.info(f'{id} is not a domain or usable home page URL')
        return None

    @classmethod
    def owns_id(cls, id):
        """Returns None if id is a domain or http(s) URL, False otherwise.

        All web pages are http(s) URLs, but not all http(s) URLs are web pages.
        """
        if not id:
            return False

        key = cls.key_for(id)
        if key:
            user = key.get()
            return True if user and user.has_redirects else None

        return None if util.is_web(id) else False

    @classmethod
    def owns_handle(cls, handle):
        if not is_valid_domain(handle):
            return False

    @classmethod
    def handle_to_id(cls, handle):
        assert cls.owns_handle(handle) is not False
        return handle

    @classmethod
    def target_for(cls, obj, shared=False):
        """Returns `obj`'s id, as a URL webmention target."""
        # TODO: we have entities in prod that fail this, eg
        # https://indieweb.social/users/bismark has source_protocol webmention
        # assert obj.source_protocol in (cls.LABEL, cls.ABBREV, 'ui', None), str(obj)

        if not util.is_web(obj.key.id()):
            logger.warning(f"{obj.key} is source_protocol web but id isn't a URL!")
            return None

        return obj.key.id()

    @classmethod
    def send(to_cls, obj, url, from_user=None, orig_obj=None, **kwargs):
        """Sends a webmention to a given target URL.

        See :meth:`Protocol.send` for details.

        Returns False if the target URL doesn't advertise a webmention endpoint,
        or if webmention/microformats2 don't support the activity type.
        https://fed.brid.gy/docs#error-handling
        """
        # we only send webmentions for responses. for sending normal posts etc
        # to followers, we just update our stored objects (elsewhere) and web
        # users consume them via feeds.
        verb = obj.as1.get('verb')

        if verb in ('accept', 'undo'):
            logger.info(f'Skipping sending {verb} (not supported in webmention/mf2) to {url}')
            return False
        elif url not in as1.targets(obj.as1):
            # logger.info(f'Skipping sending to {url} , not a target in the object')
            return False
        elif to_cls.is_blocklisted(url):
            logger.info(f'Skipping sending to blocklisted {url}')
            return False

        source_id = translate_object_id(
            id=obj.key.id(), from_proto=PROTOCOLS[obj.source_protocol], to_proto=Web)
        source_url = quote(source_id, safe=':/%+')
        logger.info(f'Sending webmention from {source_url} to {url}')

        endpoint = common.webmention_discover(url).endpoint
        if not endpoint:
            return False

        webmention.send(endpoint, source_url, url)
        return True

    @classmethod
    def fetch(cls, obj, gateway=False, check_backlink=False, **kwargs):
        """Fetches a URL over HTTP and extracts its microformats2.

        Follows redirects, but doesn't change the original URL in ``obj``'s id!
        :class:`google.cloud.ndb.model.Model` doesn't allow that anyway, but more
        importantly, we want to preserve that original URL becase other objects
        may refer to it instead of the final redirect destination URL.

        See :meth:`Protocol.fetch` for other background.

        Args:
          gateway (bool): passed through to
            :func:`oauth_dropins.webutil.util.fetch_mf2`
          check_backlink (bool): optional, whether to require a link to Bridgy
            Fed. Ignored if the URL is a homepage, ie has no path.
          kwargs: ignored
        """
        url = obj.key.id()
        if not util.is_web(url):
            logger.info(f'{url} is not a URL')
            return False

        is_homepage = urlparse(url).path.strip('/') == ''

        require_backlink = (common.host_url().rstrip('/')
                            if check_backlink and not is_homepage
                            else None)

        try:
            parsed = util.fetch_mf2(url, gateway=gateway, metaformats_hcard=True,
                                    require_backlink=require_backlink)
        except ValueError as e:
            error(str(e))

        if parsed is None:
            error(f'id {urlparse(url).fragment} not found in {url}')
        elif not parsed.get('items'):
            logger.info(f'No microformats2 found in {url}')
            return False

        # find mf2 item
        if is_homepage:
            logger.info(f"{url} is user's web url")
            entry = mf2util.representative_hcard(parsed, parsed['url'])
            if not entry:
                error(f"Couldn't find a representative h-card (http://microformats.org/wiki/representative-hcard-parsing) on {parsed['url']}")
            logger.info(f'Representative h-card: {json_dumps(entry, indent=2)}')
        else:
            entry = mf2util.find_first_entry(parsed, ['h-entry'])
            if not entry:
                error(f'No microformats2 h-entry found in {url}')

        # discard uid if set; we use URL as id
        props = entry.setdefault('properties', {})
        if 'uid' in props:
            logger.info(f'Discarding uid property: {props["uid"]}')
            props.pop('uid')

        # store final URL in mf2 object, and also default url property to it,
        # since that's the fallback for AS1/AS2 id
        if is_homepage:
            entry.setdefault('rel-urls', {}).update(parsed.get('rel-urls', {}))
            entry.setdefault('type', ['h-card'])
        if parsed['url']:
            entry['url'] = parsed['url']
            props.setdefault('url', [parsed['url']])
        logger.info(f'Extracted microformats2 entry: {json_dumps(entry, indent=2)}')

        if not is_homepage:
            # default actor/author to home page URL
            authors = props.setdefault('author', [])
            if not microformats2.get_string_urls(authors):
                homepage = urljoin(parsed.get('url') or url, '/')
                logger.info(f'Defaulting author URL to {homepage}')
                if authors and isinstance(authors[0], dict):
                    authors[0]['properties']['url'] = [homepage]
                else:
                    authors.insert(0, homepage)

            # run full authorship algorithm if necessary:
            # https://indieweb.org/authorship
            # duplicated in microformats2.json_to_object
            author = util.get_first(props, 'author')
            if not isinstance(author, dict):
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
        return True

    @classmethod
    def convert(cls, obj, from_user=None):
        """Converts a :class:`Object` to HTML.

        Args:
          obj (models.Object)
          from_user (models.User): user (actor) this activity/object is from

        Returns:
          str:
        """
        if not obj or not obj.as1:
            return ''

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

        html = microformats2.activities_to_html([cls.translate_ids(obj_as1)])

        # add HTML meta redirect to source page. should trigger for end users in
        # browsers but not for webmention receivers (hopefully).
        url = util.get_url(obj_as1)
        if url:
            utf8 = '<meta charset="utf-8">'
            refresh = f'<meta http-equiv="refresh" content="0;url={url}">'
            html = html.replace(utf8, utf8 + '\n' + refresh)

        return html


@app.get('/web-site')
@flask_util.cached(cache, timedelta(days=1))
def enter_web_site():
    return render_template('enter_web_site.html')


@app.post('/web-site')
def check_web_site():
    url = request.values['url']
    # this normalizes and lower cases domain
    domain = util.domain_from_link(url, minimize=False)
    if not domain or not is_valid_domain(domain):
        flash(f'{url} is not a valid or supported web site')
        return render_template('enter_web_site.html'), 400

    try:
        user = Web.get_or_create(domain, direct=True)
        user = user.verify()
    except BaseException as e:
        code, body = util.interpret_http_exception(e)
        if code:
            flash(f"Couldn't connect to {url}: {e}")
            return render_template('enter_web_site.html')
        raise

    user.put()
    return redirect(user.user_page_path())


@app.post('/webmention')
def webmention_external():
    """Handles inbound webmention, enqueue task to process.

    Use a task queue to deliver to followers because we send to each inbox in
    serial, which can take a long time with many followers/instances.
    """
    logger.info(f'Params: {list(request.form.items())}')

    source = flask_util.get_required_param('source').strip()
    if not util.is_web(source):
        error(f'Bad URL {source}')
    elif urlparse(source).scheme != 'https':
        error('source URLs must be https (with SSL)')

    domain = util.domain_from_link(source, minimize=False)
    if not domain:
        error(f'Bad source URL {source}')

    user = Web.get_by_id(domain)
    if not user:
        error(f'No user found for domain {domain}')

    if request.path == '/webmention':  # exclude interactive
        user.last_webmention_in = util.now()
        user.put()
        # TODO
        # maybe_superfeedr_unsubscribe(user)

    return common.create_task('webmention', **request.form)


@app.post('/webmention-interactive')
def webmention_interactive():
    """Handler that runs interactive webmention-based requests from the web UI.

    ...eg the update profile button on user pages.
    """
    source = flask_util.get_required_param('source').strip()

    try:
        webmention_external()
        user = Web(id=util.domain_from_link(source, minimize=False))
        flash(f'Updating fediverse profile from <a href="{user.web_url()}">{user.key.id()}</a>...')
        return redirect(user.user_page_path(), code=302)

    except HTTPException as e:
        flash(util.linkify(str(e.description), pretty=True))
        return redirect('/', code=302)


def maybe_superfeedr_subscribe(user):
    """Subscribes to a user's Atom or RSS feed in Superfeedr.

    Args:
      user (Web)
    """
    if user.superfeedr_subscribed:
        logger.info(f'User {user.key.id()} already subscribed via Superfeedr')
        return
    elif user.has_redirects or user.last_webmention_in:
        logger.info(f'User {user.key.id()} has Webfinger redirects or publishes via webmention, not subscribing via Superfeedr')
        return
    elif not user.obj or not user.obj.mf2:
        logger.info(f"User {user.key.id()} has no mf2, can't subscribe via Superfeedr")
        return


@app.post(f'/queue/poll-feed')
def poll_feed_task():
    """Fetches a :class:`Web` site's feed and delivers new/updated posts.

    Params:
      ``domain`` (str): key id of the :class:`Web` user
    """
    user = Web.get_by_id(flask_util.get_required_param('domain'))
    if not user:
        error(f'No Web user found for domain {domain}', status=304)

    # discover feed URL
    for url, info in user.obj.mf2.get('rel-urls', {}).items():
        if ('alternate' in info.get('rels', [])
                and info.get('type', '').split(';')[0] in FEED_TYPES.keys()):
            break
    else:
        msg = f"User {user.key.id()} has no feed URL, can't fetch feed"
        logger.info(msg)
        return msg

    # fetch feed
    resp = util.requests_get(url)
    content_type = resp.headers.get('Content-Type')
    type = FEED_TYPES.get(content_type.split(';')[0])
    if type == 'atom':
        activities = atom.atom_to_activities(resp.text)
        obj_feed_prop = {'atom': resp.text}
    elif type == 'rss':
        activities = rss.to_activities(resp.text)
        obj_feed_prop = {'rss': resp.text}
    else:
        msg = f'Unknown feed type {content_type}'
        logger.info(msg)
        return msg

    # create Objects and receive tasks
    published_last = None
    published_deltas = []  # timedeltas between entry published times
    for i, activity in enumerate(activities):
        logger.info(f'Converted to AS1: {json_dumps(activity, indent=2)}')

        published = activity.get('object', {}).get('published')
        if published and published_last:
            published_deltas.append(
                util.parse_iso8601(published) - util.parse_iso8601(published_last))
        published_last = published

        id = Object(our_as1=activity).as1.get('id')
        if not id:
            logger.warning('No id or URL!')
            continue

        activity['feed_index'] = i
        obj = Object.get_or_create(id=id, our_as1=activity, status='new',
                                   source_protocol=Web.ABBREV, users=[user.key],
                                   **obj_feed_prop)
        common.create_task(queue='receive', obj=obj.key.urlsafe(),
                           authed_as=user.key.id())

    # create next poll task
    if published_deltas:
        seconds = statistics.mean(t.total_seconds() for t in published_deltas)
        delay = max(min(timedelta(seconds=seconds), MAX_FEED_POLL_PERIOD),
                    MIN_FEED_POLL_PERIOD)
    else:
        # TODO
        delay = MIN_FEED_POLL_PERIOD

    common.create_task(queue='poll-feed', domain=user.key.id(), delay=delay)
    return 'OK'


@app.post('/queue/webmention')
@cloud_tasks_only
def webmention_task():
    """Handles inbound webmention task.

    Params:
      ``source`` (str): URL
    """
    logger.info(f'Params: {list(request.form.items())}')

    # load user
    source = flask_util.get_required_param('source').strip()
    domain = util.domain_from_link(source, minimize=False)
    logger.info(f'webmention from {domain}')

    user = Web.get_by_id(domain)
    if not user:
        error(f'No user found for domain {domain}', status=304)
    logger.info(f'User: {user.key}')

    # fetch source page
    try:
        # remote=True to force fetch, local=True to populate new/changed attrs
        obj = Web.load(source, local=True, remote=True,
                       check_backlink=not appengine_info.LOCAL_SERVER)
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
        obj = Object(id=id, status='new', our_as1={
            'id': id,
            'objectType': 'activity',
            'verb': 'delete',
            'actor': user.web_url(),
            'object': source,
        })

    if not obj or (not obj.mf2 and obj.type != 'delete'):
        error(f"Couldn't load {source} as microformats2 HTML", status=304)
    elif obj.mf2 and 'h-entry' in obj.mf2.get('type', []):
        authors = obj.mf2['properties'].setdefault('author', [])
        author_urls = microformats2.get_string_urls(authors)
        if not author_urls:
            authors.append(user.web_url())
        elif not user.is_web_url(author_urls[0]):
            logger.info(f'Overriding author {author_urls[0]} with {user.web_url()}')
            if isinstance(authors[0], dict):
                authors[0]['properties']['url'] = [user.web_url()]
            else:
                authors[0] = user.web_url()

    # if source is home page, update Web user and send an actor Update to
    # followers' instances
    if user.key.id() == obj.key.id() or user.is_web_url(obj.key.id()):
        logger.info(f'Converted to AS1: {obj.type}: {json_dumps(obj.as1, indent=2)}')
        obj.put()
        user.obj = obj
        user.put()

        logger.info('Wrapping in Update for home page user profile')
        actor_as1 = {
            **obj.as1,
            'id': user.web_url(),
            'updated': util.now().isoformat(),
        }
        id = common.host_url(f'{obj.key.id()}#update-{util.now().isoformat()}')
        obj = Object(id=id, status='new', our_as1={
            'objectType': 'activity',
            'verb': 'update',
            'id': id,
            'actor': user.web_url(),
            'object': actor_as1,
        })

    try:
        return Web.receive(obj, authed_as=user.web_url())
    except ValueError as e:
        logger.warning(e, exc_info=True)
        error(e, status=304)
