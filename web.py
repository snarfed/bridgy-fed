"""Webmention protocol with microformats2 in HTML, aka the IndieWeb stack."""
from datetime import timedelta, timezone
import difflib
import logging
import re
import statistics
import urllib.parse
from urllib.parse import quote, urlencode, urljoin, urlparse
from xml.etree import ElementTree

import brevity
from flask import redirect, render_template, request
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
from common import (
    CACHE_CONTROL,
    DOMAIN_RE,
    PRIMARY_DOMAIN,
    PROTOCOL_DOMAINS,
    SUPERDOMAIN,
)
from flask_app import app
from ids import normalize_user_id, translate_object_id, translate_user_id
from models import Follower, Object, PROTOCOLS, Target, User
from protocol import Protocol

logger = logging.getLogger(__name__)

# https://github.com/snarfed/bridgy-fed/issues/314
WWW_DOMAINS = frozenset((
    'www.jvt.me',
))

FEED_TYPES = {
    atom.CONTENT_TYPE.split(';')[0]: 'atom',
    rss.CONTENT_TYPE.split(';')[0]: 'rss',
    # https://stackoverflow.com/questions/4832357/whats-the-difference-between-text-xml-vs-application-xml-for-webservice-respons
    'application/xml': 'xml',
    'text/xml': 'xml',
}
MIN_FEED_POLL_PERIOD = timedelta(hours=2)
MAX_FEED_POLL_PERIOD = timedelta(weeks=1)
MAX_FEED_PROPERTY_SIZE = 500 * 1000  # Object.atom/rss
MAX_FEED_ITEMS_PER_POLL = 10


def is_valid_domain(domain, allow_internal=True):
    """Returns True if this is a valid domain we can use, False otherwise.

    Args:
      domain (str):
      allow_internal (bool): whether to return True for internal domains
        like ``fed.brid.gy``, ``bsky.brid.gy``, etc

    Valid means TLD is ok, not blacklisted, etc.
    """
    if not domain or not re.match(DOMAIN_RE, domain):
        # logger.debug(f"{domain} doesn't look like a domain")
        return False

    if Web.is_blocklisted(domain, allow_internal=allow_internal):
        logger.info(f'{domain} is blocklisted')
        return False

    tld = domain.split('.')[-1]
    if tld not in brevity.TLDS:
        logger.info(f"{domain} looks like a domain but {tld} isn't a TLD")
        return False

    return True


class Web(User, Protocol):
    """Web user and webmention protocol implementation.

    The key name is the domain.
    """
    ABBREV = 'web'
    PHRASE = 'the web'
    OTHER_LABELS = ('webmention',)
    LOGO_HTML = '🌐'  # used to be 🕸️
    CONTENT_TYPE = common.CONTENT_TYPE_HTML
    DEFAULT_ENABLED_PROTOCOLS = ('activitypub',)
    SUPPORTED_AS1_TYPES = (
        tuple(as1.ACTOR_TYPES)
        + tuple(as1.POST_TYPES)
        + tuple(as1.CRUD_VERBS)
        + ('audio', 'bookmark', 'event', 'image', 'video')
        + ('follow', 'like', 'share', 'stop-following')
    )

    has_redirects = ndb.BooleanProperty()
    redirects_error = ndb.TextProperty()
    has_hcard = ndb.BooleanProperty()
    last_webmention_in = ndb.DateTimeProperty(tzinfo=timezone.utc)
    last_polled_feed = ndb.DateTimeProperty(tzinfo=timezone.utc)
    feed_last_item = ndb.StringProperty()  # id (URL)
    feed_etag = ndb.StringProperty()
    feed_last_modified = ndb.StringProperty()

    # Originally, BF served Web users' AP actor ids on fed.brid.gy, eg
    # https://fed.brid.gy/snarfed.org . When we started adding new protocols, we
    # switched to per-protocol subdomains, eg https://web.brid.gy/snarfed.org .
    # However, we need to preserve the old users' actor ids as is.
    #
    # Also, our per-protocol bot accounts in ActivityPub are on their own
    # subdomains, eg @bsky.brid.gy@bsky.brid.gy.
    #
    # So, this property tracks which subdomain a given Web user's AP actor uses.
    ap_subdomain = ndb.StringProperty(
        choices=['ap', 'bsky', 'fed', 'web', 'fake', 'other', 'eefake'],
        default='web')

    # OLD. some stored entities still have these; do not reuse.
    # superfeedr_subscribed = ndb.DateTimeProperty(tzinfo=timezone.utc)
    # superfeedr_subscribed_feed = ndb.StringProperty()

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
    def get_or_create(cls, id, allow_opt_out=False, verify=None, **kwargs):
        """Normalize domain, then pass through to :meth:`User.get_or_create`.

        Normalizing currently consists of lower casing and removing leading and
        trailing dots.

        Args:
          verify (bool): whether to call :meth:`verify` to load h-card, check
            redirects, etc. Defaults to calling it only if the user is new.
        """
        key = cls.key_for(id, allow_opt_out=allow_opt_out)
        if not key:
            return None  # opted out

        domain = key.id()
        if util.domain_or_parent_in(domain, [SUPERDOMAIN.strip('.')]):
            return super().get_by_id(domain)

        user = super().get_or_create(domain, allow_opt_out=allow_opt_out, **kwargs)

        if verify or (verify is None and not user.existing):
            user = user.verify()

        if not user.existing:
            common.create_task(queue='poll-feed', domain=user.key.id())

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

        converted = translate_user_id(id=self.key.id(), from_=self,
                                      to=to_proto)

        if to_proto.LABEL == 'activitypub':
            other = 'web' if self.ap_subdomain == 'fed' else 'fed'
            converted = converted.replace(f'https://{other}.brid.gy/',
                                          f'https://{self.ap_subdomain}.brid.gy/')

        return converted

    web_url = User.profile_id

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
          self's domain started with www and we switch to the root domain.
        """
        domain = self.key.id()
        logger.info(f'Verifying {domain}')

        if domain.startswith('www.') and domain not in WWW_DOMAINS:
            # if root domain serves ok, use it instead
            # https://github.com/snarfed/bridgy-fed/issues/314
            root = domain.removeprefix('www.')
            root_site = f'https://{root}/'
            try:
                resp = util.requests_get(root_site, gateway=False)
                if resp.ok and self.is_web_url(resp.url):
                    logger.info(f'{root_site} serves ok ; using {root} instead')
                    root_user = Web.get_or_create(
                        root,
                        enabled_protocols=self.enabled_protocols,
                        direct=self.direct)
                    self.use_instead = root_user.key
                    self.put()
                    return root_user.verify()
            except RequestException as e:
                logger.info(f"Couldn't fetch {root_site} : {e}")
                logger.info(f"Continuing with {domain}")
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
            if resp.url:
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
    def key_for(cls, id, allow_opt_out=False):
        """Returns the :class:`ndb.Key` for a given id.

        If id is a domain, uses it as is. If it's a home page URL or fed.brid.gy
        or web.brid.gy AP actor URL, extracts the domain and uses that.
        Otherwise, returns None.

        Args:
          id (str)
          allow_opt_out (bool): whether to allow users who are currently opted out

        Returns:
        ndb.Key or None:
        """
        if not id:
            return None

        id = id.lower().strip('.')
        if util.is_web(id):
            parsed = urlparse(id)
            if parsed.path in ('', '/'):
                id = parsed.netloc

        if is_valid_domain(id, allow_internal=True):
            return super().key_for(id, allow_opt_out=allow_opt_out)

        return None

    @classmethod
    def owns_id(cls, id):
        """Returns None if id is a domain or http(s) URL, False otherwise.

        All web pages are http(s) URLs, but not all http(s) URLs are web pages.
        """
        if not id:
            return False

        if key := cls.key_for(id):
            user = key.get()
            return True if user and user.has_redirects else None
        elif is_valid_domain(id):
            return None

        # we allowed internal domains for protocol bot actors above, but we
        # don't want to allow non-homepage URLs on those domains, eg
        # https://bsky.brid.gy/foo, so don't allow internal here
        domain = util.domain_from_link(id)
        if util.is_web(id) and is_valid_domain(domain, allow_internal=False):
            return None

        return False

    @classmethod
    def owns_handle(cls, handle, allow_internal=False):
        if handle == PRIMARY_DOMAIN or handle in PROTOCOL_DOMAINS:
            return True
        elif not is_valid_domain(handle, allow_internal=allow_internal):
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
            logger.warning(f"{obj.key.id()} is source_protocol web but id isn't a URL!")
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
        targets = as1.targets(obj.as1)
        if not (url in targets or
                # homepage, check domain too
                (urlparse(url).path.strip('/') == ''
                 and util.domain_from_link(url) in targets)):
            # logger.info(f'Skipping sending to {url} , not a target in the object')
            return False

        if to_cls.is_blocklisted(url):
            logger.info(f'Skipping sending to blocklisted {url}')
            return False

        source_id = translate_object_id(
            id=obj.key.id(), from_=PROTOCOLS[obj.source_protocol], to=Web)
        source_url = quote(source_id, safe=':/%+')
        logger.info(f'Sending webmention from {source_url} to {url}')

        # we only send webmentions for responses. for sending normal posts etc
        # to followers, we just update our stored objects (elsewhere) and web
        # users consume them via feeds.
        endpoint = common.webmention_discover(url).endpoint
        if not endpoint:
            return False

        webmention.send(endpoint, source_url, url)
        return True

    @classmethod
    def load(cls, id, **kwargs):
        """Wrap :meth:`Protocol.load` to convert domains to homepage URLs."""
        if re.match(DOMAIN_RE, id):
            id = f'https://{id}/'

        return super().load(id, **kwargs)

    @classmethod
    def fetch(cls, obj, gateway=False, check_backlink=False,
              authorship_fetch_mf2=True, metaformats=None, **kwargs):
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
          authorship_fetch_mf2 (bool): optional, when running the authorship
            algorithm, fetch author URL if necessary
          kwargs: ignored
        """
        url = obj.key.id()
        if not util.is_web(url):
            logger.info(f'{url} is not a URL')
            return False

        is_homepage = urlparse(url).path.strip('/') == ''
        if is_homepage:
            domain = util.domain_from_link(url)
            if domain == PRIMARY_DOMAIN or domain in PROTOCOL_DOMAINS:
                profile = util.read(f'{domain}.as2.json')
                if profile:
                    obj.as2 = json_loads(profile)
                    return True
                return False

        require_backlink = (common.host_url().rstrip('/')
                            if check_backlink and not is_homepage
                            else None)
        if metaformats is None:
            # default to only for homepages
            metaformats = urlparse(url).path in ('', '/')

        try:
            parsed = util.fetch_mf2(url, gateway=gateway, metaformats=metaformats,
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
            logger.info(f'Found representative h-card')
        else:
            entry = mf2util.find_first_entry(parsed, ['h-entry'])
            if not entry:
                error(f'No microformats2 h-entry found in {url}')

        # discard uid if set; we use URL as id
        props = entry.setdefault('properties', {})
        if 'uid' in props:
            logger.info(f'Discarding uid property: {props["uid"]}')
            props.pop('uid')

        # store final URL in mf2 object
        if is_homepage:
            entry.setdefault('rel-urls', {}).update(parsed.get('rel-urls', {}))
            entry.setdefault('type', ['h-card'])
        if parsed['url']:
            entry['url'] = parsed['url']
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
                fetch_fn = util.fetch_mf2 if authorship_fetch_mf2 else None
                author = mf2util.find_author({'items': [entry]}, hentry=entry,
                                             fetch_mf2_func=fetch_fn)
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
    def _convert(cls, obj, from_user=None):
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
        if from_user and not from_user.is_enabled(cls):
            error(f'{from_user.key.id()} => {cls.LABEL} not enabled')

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
        url = util.get_url(obj_as1) or obj_as1.get('id') or obj.key.id()
        if util.is_web(url):
            utf8 = '<meta charset="utf-8">'
            refresh = f'<meta http-equiv="refresh" content="0;url={url}">'
            html = html.replace(utf8, utf8 + '\n' + refresh)

        return html


@app.get('/web-site')
@flask_util.headers(CACHE_CONTROL)
def enter_web_site():
    return render_template('enter_web_site.html')


@app.post('/web-site')
def check_web_site():
    logger.info(f'Params: {list(request.form.items())}')

    url = request.values['url']

    # this normalizes and lower cases domain
    try:
        domain = normalize_user_id(id=url, proto=Web)
    except (ValueError, AssertionError):
        logger.info(f'bad web id? {url}', exc_info=True)
        domain = None

    if not domain or not is_valid_domain(domain, allow_internal=False):
        flash(f'{url} is not a valid or supported web site')
        return render_template('enter_web_site.html'), 400

    if util.is_web(url) and urlparse(url).path.strip('/'):
        flash('Only top-level web sites and domains are supported.')
        return render_template('enter_web_site.html'), 400

    try:
        user = Web.get_or_create(domain, enabled_protocols=['atproto'],
                                 propagate=True, direct=True, verify=True)
        if not user:  # opted out
            flash(f'{url} is not a valid or supported web site')
            return render_template('enter_web_site.html'), 400
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

    user.last_webmention_in = util.now()
    user.put()

    return common.create_task('webmention', **request.form)


@app.post(f'/queue/poll-feed')
@cloud_tasks_only
def poll_feed_task():
    """Fetches a :class:`Web` site's feed and delivers new/updated posts.

    Params:
      ``domain`` (str): key id of the :class:`Web` user
    """
    domain = flask_util.get_required_param('domain')
    logger.info(f'Polling feed for {domain}')

    user = Web.get_by_id(domain)
    if not (user and user.obj and user.obj.mf2):
        error(f'No Web user or object found for domain {domain}', status=304)
    elif user.last_webmention_in:
        logger.info(f'Dropping since last_webmention_in is set')
        return 'OK'

    # discover feed URL
    for url, info in user.obj.mf2.get('rel-urls', {}).items():
        rel_type = FEED_TYPES.get(info.get('type', '').split(';')[0])
        if 'alternate' in info.get('rels', []) and rel_type:
            break
    else:
        msg = f"User {user.key.id()} has no feed URL, can't fetch feed"
        logger.info(msg)
        return msg

    # fetch feed
    headers = {}
    if user.feed_etag:
        headers['If-None-Match'] = user.feed_etag
    if user.feed_last_modified:
        headers['If-Modified-Since'] = user.feed_last_modified
    resp = util.requests_get(url, headers=headers, gateway=True)

    content_type = resp.headers.get('Content-Type') or ''
    type = FEED_TYPES.get(content_type.split(';')[0])
    if resp.status_code == 304:
        logger.info('Feed is unchanged since last poll')
        activities = []
    elif type == 'atom' or (type == 'xml' and rel_type == 'atom'):
        try:
            activities = atom.atom_to_activities(resp.text)
        except (ValueError, ElementTree.ParseError) as e:
            # TODO: should probably still create the next poll-feed task
            error(f"Couldn't parse feed as Atom: {e}", status=502)
        obj_feed_prop = {'atom': resp.text[:MAX_FEED_PROPERTY_SIZE]}
    elif type == 'rss' or (type == 'xml' and rel_type == 'rss'):
        try:
            activities = rss.to_activities(resp.text)
        except ValueError as e:
            error(f"Couldn't parse feed as RSS: {e}", status=502)
        obj_feed_prop = {'rss': resp.text[:MAX_FEED_PROPERTY_SIZE]}
    else:
        msg = f'Unknown feed type {content_type}'
        logger.info(msg)
        return msg

    if len(activities) > MAX_FEED_ITEMS_PER_POLL:
        logger.info(f'Got {len(activities)} feed items, only processing the first {MAX_FEED_ITEMS_PER_POLL}')
        activities = activities[:MAX_FEED_ITEMS_PER_POLL]

    # create Objects and receive tasks
    for i, activity in enumerate(activities):
        # default actor and author to user
        activity.setdefault('actor', {}).setdefault('id', user.profile_id())
        obj = activity.setdefault('object', {})
        obj.setdefault('author', {}).setdefault('id', user.profile_id())

        # use URL as id since some feeds use non-URL (eg tag URI) ids
        for elem in obj, activity:
            if url := elem.get('url'):
                elem['id'] = elem['url']

        # logger.info(f'Converted to AS1: {json_dumps(activity, indent=2)}')

        id = Object(our_as1=activity).as1.get('id')
        if not id:
            logger.warning('No id or URL!')
            continue

        if i == 0:
            logger.info(f'Setting feed_last_item to {id}')
            user.feed_last_item = id
        elif id == user.feed_last_item:
            logger.info(f'Already seen {id}, skipping rest of feed')
            break

        if Web.owns_id(id) is False:
            logger.warning(f'Skipping bad id {id}')
            continue

        if not obj.get('image'):
            # fetch and check the post itself
            post = Web.load(id, metaformats=True, authorship_fetch_mf2=False)
            if post and post.as1:
                profile_images = (as1.get_ids(user.obj.as1, 'image')
                                  if user.obj.as1 else [])
                obj['image'] = [img for img in as1.get_ids(post.as1, 'image')
                                if img not in profile_images]

        activity['feed_index'] = i
        obj = Object.get_or_create(id=id, authed_as=domain, our_as1=activity,
                                   status='new', source_protocol=Web.ABBREV,
                                   users=[user.key], **obj_feed_prop)
        common.create_task(queue='receive', obj=obj.key.urlsafe(),
                           authed_as=user.key.id())

    # determine posting frequency
    published_last = None
    published_deltas = []  # timedeltas between entry published times
    for activity in activities:
        published = activity['object'].get('published')
        if published and published_last:
            published_deltas.append(
                abs(util.parse_iso8601(published) -
                    util.parse_iso8601(published_last)))
        published_last = published

    # create next poll task
    def clamp(delay):
        return max(min(delay, MAX_FEED_POLL_PERIOD), MIN_FEED_POLL_PERIOD)

    if published_deltas:
        delay = clamp(timedelta(seconds=statistics.mean(
            t.total_seconds() for t in published_deltas)))
    else:
        delay = clamp(util.now() - (user.last_polled_feed
                                    or user.created.replace(tzinfo=timezone.utc)))

    common.create_task(queue='poll-feed', domain=user.key.id(), delay=delay)

    # update user
    user.last_polled_feed = util.now()
    user.feed_etag = resp.headers.get('ETag')
    user.feed_last_modified = resp.headers.get('Last-Modified')
    user.put()

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
    logger.info(f'User: {user.key.id()}')

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

    try:
        return Web.receive(obj, authed_as=user.key.id())
    except ValueError as e:
        logger.warning(e, exc_info=True)
        error(e, status=304)
