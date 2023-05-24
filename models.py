"""Datastore model classes."""
import base64
from datetime import timedelta, timezone
import difflib
import itertools
import json
import logging
import random
import urllib.parse

from arroba.mst import dag_cbor_cid
from Crypto import Random
from Crypto.PublicKey import ECC, RSA
from Crypto.Util import number
import dag_json
from flask import g, request
from google.cloud import ndb
from granary import as1, as2, bluesky, microformats2
from oauth_dropins.webutil.appengine_info import DEBUG
from oauth_dropins.webutil.models import ComputedJsonProperty, JsonProperty, StringIdModel
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads
import requests
from werkzeug.exceptions import BadRequest, NotFound

import common

# https://github.com/snarfed/bridgy-fed/issues/314
WWW_DOMAINS = frozenset((
    'www.jvt.me',
))
# TODO: eventually load from protocol.protocols instead, if/when we can get
# around the circular import
PROTOCOLS = ('activitypub', 'bluesky', 'ostatus', 'webmention', 'ui')
# 2048 bits makes tests slow, so use 1024 for them
KEY_BITS = 1024 if DEBUG else 2048
PAGE_SIZE = 20

# auto delete old objects of these types via the Object.expire property
# https://cloud.google.com/datastore/docs/ttl
OBJECT_EXPIRE_TYPES = (
    'post',
    'update',
    'delete',
    'accept',
    'reject',
    'undo',
    None
)
OBJECT_EXPIRE_AGE = timedelta(days=90)

logger = logging.getLogger(__name__)


def base64_to_long(x):
    """Converts x from URL safe base64 encoding to a long integer.

    Originally from django_salmon.magicsigs.
    """
    return number.bytes_to_long(base64.urlsafe_b64decode(x))


def long_to_base64(x):
    """Converts x from a long integer to base64 URL safe encoding.

    Originally from django_salmon.magicsigs.
    """
    return base64.urlsafe_b64encode(number.long_to_bytes(x))


class User(StringIdModel):
    """Stores a Bridgy Fed user.

    The key name is the domain.

    Stores multiple keypairs needed for the supported protocols. Currently:

    * RSA keypair for ActivityPub HTTP Signatures
      properties: mod, public_exponent, private_exponent
      https://tools.ietf.org/html/draft-cavage-http-signatures-12

    * P-256 keypair for AT Protocol's signing key
      property: p256_key, PEM encoded
      https://atproto.com/guides/overview#account-portability

    The key pair's modulus and exponent properties are all encoded as base64url
    (ie URL-safe base64) strings as described in RFC 4648 and section 5.1 of the
    Magic Signatures spec.
    """
    mod = ndb.StringProperty(required=True)
    public_exponent = ndb.StringProperty(required=True)
    private_exponent = ndb.StringProperty(required=True)
    p256_key = ndb.StringProperty()
    has_redirects = ndb.BooleanProperty()
    redirects_error = ndb.TextProperty()
    has_hcard = ndb.BooleanProperty()
    actor_as2 = JsonProperty()
    use_instead = ndb.KeyProperty()

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @property
    def homepage(self):
        return f'https://{self.key.id()}/'

    @classmethod
    def _get_kind(cls):
        return 'MagicKey'

    def _post_put_hook(self, future):
        logger.info(f'Wrote User {self.key.id()}')

    @classmethod
    def get_by_id(cls, id):
        """Override Model.get_by_id to follow the use_instead property."""
        user = cls._get_by_id(id)
        if user and user.use_instead:
            return user.use_instead.get()

        return user

    @staticmethod
    @ndb.transactional()
    def get_or_create(domain, **kwargs):
        """Loads and returns a User. Creates it if necessary."""
        user = User.get_by_id(domain)
        if user:
            return user

        # originally from django_salmon.magicsigs
        # this uses urandom(), and does nontrivial math, so it can take a
        # while depending on the amount of randomness available.
        rng = Random.new().read
        rsa_key = RSA.generate(KEY_BITS, rng)
        p256_key = ECC.generate(curve='P-256',
                                randfunc=random.randbytes if DEBUG else None)
        user = User(id=domain,
                    mod=long_to_base64(rsa_key.n),
                    public_exponent=long_to_base64(rsa_key.e),
                    private_exponent=long_to_base64(rsa_key.d),
                    p256_key=p256_key.export_key(format='PEM'),
                    **kwargs)
        user.put()
        return user

    def href(self):
        return f'data:application/magic-public-key,RSA.{self.mod}.{self.public_exponent}'

    def public_pem(self):
        """Returns: bytes"""
        rsa = RSA.construct((base64_to_long(str(self.mod)),
                             base64_to_long(str(self.public_exponent))))
        return rsa.exportKey(format='PEM')

    def private_pem(self):
        """Returns: bytes"""
        rsa = RSA.construct((base64_to_long(str(self.mod)),
                             base64_to_long(str(self.public_exponent)),
                             base64_to_long(str(self.private_exponent))))
        return rsa.exportKey(format='PEM')

    def to_as1(self):
        """Returns this user as an AS1 actor dict, if possible."""
        if self.actor_as2:
            return as2.to_as1(self.actor_as2)

    def username(self):
        """Returns the user's preferred username.

        Uses stored representative h-card, falls back to domain if that's not
        available.

        Returns: str
        """
        domain = self.key.id()

        if self.actor_as2:
            for url in [u.get('value') if isinstance(u, dict) else u
                        for u in util.get_list(self.actor_as2, 'url')]:
                if url and url.startswith('acct:'):
                    urluser, urldomain = util.parse_acct_uri(url)
                    if urldomain == domain:
                        logger.info(f'Found custom username: {urluser}')
                        return urluser

        logger.info(f'Defaulting username to domain {domain}')
        return domain

    def address(self):
        """Returns this user's ActivityPub address, eg '@me@foo.com'."""
        return f'@{self.username()}@{self.key.id()}'

    def actor_id(self):
        """Returns this user's AS2 actor id, eg 'https://fed.brid.gy/foo.com'."""
        return common.host_url(self.key.id())

    def is_homepage(self, url):
        """Returns True if the given URL points to this user's home page."""
        if not url:
            return False

        url = url.strip().rstrip('/')
        if url == self.key.id():
            return True

        parsed = urllib.parse.urlparse(url)
        return (parsed.netloc == self.key.id()
                and parsed.scheme in ('', 'http', 'https')
                and not parsed.path and not parsed.query
                and not parsed.params and not parsed.fragment)

    def user_page_link(self):
        """Returns a pretty user page link with the user's name and profile picture."""
        domain = self.key.id()
        actor = self.actor_as2 or {}
        name = (actor.get('name') or
                # prettify if domain, noop if username
                util.domain_from_link(self.username()))
        img = util.get_url(actor, 'icon') or ''

        return f'<a class="h-card u-author" href="/user/{domain}"><img src="{img}" class="profile"> {name}</a>'

    def verify(self):
        """Fetches site a couple ways to check for redirects and h-card.

        Returns: User that was verified. May be different than self! eg if self's
          domain started with www and we switch to the root domain.
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
                if resp.ok and self.is_homepage(resp.url):
                    logger.info(f'{root_site} redirects to {resp.url} ; using {root} instead')
                    root_user = User.get_or_create(root)
                    self.use_instead = root_user.key
                    self.put()
                    return root_user.verify()
            except requests.RequestException:
                pass

        # check webfinger redirect
        path = f'/.well-known/webfinger?resource=acct:{domain}@{domain}'
        self.has_redirects = False
        self.redirects_error = None
        try:
            url = urllib.parse.urljoin(self.homepage, path)
            resp = util.requests_get(url, gateway=False)
            domain_urls = ([f'https://{domain}/' for domain in common.DOMAINS] +
                           [common.host_url()])
            expected = [urllib.parse.urljoin(url, path) for url in domain_urls]
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
        except requests.RequestException:
            pass

        # check home page
        try:
            import activitypub, webmention  # TODO: actually fix these circular imports
            obj = webmention.Webmention.load(self.homepage, gateway=True)
            self.actor_as2 = activitypub.postprocess_as2(as2.from_as1(obj.as1))
            self.has_hcard = True
        except (BadRequest, NotFound):
            self.actor_as2 = None
            self.has_hcard = False

        return self


class Target(ndb.Model):
    """Delivery destinations. ActivityPub inboxes, webmention targets, etc.

    Used in StructuredPropertys inside Object; not stored directly in the
    datastore.

    ndb implements this by hoisting each property here into a corresponding
    property on the parent entity, prefixed by the StructuredProperty name
    below, eg delivered.uri, delivered.protocol, etc.

    For repeated StructuredPropertys, the hoisted properties are all
    repeated on the parent entity, and reconstructed into
    StructuredPropertys based on their order.

    https://googleapis.dev/python/python-ndb/latest/model.html#google.cloud.ndb.model.StructuredProperty
    """
    uri = ndb.StringProperty(required=True)
    protocol = ndb.StringProperty(choices=PROTOCOLS, required=True)


class Object(StringIdModel):
    """An activity or other object, eg actor.

    Key name is the id. We synthesize ids if necessary.
    """
    STATUSES = ('new', 'in progress', 'complete', 'failed', 'ignored')
    LABELS = ('activity', 'feed', 'notification', 'user')

    # domains of the Bridgy Fed users this activity is to or from
    domains = ndb.StringProperty(repeated=True)
    status = ndb.StringProperty(choices=STATUSES)
    # TODO: remove? is this redundant with the protocol-specific data fields below?
    source_protocol = ndb.StringProperty(choices=PROTOCOLS)
    labels = ndb.StringProperty(repeated=True, choices=LABELS)

    # TODO: switch back to ndb.JsonProperty if/when they fix it for the web console
    # https://github.com/googleapis/python-ndb/issues/874
    as2 = JsonProperty()      # only one of the rest will be populated...
    bsky = JsonProperty()     # Bluesky / AT Protocol
    mf2 = JsonProperty()      # HTML microformats2 item (ie _not_ the top level
                              # parse object with items inside an 'items' field)
    our_as1 = JsonProperty()  # AS1 for activities that we generate or modify ourselves

    # Protocol and subclasses set these in fetch if this Object is new or if its
    # contents have changed from what was originally loaded from the datastore.
    new = None
    changed = None

    @ComputedJsonProperty
    def as1(self):
        # TODO: switch back to assert?
        # assert (self.as2 is not None) ^ (self.bsky is not None) ^ (self.mf2 is not None), \
        #     f'{self.as2} {self.bsky} {self.mf2}'
        if bool(self.as2) + bool(self.bsky) + bool(self.mf2) > 1:
            logger.warning(f'{self.key} has multiple! {bool(self.as2)} {bool(self.bsky)} {bool(self.mf2)}')

        if self.our_as1 is not None:
            return common.redirect_unwrap(self.our_as1)
        elif self.as2 is not None:
            return as2.to_as1(common.redirect_unwrap(self.as2))
        elif self.bsky is not None:
            return bluesky.to_as1(self.bsky)
        elif self.mf2 is not None:
            return microformats2.json_to_object(self.mf2,
                                                rel_urls=self.mf2.get('rel-urls'))

    @ndb.ComputedProperty
    def type(self):  # AS1 objectType, or verb if it's an activity
        if self.as1:
            return as1.object_type(self.as1)

    def _object_ids(self):  # id(s) of inner objects
        if self.as1:
            return common.redirect_unwrap(as1.get_ids(self.as1, 'object'))
    object_ids = ndb.ComputedProperty(_object_ids, repeated=True)

    deleted = ndb.BooleanProperty()

    delivered = ndb.StructuredProperty(Target, repeated=True)
    undelivered = ndb.StructuredProperty(Target, repeated=True)
    failed = ndb.StructuredProperty(Target, repeated=True)

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    # For certain types, automatically delete this Object after 90d using a
    # TTL policy:
    # https://cloud.google.com/datastore/docs/ttl#ttl_properties_and_indexes
    # They recommend not indexing TTL properties:
    # https://cloud.google.com/datastore/docs/ttl#ttl_properties_and_indexes
    def _expire(self):
        if self.type in OBJECT_EXPIRE_TYPES:
            return (self.updated or util.now()) + OBJECT_EXPIRE_AGE
    expire = ndb.ComputedProperty(_expire, indexed=False)

    def _pre_put_hook(self):
        assert '^^' not in self.key.id()

        if self.as1 and self.as1.get('objectType') == 'activity':
            if 'activity' not in self.labels:
                self.labels.append('activity')
        else:
            if 'activity' in self.labels:
                self.labels.remove('activity')

    def _post_put_hook(self, future):
        """Update :meth:`Protocol.load` cache."""
        # TODO: assert that as1 id is same as key id? in pre put hook?
        logger.info(f'Wrote Object {self.key.id()} {self.type} {self.status or ""} {self.labels} for {len(self.domains)} users')
        if '#' not in self.key.id():
            import protocol  # TODO: actually fix this circular import
            protocol.objects_cache[self.key.id()] = self

    @classmethod
    def get_by_id(cls, id):
        """Override Model.get_by_id to un-escape ^^ to #.

        https://github.com/snarfed/bridgy-fed/issues/469

        See "meth:`proxy_url()` for the inverse.
        """
        return super().get_by_id(id.replace('^^', '#'))

    def clear(self):
        """Clears all data properties."""
        for prop in 'as2', 'bsky', 'mf2':
            val = getattr(self, prop, None)
            if val:
                logger.warning(f'Wiping out {prop}: {json_dumps(val, indent=2)}')
            setattr(self, prop, None)

    def proxy_url(self):
        """Returns the Bridgy Fed proxy URL to render this post as HTML.

        Escapes # characters to ^^.
        https://github.com/snarfed/bridgy-fed/issues/469

        See "meth:`get_by_id()` for the inverse.
        """
        assert '^^' not in self.key.id()
        id = self.key.id().replace('#', '^^')
        return common.host_url('render?' + urllib.parse.urlencode({'id': id}))

    def actor_link(self):
        """Returns a pretty actor link with their name and profile picture."""
        attrs = {'class': 'h-card u-author'}

        if (self.source_protocol in ('webmention', 'ui') and g.user and
            g.user.key.id() in self.domains):
            # outbound; show a nice link to the user
            return g.user.user_page_link()

        actor = (util.get_first(self.as1, 'actor')
                 or util.get_first(self.as1, 'author')
                 or {})
        if isinstance(actor, str):
            return common.pretty_link(actor, attrs=attrs)

        url = util.get_first(actor, 'url') or ''
        name = actor.get('displayName') or actor.get('username') or ''
        image = util.get_url(actor, 'image')
        if not image:
            return common.pretty_link(url, text=name, attrs=attrs)

        return f"""\
        <a class="h-card u-author" href="{url}" title="{name}">
          <img class="profile" src="{image}" />
          {util.ellipsize(name, chars=40)}
        </a>"""

class AtpNode(StringIdModel):
    """An AT Protocol (Bluesky) node.

    May be a data record, an MST node, or a commit.

    Key name is the DAG-CBOR base32 CID of the data.

    Properties:
    * data: JSON-decoded DAG-JSON value of this node
    * obj: optional, Key of the corresponding :class:`Object`, only populated
      for records
    """
    data = JsonProperty(required=True)
    obj = ndb.KeyProperty(Object)

    @staticmethod
    def create(data):
        """Writes a new AtpNode to the datastore.

        Args:
          data: dict value

        Returns:
          :class:`AtpNode`
        """
        data = json.loads(dag_json.encode(data))
        cid = dag_cbor_cid(data)
        node = AtpNode(id=cid.encode('base32'), data=data)
        node.put()
        return node


class Follower(StringIdModel):
    """A follower of a Bridgy Fed user.

    Key name is 'TO FROM', where each part is either a domain or an AP id, eg:
    'snarfed.org https://mastodon.social/@swentel'.

    Both parts are duplicated in the src and dest properties.
    """
    STATUSES = ('active', 'inactive')

    src = ndb.StringProperty()
    dest = ndb.StringProperty()
    # Most recent AP (AS2) JSON Follow activity. If inbound, must have a
    # composite actor object with an inbox, publicInbox, or sharedInbox.
    last_follow = JsonProperty()
    status = ndb.StringProperty(choices=STATUSES, default='active')

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    def _post_put_hook(self, future):
        logger.info(f'Wrote Follower {self.key.id()} {self.status}')

    @classmethod
    def _id(cls, dest, src):
        assert src
        assert dest
        return f'{dest} {src}'

    @classmethod
    def get_or_create(cls, dest, src, **kwargs):
        follower = cls.get_or_insert(cls._id(dest, src), src=src, dest=dest, **kwargs)
        follower.dest = dest
        follower.src = src
        for prop, val in kwargs.items():
            setattr(follower, prop, val)
        follower.put()
        return follower

    def to_as1(self):
        """Returns this follower as an AS1 actor dict, if possible."""
        return as2.to_as1(self.to_as2())

    def to_as2(self):
        """Returns this follower as an AS2 actor dict, if possible."""
        if self.last_follow:
            return self.last_follow.get('actor' if util.is_web(self.src) else 'object')

    @staticmethod
    def fetch_page(domain, collection):
        """Fetches a page of Follower entities.

        Wraps :func:`fetch_page`. Paging uses the `before` and `after` query
        parameters, if available in the request.

        Args:
          domain: str, user to fetch entities for
          collection, str, 'followers' or 'following'

        Returns:
          (results, new_before, new_after) tuple with:
          results: list of Follower entities
          new_before, new_after: str query param values for `before` and `after`
            to fetch the previous and next pages, respectively
        """
        assert collection in ('followers', 'following'), collection

        domain_prop = Follower.dest if collection == 'followers' else Follower.src
        query = Follower.query(
            Follower.status == 'active',
            domain_prop == domain,
        ).order(-Follower.updated)
        return fetch_page(query, Follower)


def fetch_page(query, model_class):
    """Fetches a page of results from a datastore query.

    Uses the `before` and `after` query params (if provided; should be ISO8601
    timestamps) and the queried model class's `updated` property to identify the
    page to fetch.

    Populates a `log_url_path` property on each result entity that points to a
    its most recent logged request.

    Args:
      query: :class:`ndb.Query`
      model_class: ndb model class

    Returns:
      (results, new_before, new_after) tuple with:
      results: list of query result entities
      new_before, new_after: str query param values for `before` and `after`
        to fetch the previous and next pages, respectively
    """
    # if there's a paging param ('before' or 'after'), update query with it
    # TODO: unify this with Bridgy's user page
    def get_paging_param(param):
        val = request.values.get(param)
        if val:
            try:
                dt = util.parse_iso8601(val.replace(' ', '+'))
            except BaseException as e:
                error(f"Couldn't parse {param}, {val!r} as ISO8601: {e}")
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt

    before = get_paging_param('before')
    after = get_paging_param('after')
    if before and after:
        error("can't handle both before and after")
    elif after:
        query = query.filter(model_class.updated >= after).order(model_class.updated)
    elif before:
        query = query.filter(model_class.updated < before).order(-model_class.updated)
    else:
        query = query.order(-model_class.updated)

    query_iter = query.iter()
    results = sorted(itertools.islice(query_iter, 0, PAGE_SIZE),
                     key=lambda r: r.updated, reverse=True)

    # calculate new paging param(s)
    has_next = results and query_iter.probably_has_next()
    new_after = (
        before if before
        else results[0].updated if has_next and after
        else None)
    if new_after:
        new_after = new_after.isoformat()

    new_before = (
        after if after else
        results[-1].updated if has_next
        else None)
    if new_before:
        new_before = new_before.isoformat()

    return results, new_before, new_after
