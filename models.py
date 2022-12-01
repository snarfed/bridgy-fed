"""Datastore model classes."""
import difflib
import logging
import urllib.parse

import requests
from werkzeug.exceptions import BadRequest, NotFound

from Crypto.PublicKey import RSA
from django_salmon import magicsigs
from flask import request
from google.cloud import ndb
from granary import as2, microformats2
from oauth_dropins.webutil.models import StringIdModel
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

import common

logger = logging.getLogger(__name__)


class User(StringIdModel):
    """Stores a Bridgy Fed user.

    The key name is the domain. The key pair is used for both ActivityPub HTTP
    Signatures and Salmon Magic Signatures.

    https://tools.ietf.org/html/draft-cavage-http-signatures-07
    http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html
    http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-salmon-00.html

    The key pair's modulus and exponent properties are all encoded as base64url
    (ie URL-safe base64) strings as described in RFC 4648 and section 5.1 of the
    Magic Signatures spec.
    """
    mod = ndb.StringProperty(required=True)
    public_exponent = ndb.StringProperty(required=True)
    private_exponent = ndb.StringProperty(required=True)
    has_redirects = ndb.BooleanProperty()
    redirects_error = ndb.TextProperty()
    has_hcard = ndb.BooleanProperty()
    actor_as2 = ndb.TextProperty()

    @classmethod
    def _get_kind(cls):
        return 'MagicKey'

    @staticmethod
    @ndb.transactional()
    def get_or_create(domain):
        """Loads and returns a User. Creates it if necessary."""
        user = User.get_by_id(domain)

        if not user:
            # this uses urandom(), and does nontrivial math, so it can take a
            # while depending on the amount of randomness available.
            pubexp, mod, privexp = magicsigs.generate()
            user = User(id=domain, mod=mod, public_exponent=pubexp,
                        private_exponent=privexp)
            user.put()

        return user

    def href(self):
        return 'data:application/magic-public-key,RSA.%s.%s' % (
            self.mod, self.public_exponent)

    def public_pem(self):
        """Returns: bytes"""
        rsa = RSA.construct((magicsigs.base64_to_long(str(self.mod)),
                             magicsigs.base64_to_long(str(self.public_exponent))))
        return rsa.exportKey(format='PEM')

    def private_pem(self):
        """Returns: bytes"""
        rsa = RSA.construct((magicsigs.base64_to_long(str(self.mod)),
                             magicsigs.base64_to_long(str(self.public_exponent)),
                             magicsigs.base64_to_long(str(self.private_exponent))))
        return rsa.exportKey(format='PEM')

    def username(self):
        """Returns the user's preferred username from an acct: url, if available.

        If there's no acct: URL, or if we haven't found their representative
        h-card yet returns their domain.

        Args:
          domain: str
          urls: sequence of str

        Returns: str
        """
        domain = self.key.id()

        if self.actor_as2:
            actor = json_loads(self.actor_as2)
            for url in [u.get('value') if isinstance(u, dict) else u
                        for u in util.get_list(actor, 'url')]:
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

    def user_page_link(self):
        """Returns a pretty user page link with the user's name and profile picture."""
        domain = self.key.id()
        actor = util.json_loads(self.actor_as2) if self.actor_as2 else {}
        name = (actor.get('name') or
                # prettify if domain, noop if username
                util.domain_from_link(self.username()))
        img = util.get_url(actor, 'icon') or ''

        return f'<a href="/user/{domain}"><img src="{img}" class="profile"> {name}</a>'

    def verify(self):
        """Fetches site a couple ways to check for redirects and h-card."""
        domain = self.key.id()
        site = f'https://{domain}/'
        logger.info(f'Verifying {site}')

        # check webfinger redirect
        path = f'/.well-known/webfinger?resource=acct:{domain}@{domain}'
        self.has_redirects = False
        self.redirects_error = None
        try:
            url = urllib.parse.urljoin(site, path)
            resp = util.requests_get(url, gateway=False)
            domain_urls = ([f'https://{domain}/' for domain in common.DOMAINS] +
                           [request.host_url])
            expected = [urllib.parse.urljoin(url, path) for url in domain_urls]
            if resp.ok:
                if resp.url in expected:
                    self.has_redirects = True
                elif resp.url:
                    diff = '\n'.join(difflib.Differ().compare([resp.url], [expected[0]]))
                    self.redirects_error = f'Current vs expected:<pre>{diff}</pre>'
        except requests.RequestException:
            pass

        # check home page
        try:
            self.actor_as2 = json_dumps(common.actor(self.key.id(), user=self))
            self.has_hcard = True
        except (BadRequest, NotFound):
            self.actor_as2 = None
            self.has_hcard = False


class Activity(StringIdModel):
    """A reply, like, repost, or other interaction that we've relayed.

    Key name is 'SOURCE_URL TARGET_URL', e.g. 'http://a/reply http://orig/post'.
    """
    STATUSES = ('new', 'complete', 'error', 'ignored')
    PROTOCOLS = ('activitypub', 'ostatus')
    DIRECTIONS = ('out', 'in')

    # domains of the Bridgy Fed users this activity is to or from
    domain = ndb.StringProperty(repeated=True)
    status = ndb.StringProperty(choices=STATUSES, default='new')
    protocol = ndb.StringProperty(choices=PROTOCOLS)
    direction = ndb.StringProperty(choices=DIRECTIONS)

    # usually only one of these at most will be populated.
    source_mf2 = ndb.TextProperty()  # JSON
    source_as2 = ndb.TextProperty()  # JSON
    source_atom = ndb.TextProperty()
    target_as2 = ndb.TextProperty()  # JSON

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def _get_kind(cls):
        return 'Response'

    def __init__(self, source=None, target=None, **kwargs):
        if source and target:
            assert 'id' not in kwargs
            kwargs['id'] = self._id(source, target)
            logger.info(f"Activity id (source target): {kwargs['id']}")
        super(Activity, self).__init__(**kwargs)

    @classmethod
    def get_or_create(cls, source=None, target=None, **kwargs):
        logger.info(f'Activity source target: {source} {target}')
        return cls.get_or_insert(cls._id(source, target), **kwargs)

    def source(self):
        return self.key.id().split()[0]

    def target(self):
        return self.key.id().split()[1]

    def proxy_url(self):
        """Returns the Bridgy Fed proxy URL to render this post as HTML."""
        if self.source_mf2 or self.source_as2 or self.source_atom:
            source, target = self.key.id().split(' ')
            return f'{request.host_url}render?' + urllib.parse.urlencode({
                'source': source,
                'target': target,
            })

    def to_as1(self):
        """Returns this activity as an ActivityStreams 1 dict, if available."""
        if self.source_mf2:
            mf2 = json_loads(self.source_mf2)
            items = mf2.get('items')
            if items:
                return microformats2.json_to_object(items[0])
        if self.source_as2:
            return as2.to_as1(json_loads(self.source_as2))
        if self.source_atom:
            return atom.atom_to_activity(self.source_atom)

    def actor_link(self, as1=None):
        """Returns a pretty actor link with their name and profile picture."""
        if self.direction == 'out' and self.domain:
            return User.get_by_id(self.domain[0]).user_page_link()

        if not as1:
           as1 = self.to_as1()

        actor = util.get_first(as1, 'actor') or util.get_first(as1, 'author') or {}
        if isinstance(actor, str):
            return util.pretty_link(url)

        url = util.get_first(actor, 'url') or ''
        name = actor.get('displayName') or ''
        image = util.get_url(actor, 'image') or ''
        if not image:
            return util.pretty_link(url, text=name)

        return f"""\
        <a href="{url}" title="{name}">
          <img class="profile" src="{image}" />
          {util.ellipsize(name, chars=40)}
        </a>"""

    @classmethod
    def _id(cls, source, target):
        assert source
        assert target
        return '%s %s' % (cls._encode(source), cls._encode(target))

    @classmethod
    def _encode(cls, val):
        return val.replace('#', '__')

    @classmethod
    def _decode(cls, val):
        return val.replace('__', '#')


class Follower(StringIdModel):
    """A follower of a Bridgy Fed user.

    Key name is 'TO FROM', where each part is either a domain or an AP id, eg:
    'snarfed.org https://mastodon.social/@swentel'.

    Both parts are duplicated in the src and dest properties.
    """
    STATUSES = ('active', 'inactive')

    src = ndb.StringProperty()
    dest = ndb.StringProperty()
    # most recent AP Follow activity (JSON). must have a composite actor object
    # with an inbox, publicInbox, or sharedInbox!
    last_follow = ndb.TextProperty()
    status = ndb.StringProperty(choices=STATUSES, default='active')

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def _id(cls, dest, src):
        assert src
        assert dest
        return '%s %s' % (dest, src)

    @classmethod
    def get_or_create(cls, dest, src, **kwargs):
        logger.info(f'new Follower from {src} to {dest}')
        follower = cls.get_or_insert(cls._id(dest, src), src=src, dest=dest, **kwargs)
        follower.dest = dest
        follower.src = src
        for prop, val in kwargs.items():
            setattr(follower, prop, val)
        follower.put()
        return follower
