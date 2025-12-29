"""Utilities for working with DNS domain names."""
import re
from urllib.parse import urljoin, urlparse

from flask import request
from oauth_dropins.webutil.appengine_info import DEBUG, LOCAL_SERVER
from oauth_dropins.webutil import util

# allow hostname chars (a-z, 0-9, -), allow arbitrary unicode (eg ☃.net), don't
# allow specific chars that we'll often see in webfinger, AP handles, etc. (@, :)
# https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
#
# TODO: preprocess with domain2idna, then narrow this to just [a-z0-9-]
# TODO: unify with oauth_dropins.webutil.util.DOMAIN_RE?
DOMAIN_RE = re.compile(r'([^/:;@?!\'.]+\.)+[^/:@_?!\'.]+')

# populated in models.reset_protocol_properties
SUBDOMAIN_BASE_URL_RE = None

PRIMARY_DOMAIN = 'fed.brid.gy'
# protocol-specific subdomains are under this "super"domain
SUPERDOMAIN = '.brid.gy'
# TODO: add a Flask route decorator version of util.canonicalize_domain, then
# use it to canonicalize most UI routes from these to fed.brid.gy.
# TODO: unify with models.PROTOCOLS
PROTOCOL_DOMAINS = (
    'ap.brid.gy',
    'atproto.brid.gy',
    'bsky.brid.gy',
    'nostr.brid.gy',
    'web.brid.gy',
)
if DEBUG:
    PROTOCOL_DOMAINS += (
        'efake.brid.gy',
        'fa.brid.gy',
        'other.brid.gy',
    )
OTHER_DOMAINS = (
    'bridgy-federated.appspot.com',
    'bridgy-federated.uc.r.appspot.com',
)
LOCAL_DOMAINS = (
  'localhost',
  'localhost:8080',
  'my.dev.com:8080',
)
DOMAINS = (PRIMARY_DOMAIN,) + PROTOCOL_DOMAINS + OTHER_DOMAINS + LOCAL_DOMAINS
# TODO: unify with manual_opt_out
# TODO: unify with Bridgy's
DOMAIN_BLOCKLIST = (
    'bsky.social',
    'facebook.com',
    'fb.com',
    'instagram.com',
    'reddit.com',
    'rumble.com',  # serves infinite HTTP 307 redirects to GCP
    't.co',
    'tiktok.com',
    'twitter.com',
    'x.com',
    'youtu.be',
    'youtube.com',
)

# canaries that Seirdy inserts into their blocklists
# https://seirdy.one/posts/2023/05/02/fediverse-blocklists/#important-modifications-before-importing
DOMAIN_BLOCKLIST_CANARIES = (
    '000delete.this.line.if.you.have.read.the.documentation.on.seirdy.one',
    'canary.tier1.example.com',
    'canary.tier0.example.com',
    'canary.fedinuke.example.com',
)

# domains that we allow to post as the protocol bot accounts
# https://github.com/snarfed/bridgy-fed/#how-to-post-as-the-protocol-bot-accounts-apbridgy-bskybridgy-etc
BLOG_REDIRECT_DOMAINS = (
    'snarfed.org',

    # would be nice to have 'blog.anew.social' here too! but we're currently on
    # their default theme, which doesn't have microformats:
    # https://indieweb.org/Ghost#Rejected_microformats2_markup_in_default_theme
    # ...also it's usually nicer to write custom microblog posts, instead of posting
    # the blog post itself, which will usually get rendered as just the title and link
)


def redirect_wrap(url, domain=None):
    """Returns a URL on our domain that redirects to this URL.

    ...to satisfy Mastodon's non-standard domain matching requirement. :(

    Args:
      url (str)
      domain (str): optional Bridgy Fed domain to use. Must be in :attr:`DOMAINS`

    * https://github.com/snarfed/bridgy-fed/issues/16#issuecomment-424799599
    * https://github.com/tootsuite/mastodon/pull/6219#issuecomment-429142747

    Returns:
      str: redirect url
    """
    if not url or util.domain_from_link(url) in DOMAINS:
        return url

    path = '/r/' + url

    if domain:
        assert domain in DOMAINS, (domain, url)
        return urljoin(f'https://{domain}/', path)

    return host_url(path)


def subdomain_wrap(proto, path=None):
    """Returns the URL for a given path on this protocol's subdomain.

    Eg for the path ``foo/bar`` on ActivityPub, returns
    ``https://ap.brid.gy/foo/bar``.

    Args:
      proto (subclass of :class:`protocol.Protocol`)

    Returns:
      str: URL
    """
    subdomain = proto.ABBREV if proto and proto.ABBREV else 'fed'
    return urljoin(f'https://{subdomain}{SUPERDOMAIN}/', path)


def unwrap(val, field=None):
    """Removes our subdomain/redirect wrapping from a URL, if it's there.

    ``val`` may be a string, dict, or list. dicts and lists are unwrapped
    recursively.

    Strings that aren't wrapped URLs are left unchanged.

    Args:
      val (str or dict or list)
      field (str): optional field name for this value

    Returns:
      str: unwrapped url
    """
    id_fields = ('id', 'object', 'actor', 'author', 'inReplyTo', 'url')

    if isinstance(val, dict):
        # TODO: clean up. https://github.com/snarfed/bridgy-fed/issues/967
        id = val.get('id')
        if (isinstance(id, str)
                and urlparse(id).path.strip('/') in DOMAINS + ('',)
                and util.domain_from_link(id) in DOMAINS):
            # protocol bot user, don't touch its URLs
            return {**val, 'id': unwrap(id)}

        return {f: unwrap(v, field=f) for f, v in val.items()}

    elif isinstance(val, list):
        return [unwrap(v) for v in val]

    elif isinstance(val, str):
        if match := SUBDOMAIN_BASE_URL_RE.match(val):
            unwrapped = match.group('path')
            if field in id_fields and DOMAIN_RE.fullmatch(unwrapped):
                return f'https://{unwrapped}/'
            return unwrapped

    return val


def host_url(path_query=None):
    base = request.host_url
    if (util.domain_or_parent_in(request.host, OTHER_DOMAINS)
            # when running locally against prod datastore
            or (not DEBUG and request.host in LOCAL_DOMAINS)):
        base = f'https://{PRIMARY_DOMAIN}'

    assert base
    return urljoin(base, path_query)
