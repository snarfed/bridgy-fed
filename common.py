"""Misc common utilities."""
import datetime

DOMAIN_RE = r'([^/:]+\.[^/:]+)'
TLD_BLOCKLIST = ('7z', 'asp', 'aspx', 'gif', 'html', 'ico', 'jpg', 'jpeg', 'js',
                 'json', 'php', 'png', 'rar', 'txt', 'yaml', 'yml', 'zip')

PRIMARY_DOMAIN = 'at.brid.gy'
OTHER_DOMAINS = (
    'bridgy-at.appspot.com',
    'localhost',
)
DOMAINS = (PRIMARY_DOMAIN,) + OTHER_DOMAINS
# TODO: unify with Bridgy's, Bridgy Fed's
DOMAIN_BLOCKLIST = frozenset((
    'facebook.com',
    'fb.com',
    't.co',
    'twitter.com',
) + DOMAINS)

# alias allows unit tests to mock the function
utcnow = datetime.datetime.utcnow
