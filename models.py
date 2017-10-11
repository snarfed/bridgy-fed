"""Datastore model classes.

Based on webfinger-unofficial/user.py.
"""
import urllib

from Crypto.PublicKey import RSA
from django_salmon import magicsigs
from google.appengine.ext import ndb
from oauth_dropins.webutil.models import StringIdModel

import appengine_config


class MagicKey(StringIdModel):
    """Stores a user's public/private key pair used for Magic Signatures.

    The key name is the domain.

    The modulus and exponent properties are all encoded as base64url (ie URL-safe
    base64) strings as described in RFC 4648 and section 5.1 of the Magic
    Signatures spec.

    Magic Signatures are used to sign Salmon slaps. Details:
    http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html
    http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-salmon-00.html
    """
    mod = ndb.StringProperty(required=True)
    public_exponent = ndb.StringProperty(required=True)
    private_exponent = ndb.StringProperty(required=True)

    @staticmethod
    @ndb.transactional
    def get_or_create(domain):
        """Loads and returns a MagicKey. Creates it if necessary."""
        key = MagicKey.get_by_id(domain)

        if not key:
            # this uses urandom(), and does nontrivial math, so it can take a
            # while depending on the amount of randomness available.
            pubexp, mod, privexp = magicsigs.generate()
            key = MagicKey(id=domain, mod=mod, public_exponent=pubexp,
                           private_exponent=privexp)
            key.put()

        return key

    def href(self):
        return 'data:application/magic-public-key,RSA.%s.%s' % (
            self.mod, self.public_exponent)

    def public_pem(self):
        rsa = RSA.construct((magicsigs.base64_to_long(str(self.mod)),
                             magicsigs.base64_to_long(str(self.public_exponent))))
        return rsa.exportKey(format='PEM')

    def private_pem(self):
        rsa = RSA.construct((magicsigs.base64_to_long(str(self.mod)),
                             magicsigs.base64_to_long(str(self.public_exponent)),
                             magicsigs.base64_to_long(str(self.private_exponent))))
        return rsa.exportKey(format='PEM')


class Response(StringIdModel):
    """A reply, like, repost, or other interaction that we've relayed.

    Key name is 'SOURCE_URL TARGET_URL', e.g. 'http://a/reply http://orig/post'.
    """
    STATUSES = ('new', 'complete', 'error')
    PROTOCOLS = ('activitypub', 'ostatus')
    DIRECTIONS = ('out', 'in')

    status = ndb.StringProperty(choices=STATUSES, default='new')
    protocol = ndb.StringProperty(choices=PROTOCOLS)
    direction = ndb.StringProperty(choices=DIRECTIONS)

    # usually only one of these at most will be populated.
    source_mf2 = ndb.TextProperty()  # JSON
    source_as2 = ndb.TextProperty()  # JSON
    source_atom = ndb.TextProperty()

    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    def proxy_url(self):
        """Returns the Bridgy Fed proxy URL to render this response as HTML."""
        if self.source_mf2 or self.source_as2:
            source, target = self.key.id().split(' ')
            return '%s/render?%s' % (appengine_config.HOST_URL, urllib.urlencode({
                'source': source,
                'target': target,
            }))
