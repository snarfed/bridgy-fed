"""Datastore model classes.

Based on webfinger-unofficial/user.py.
"""
from django_salmon import magicsigs
from google.appengine.ext import ndb
from oauth_dropins.webutil.models import StringIdModel


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
    def get_or_create(uri):
        """Loads and returns a MagicKey. Creates it if necessary."""
        key = MagicKey.get_by_id(uri)

        if not key:
            # this uses urandom(), and does nontrivial math, so it can take a
            # while depending on the amount of randomness available.
            pubexp, mod, privexp = magicsigs.generate()
            key = MagicKey(id=uri, mod=mod, public_exponent=pubexp,
                           private_exponent=privexp)
            key.put()

        return key

    def href(self):
        return 'data:application/magic-public-key,RSA.%s.%s' % (
            self.mod, self.public_exponent)
