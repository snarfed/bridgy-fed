"""Old, now-unused Activity model, stored as MagicKey in the datastore.

Replaced by Object.
"""

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

    # TODO: uncomment
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def _get_kind(cls):
        return 'Response'

    def source(self):
        return self.key.id().split()[0]

    def target(self):
        return self.key.id().split()[1]

    def to_as1(self):
        """Returns this activity as an ActivityStreams 1 dict, if available."""
        if self.source_mf2:
            mf2 = json_loads(self.source_mf2)
            items = mf2.get('items')
            if items:
                mf2 = items[0]
            return microformats2.json_to_object(mf2)
        if self.source_as2:
            return as2.to_as1(json_loads(self.source_as2))
        if self.source_atom:
            return atom.atom_to_activity(self.source_atom)
