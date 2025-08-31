"""Unit tests for dms.py."""
from unittest import mock
from unittest.mock import patch

from atproto import ATProto
import common
from common import memcache
import dms
from dms import maybe_send, receive
import ids
from models import DM, Follower, Object, Target
from web import Web

from oauth_dropins.webutil.flask_util import NotModified
from oauth_dropins.webutil.util import json_dumps, json_loads
from .testutil import ExplicitFake, Fake, OtherFake, TestCase
from .test_atproto import DID_DOC

DM_BASE = {
    'objectType': 'note',
    'id': 'efake:dm',
    'actor': 'efake:alice',
    'to': ['other.brid.gy'],
}

DM_ALICE_REQUESTS_BOB = {
    **DM_BASE,
    'content': ' other:handle:bob ',
}
ALICE_REQUEST_CONFIRMATION = """Got it! We'll send <a class="h-card u-author mention" rel="me" href="web:other:bob" title="other:handle:bob">other:handle:bob</a> a message and say that you hope they'll enable the bridge. Fingers crossed!"""
ALICE_REQUEST_CONTENT = """\
<p>Hi! <a class="h-card u-author mention" rel="me" href="web:other:efake:alice" title="efake:handle:alice &middot; other:handle:efake:handle:alice"><span style="unicode-bidi: isolate">efake:handle:alice</span> &middot; other:handle:efake:handle:alice</a> is using Bridgy Fed to bridge their account from efake-phrase into other-phrase, and they'd like to follow you. You can bridge your account into efake-phrase by following this account. <a href="https://fed.brid.gy/docs">See the docs</a> for more information.
<p>If you do nothing, your account won't be bridged, and users on efake-phrase won't be able to see or interact with you.
<p>Bridgy Fed will only send you this message once."""

DM_ALICE_SET_USERNAME_OTHER = {
    **DM_BASE,
    'content': 'username new-handle',
}
ALICE_USERNAME_CONFIRMATION = 'Your username in other-phrase has been set to <a class="h-card u-author mention" rel="me" href="web:other:efake:alice" title="other:handle:efake:handle:alice">other:handle:efake:handle:alice</a>. It should appear soon!'

DM_ALICE_BLOCK_BOB = {
    **DM_BASE,
    'content': 'block other:handle:bob',
}
ALICE_BLOCK_CONFIRMATION = """OK, you're now blocking <a class="h-card u-author mention" rel="me" href="web:other:bob" title="other:handle:bob">other:handle:bob</a> on other-phrase."""

DM_ALICE_UNBLOCK_BOB = {
    **DM_BASE,
    'content': 'unblock other:handle:bob',
}
ALICE_UNBLOCK_CONFIRMATION = """OK, you're not blocking <a class="h-card u-author mention" rel="me" href="web:other:bob" title="other:handle:bob">other:handle:bob</a> on other-phrase."""

DM_ALICE_MIGRATE = {
    **DM_BASE,
    'content': 'migrate-to other:handle:new-alice',
}
ALICE_MIGRATE_CONFIRMATION = """OK, we'll migrate your bridged account on other-phrase to <a class="h-card u-author mention" rel="me" href="web:other:new-alice" title="other:handle:new-alice">other:handle:new-alice</a>."""

@mock.patch.object(Fake, 'SUPPORTS_DMS', True)
class DmsTest(TestCase):

    def make_alice_bob(self):
        self.make_user(id='efake.brid.gy', cls=Web)
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        bob = self.make_user(id='other:bob', cls=OtherFake, obj_as1={'x': 'y'})
        return alice, bob

    def assert_replied(self, *args, **kwargs):
        kwargs.setdefault('in_reply_to', 'efake:dm')
        self.assert_sent(*args, **kwargs)

    def assert_sent(self, from_cls, tos, type, text, in_reply_to=None, strict=True):
        if not isinstance(tos, list):
            tos = [tos]

        self.assertGreaterEqual(len(tos[-1].sent), len(tos))

        from_id = f'{from_cls.ABBREV}.brid.gy'
        for expected, (target, activity) in zip(tos, tos[-1].sent, strict=strict):
            id = expected.key.id()
            self.assertEqual(f'{id}:target', target)
            content = activity['object'].pop('content')
            if content != text:
                assert content.startswith(text), content
            self.assertEqual({
                'objectType': 'activity',
                'verb': 'post',
                'id': f'https://{from_id}/#bridgy-fed-dm-{type}-{id}-2022-01-02T03:04:05+00:00-create',
                'actor': from_id,
                'object': {
                    'objectType': 'note',
                    'id': f'https://{from_id}/#bridgy-fed-dm-{type}-{id}-2022-01-02T03:04:05+00:00',
                    'author': from_id,
                    'inReplyTo': in_reply_to,
                    'tags': [{'objectType': 'mention', 'url': id}],
                    'published': '2022-01-02T03:04:05+00:00',
                    'to': [id],
                },
                'published': '2022-01-02T03:04:05+00:00',
                'to': [id],
            }, activity)

    def test_maybe_send(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='other:user', cls=OtherFake, obj_as1={'x': 'y'})

        maybe_send(from_proto=Fake, to_user=user, text='hi hi hi',
                   type='replied_to_bridged_user')
        self.assert_sent(Fake, user, 'replied_to_bridged_user', 'hi hi hi')
        expected_sent_dms = [DM(protocol='fake', type='replied_to_bridged_user')]
        self.assertEqual(expected_sent_dms, user.key.get().sent_dms)

        # now that this type is in sent_dms, another attempt should be a noop
        OtherFake.sent = []
        maybe_send(from_proto=Fake, to_user=user, text='hi again',
                   type='replied_to_bridged_user')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual(expected_sent_dms, user.key.get().sent_dms)

    def test_maybe_send_no_type(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='other:user', cls=OtherFake, obj_as1={'x': 'y'})

        maybe_send(from_proto=Fake, to_user=user, text='hi hi hi')
        self.assert_sent(Fake, user, '?', 'hi hi hi')
        self.assertEqual([], user.key.get().sent_dms)

        # another DM without type should also work
        OtherFake.sent = []
        maybe_send(from_proto=Fake, to_user=user, text='hi again')
        self.assert_sent(Fake, user, '?', 'hi again')
        self.assertEqual([], user.key.get().sent_dms)

    def test_maybe_send_user_missing_obj(self):
        self.make_user(id='other.brid.gy', cls=Web)
        user = OtherFake(id='other:user')
        assert not user.obj

        maybe_send(from_proto=OtherFake, to_user=user, text='nope', type='welcome')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], user.sent_dms)

    def test_receive_empty(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user('efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_id='efake:alice')

        obj = Object(our_as1={
            **DM_BASE,
            'content': ' ',
        })
        self.assertEqual((r'¯\_(ツ)_/¯', 204), receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_receive_empty_strip_mention_of_bot(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': '<a href="https://other.brid.gy/other.brid.gy">@other.brid.gy</a> ',
        })
        self.assertEqual(('¯\\_(ツ)_/¯', 204), receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], ExplicitFake.sent)

    def test_receive_unknown_text(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user('efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_id='efake:alice')

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'foo bar baz',
        })
        self.assertEqual(('¯\\_(ツ)_/¯', 204), receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_receive_no_yes_sets_enabled_protocols(self):
        alice = self.make_user('fake:alice', cls=Fake, obj_id='fake:alice')
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        dm = Object(our_as1={
            'objectType': 'note',
            'id': 'efake:dm',
            'actor': 'efake:user',
            'to': ['fa.brid.gy'],
            'content': 'no',
        })

        user = self.make_user('efake:user', cls=ExplicitFake, obj_as1={'x': 'y'})
        self.assertFalse(user.is_enabled(Fake))

        # fake protocol isn't enabled yet, no DM should be a noop
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)

        # "yes" DM should add to enabled_protocols
        dm.our_as1['id'] += '2'
        dm.our_as1['content'] = '<p><a href="...">@bsky.brid.gy</a> yes</p>'
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual(['efake:user'], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))

        # another "yes" DM should be a noop
        dm.our_as1['id'] += '3'
        ExplicitFake.sent = []
        Fake.created_for = []
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))
        self.assert_replied(Fake, user, '?',
                            "Looks like you're already bridged to fake-phrase!",
                            in_reply_to='efake:dm23')

        # "no" DM should remove from enabled_protocols
        Follower.get_or_create(to=user, from_=alice)
        dm.our_as1['id'] += '4'
        dm.our_as1['content'] = '<p><a href="...">@bsky.brid.gy</a>\n  NO \n</p>'
        Fake.sent = []
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertFalse(user.is_enabled(Fake))

        # ...and delete copy actor
        self.assertEqual([('fake:shared:target', {
            'objectType': 'activity',
            'verb': 'delete',
            'id': 'efake:user#bridgy-fed-delete-user-fake-2022-01-02T03:04:05+00:00',
            'actor': 'efake:user',
            'object': 'efake:user',
        })], Fake.sent)

    def test_receive_prompt_sends_request_dm(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, bob, 'request_bridging',
                         ALICE_REQUEST_CONTENT)

    def test_receive_prompt_strips_leading_at_sign(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': '@other:handle:bob',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, bob, 'request_bridging',
                         ALICE_REQUEST_CONTENT)

    def test_receive_prompt_html_link(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': '<a href="http://bob">@other:handle:bob</a>',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, bob, 'request_bridging',
                         ALICE_REQUEST_CONTENT)

    def test_receive_prompt_strip_mention_of_bot(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': '<a href="https://other.brid.gy/other.brid.gy">@other.brid.gy</a> other:handle:bob',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, bob, 'request_bridging', ALICE_REQUEST_CONTENT)

    def test_receive_prompt_strip_mention_of_bot_newline(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': '<p><a href="https://other.brid.gy/other.brid.gy">@other.brid.gy</a></p><p>other:handle:bob</p>',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, bob, 'request_bridging', ALICE_REQUEST_CONTENT)

    def test_receive_prompt_fetch_user(self):
        self.make_user(id='efake.brid.gy', cls=Web)
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        OtherFake.fetchable['other:bob'] = {'x': 'y'}

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_REQUEST_CONFIRMATION)
        self.assert_sent(ExplicitFake, OtherFake(id='other:bob'),
                         'request_bridging', ALICE_REQUEST_CONTENT)
        self.assertEqual(['other:bob'], OtherFake.fetched)

    def test_receive_prompt_user_doesnt_exist(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        OtherFake.fetchable = {}

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', "Couldn't find user other:handle:bob on other-phrase")
        self.assertEqual([], OtherFake.sent)

    @mock.patch.object(OtherFake, 'REQUIRES_NAME', True)
    def test_receive_prompt_user_not_eligible(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        OtherFake.fetchable = {'other:bob': {'a': 'b'}}

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', """<a class="h-card u-author mention" rel="me" href="web:other:bob" title="other:handle:bob">other:handle:bob</a> on other-phrase isn't eligible for bridging into efake-phrase because their account's name and username are the same""")
        self.assertEqual([], OtherFake.sent)

    def test_receive_prompt_from_user_not_bridged(self):
        alice, _ = self.make_alice_bob()
        # not bridged into OtherFake
        alice.enabled_protocols = ['fake']
        alice.put()

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', "Looks like you're not bridged to other-phrase yet!")
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_receive_prompt_already_bridged(self):
        alice, bob = self.make_alice_bob()
        bob.enabled_protocols = ['efake']
        bob.put()

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', """<a class="h-card u-author mention" rel="me" href="web:efake:other:bob" title="other:handle:bob &middot; efake:handle:other:handle:bob"><span style="unicode-bidi: isolate">other:handle:bob</span> &middot; efake:handle:other:handle:bob</a> is already bridged into efake-phrase.""")
        self.assertEqual([], OtherFake.sent)

    def test_receive_prompt_already_requested(self):
        alice, bob = self.make_alice_bob()
        bob.sent_dms = [DM(protocol='efake', type='request_bridging')]
        bob.put()

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', """We've already sent <a class="h-card u-author mention" rel="me" href="web:other:bob" title="other:handle:bob">other:handle:bob</a> a DM. Fingers crossed!""")
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    @mock.patch.object(dms, 'REQUESTS_LIMIT_USER', 2)
    def test_receive_prompt_request_rate_limit(self):
        alice, bob = self.make_alice_bob()
        eve = self.make_user(id='other:eve', cls=OtherFake, obj_as1={'x': 'y'})
        frank = self.make_user(id='other:frank', cls=OtherFake, obj_as1={'x': 'y'})

        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'other:handle:eve',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_sent(ExplicitFake, [bob, eve], 'request_bridging',
                         ALICE_REQUEST_CONTENT)
        self.assertEqual(2, memcache.memcache.get(
            'dm-user-requests-efake-efake:alice'))

        # over the limit
        OtherFake.sent = []
        ExplicitFake.sent = []
        obj = Object(our_as1={
            **DM_BASE,
            'content': 'other:handle:frank',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assert_replied(OtherFake, alice, '?', "Sorry, you've hit your limit of 2 requests per day. Try again tomorrow!")
        self.assertEqual(3, memcache.memcache.get(
            'dm-user-requests-efake-efake:alice'))

    def test_receive_prompt_wrong_protocol(self):
        self.make_user(id='other.brid.gy', cls=Web)
        user = self.make_user('fake:user', cls=Fake, obj_as1={'x': 'y'})

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'fake:eve',
        })
        self.assertEqual(('OK', 200), receive(from_user=user, obj=obj))
        self.assertEqual([], ExplicitFake.sent)
        self.assertEqual([], OtherFake.sent)
        self.assert_replied(OtherFake, user, '?', "Couldn't find user fake:eve on other-phrase")

    @mock.patch('ids.translate_handle', side_effect=ValueError('nope'))
    def test_receive_prompt_not_supported_in_target_protocol(self, _):
        alice, bob = self.make_alice_bob()
        obj = Object(our_as1=DM_ALICE_REQUESTS_BOB)

        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', "Sorry, Bridgy Fed doesn't yet support bridging handle other:handle:bob from other-phrase to efake-phrase.")
        self.assertEqual([], OtherFake.sent)

    def test_receive_username(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})

        obj = Object(our_as1=DM_ALICE_SET_USERNAME_OTHER)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_USERNAME_CONFIRMATION)
        self.assertEqual({'efake:alice': 'new-handle'}, OtherFake.usernames)

    def test_receive_username_strip_invisible_chars(self):
        # https://github.com/snarfed/bridgy-fed/issues/1936
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})

        obj = Object(our_as1={
            **DM_BASE,
            'content': json_loads(r'"username \u202anew\u202d-handle\u202c"'),
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_USERNAME_CONFIRMATION)
        self.assertEqual({'efake:alice': 'new-handle'}, OtherFake.usernames)

    def test_receive_username_no_arg(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})

        self.assertEqual(('OK', 200), receive(from_user=alice, obj=Object(our_as1={
            **DM_BASE,
            'content': 'username',
        })))
        self.assert_replied(OtherFake, alice, '?',
                            'username command needs an argument')

    def test_receive_username_not_implemented(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['fake'], obj_as1={'x': 'y'})

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'username fake:handle:alice',
            'to': ['fa.brid.gy'],
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(Fake, alice, '?', "Sorry, Bridgy Fed doesn't support custom usernames for fake-phrase yet.")

    @mock.patch.object(OtherFake, 'set_username', side_effect=RuntimeError('nopey'))
    def test_receive_username_fails(self, _):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})

        obj = Object(our_as1=DM_ALICE_SET_USERNAME_OTHER)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', 'nopey')
        self.assertEqual({}, OtherFake.usernames)

    def test_receive_help(self):
        for command in 'help', 'hello', '?':
            ExplicitFake.sent = []
            self.make_user(id='other.brid.gy', cls=Web)
            alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                                   enabled_protocols=['other'], obj_as1={'x': 'y'})
            obj = Object(our_as1={
                **DM_BASE,
                'content': command,
            })
            self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
            self.assert_replied(OtherFake, alice, '?', "<p>Hi! I'm a friendly bot")
            self.assertEqual({}, OtherFake.usernames)

    def test_receive_help_strip_mention_of_bot(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})

        for content in (
                '@other.brid.gy help',
                'other.brid.gy@other.brid.gy help',
                '@other.brid.gy@other.brid.gy help',
                'https://other.brid.gy/other.brid.gy help',
        ):
            ExplicitFake.sent = []
            with self.subTest(content=content):
                obj = Object(our_as1={
                    **DM_BASE,
                    'content': content,
                })
                self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
                self.assert_replied(OtherFake, alice, '?', "<p>Hi! I'm a friendly bot")

    def test_receive_help_atproto_plain_text(self):
        self.store_object(id='did:plc:123', raw=DID_DOC)
        self.store_object(id='did:plc:999', raw=DID_DOC)

        self.make_user(id='other.brid.gy', cls=Web, enabled_protocols=['atproto'],
                       copies=[Target(protocol='atproto', uri='did:plc:999')])
        alice = self.make_user(id='did:plc:123', cls=ATProto, obj_bsky={
            '$type': 'app.bsky.actor.profile',
            'displayName': 'alice'
        })
        obj = Object(our_as1={
            'objectType': 'note',
            'id': 'at://did:plc:123/msg/abc',
            'actor': 'did:plc:123',
            'content': 'help',
            'to': ['other.brid.gy'],
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        reply = Object.get_by_id('https://other.brid.gy/#bridgy-fed-dm-?-did:plc:123-2022-01-02T03:04:05+00:00')
        self.assertIn('start: enable bridging for your account', reply.as1['content'])

    def test_receive_did_atproto(self):
        for content in 'did', 'did foo':
            ExplicitFake.sent = []
            with self.subTest(content=content):
                self.make_user(id='bsky.brid.gy', cls=Web)
                alice = self.make_user(id='efake:alice', cls=ExplicitFake,
                                       enabled_protocols=['atproto'], obj_as1={'x': 'y'},
                                       copies=[Target(protocol='atproto', uri='did:abc:123')])
                obj = Object(our_as1={
                    **DM_BASE,
                    'to': ['bsky.brid.gy'],
                    'content': 'did',
                })
                self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
                self.assert_replied(ATProto, alice, '?',
                                    'Your DID is <code>did:abc:123</code>')

    def test_receive_notify(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake, obj_as1={'x': 'y'},
                               enabled_protocols=['other'], send_notifs='none')

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'notify',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', 'Notifications enabled!')
        self.assertEqual('all', ExplicitFake.get_by_id('efake:alice').send_notifs)

    def test_receive_mute(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='efake:alice', cls=ExplicitFake, obj_as1={'x': 'y'},
                               enabled_protocols=['other'], send_notifs='all')

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'mute',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', 'Notifications disabled.')
        self.assertEqual('none', ExplicitFake.get_by_id('efake:alice').send_notifs)

    def test_receive_block(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1=DM_ALICE_BLOCK_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_replied(OtherFake, alice, '?', ALICE_BLOCK_CONFIRMATION)

        block_as1 = {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'efake:alice#bridgy-fed-block-2022-01-02T03:04:05+00:00',
            'actor': 'efake:alice',
            'object': 'other:bob',
        }
        self.assert_object(id='efake:alice#bridgy-fed-block-2022-01-02T03:04:05+00:00',
                           our_as1=block_as1, source_protocol='efake',
                           ignore=['copies'])
        self.assertEqual([('other:bob:target', block_as1)], OtherFake.sent)

    def test_receive_block_handle_at_symbol(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_ALICE_BLOCK_BOB,
            'content': ' block @other:handle:bob ',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_replied(OtherFake, alice, '?', ALICE_BLOCK_CONFIRMATION)
        self.assertEqual([('other:bob:target', {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'efake:alice#bridgy-fed-block-2022-01-02T03:04:05+00:00',
            'actor': 'efake:alice',
            'object': 'other:bob',
        })], OtherFake.sent)

    def test_receive_block_id(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_ALICE_BLOCK_BOB,
            'content': 'block other:bob',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_replied(OtherFake, alice, '?', ALICE_BLOCK_CONFIRMATION)
        self.assertEqual([('other:bob:target', {
            'objectType': 'activity',
            'verb': 'block',
            'id': 'efake:alice#bridgy-fed-block-2022-01-02T03:04:05+00:00',
            'actor': 'efake:alice',
            'object': 'other:bob',
        })], OtherFake.sent)

    def test_receive_unblock(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1=DM_ALICE_UNBLOCK_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assert_replied(OtherFake, alice, '?', ALICE_UNBLOCK_CONFIRMATION)

        unblock_as1 = {
            'objectType': 'activity',
            'verb': 'undo',
            'id': 'efake:alice#bridgy-fed-unblock-2022-01-02T03:04:05+00:00',
            'actor': 'efake:alice',
            'object': {
                'objectType': 'activity',
                'verb': 'block',
                'actor': 'efake:alice',
                'object': 'other:bob',
            },
        }
        self.assert_object(id='efake:alice#bridgy-fed-unblock-2022-01-02T03:04:05+00:00',
                           our_as1=unblock_as1, source_protocol='efake',
                           ignore=['copies'])
        self.assertEqual([('other:bob:target', unblock_as1)], OtherFake.sent)

    def test_receive_migrate_to(self):
        alice, bob = self.make_alice_bob()
        OtherFake.fetchable = {'other:new-alice': {'url': 'http://new/alice'}}

        obj = Object(our_as1=DM_ALICE_MIGRATE)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', ALICE_MIGRATE_CONFIRMATION)
        self.assertEqual([(alice, 'other:new-alice')], OtherFake.migrated_out)

    def test_receive_migrate_to_no_handle_arg(self):
        alice, bob = self.make_alice_bob()

        obj = Object(our_as1={
            **DM_BASE,
            'content': 'migrate-to ',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?',
                            'migrate-to command needs an argument')
        self.assertEqual([], OtherFake.migrated_out)

    def test_receive_DM_recipient_in_cc_instead_of_to(self):
        # eg this is evidently how https://neodb.net/ sends DMs, with the recipient
        # in cc instead of to
        obj = Object(our_as1={
            'objectType': 'note',
            'id': 'efake:dm',
            'actor': 'efake:alice',
            'cc': ['other.brid.gy'],
            'content': 'help',
        })
        alice, bob = self.make_alice_bob()

        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assert_replied(OtherFake, alice, '?', "<p>Hi! I'm a friendly bot")
