"""Unit tests for dms.py."""
from unittest import mock

from common import memcache
import dms
from dms import maybe_send, receive
from models import DM, Follower, Object
from web import Web

from .testutil import ExplicitEnableFake, Fake, OtherFake, TestCase

DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB = {
    'objectType': 'note',
    'id': 'eefake:dm',
    'actor': 'eefake:alice',
    'to': ['other.brid.gy'],
    'content': ' other:handle:bob ',
}


class DmsTest(TestCase):
    def make_alice_bob(self):
        self.make_user(id='eefake.brid.gy', cls=Web)
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='eefake:alice', cls=ExplicitEnableFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        bob = self.make_user(id='other:bob', cls=OtherFake, obj_as1={'x': 'y'})
        return alice, bob

    def test_maybe_send(self):
        self.make_user(id='fa.brid.gy', cls=Web)
        user = self.make_user(id='other:user', cls=OtherFake, obj_as1={'x': 'y'})

        maybe_send(from_proto=Fake, to_user=user, text='hi hi hi',
                   type='replied_to_bridged_user')
        self.assertEqual([
            ('https://fa.brid.gy/#replied_to_bridged_user-dm-other:user-2022-01-02T03:04:05+00:00',
             'other:user:target'),
        ], OtherFake.sent)
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
        self.assertEqual([
            ('https://fa.brid.gy/#?-dm-other:user-2022-01-02T03:04:05+00:00',
             'other:user:target'),
        ], OtherFake.sent)
        self.assertEqual([], user.key.get().sent_dms)

        # another DM without type should also work
        OtherFake.sent = []
        maybe_send(from_proto=Fake, to_user=user, text='hi again')
        self.assertEqual([
            ('https://fa.brid.gy/#?-dm-other:user-2022-01-02T03:04:05+00:00',
             'other:user:target'),
        ], OtherFake.sent)
        self.assertEqual([], user.key.get().sent_dms)

    def test_maybe_send_user_missing_obj(self):
        self.make_user(id='other.brid.gy', cls=Web)
        user = OtherFake(id='other:user')
        assert not user.obj

        maybe_send(from_proto=OtherFake, to_user=user, text='nope', type='welcome')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], user.sent_dms)

    def test_receive_unknown_text(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user('eefake:alice', cls=ExplicitEnableFake,
                               enabled_protocols=['other'], obj_id='eefake:alice')

        obj = Object(our_as1={
            **DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB,
            'content': 'foo bar',
        })
        self.assertEqual(("Couldn't understand DM: foo bar", 304),
                         receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_receive_no_yes_sets_enabled_protocols(self):
        alice = self.make_user('fake:alice', cls=Fake, obj_id='fake:alice')
        # bot user
        self.make_user('fa.brid.gy', cls=Web)

        dm = Object(our_as1={
            'objectType': 'note',
            'id': 'eefake:dm',
            'actor': 'eefake:user',
            'to': ['fa.brid.gy'],
            'content': 'no',
        })

        user = self.make_user('eefake:user', cls=ExplicitEnableFake)
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
        self.assertEqual(['eefake:user'], Fake.created_for)
        self.assertTrue(user.is_enabled(Fake))

        # another "yes" DM should be a noop
        dm.our_as1['id'] += '3'
        Fake.created_for = []
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual(['fake'], user.enabled_protocols)
        self.assertTrue(user.is_enabled(Fake))
        self.assertEqual([], Fake.created_for)

        # "no" DM should remove from enabled_protocols
        Follower.get_or_create(to=user, from_=alice)
        dm.our_as1['id'] += '4'
        dm.our_as1['content'] = '<p><a href="...">@bsky.brid.gy</a>\n  NO \n</p>'
        self.assertEqual(('OK', 200), receive(from_user=user, obj=dm))
        user = user.key.get()
        self.assertEqual([], user.enabled_protocols)
        self.assertEqual([], Fake.created_for)
        self.assertFalse(user.is_enabled(Fake))

        # ...and delete copy actor
        self.assertEqual(
            [('eefake:user#delete-copy-fake-2022-01-02T03:04:05+00:00',
              'fake:shared:target')],
            Fake.sent)

    def test_receive_handle_sends_request_dm(self):
        alice, _ = self.make_alice_bob()

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual(
            [('https://eefake.brid.gy/#request_bridging-dm-other:bob-2022-01-02T03:04:05+00:00',
              'other:bob:target')],
            OtherFake.sent)

    def test_receive_handle_fetch_user(self):
        self.make_user(id='eefake.brid.gy', cls=Web)
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='eefake:alice', cls=ExplicitEnableFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        OtherFake.fetchable['other:bob'] = {'x': 'y'}

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual(
            [('https://eefake.brid.gy/#request_bridging-dm-other:bob-2022-01-02T03:04:05+00:00',
              'other:bob:target')],
            OtherFake.sent)

    def test_receive_handle_user_doesnt_exist(self):
        self.make_user(id='other.brid.gy', cls=Web)
        alice = self.make_user(id='eefake:alice', cls=ExplicitEnableFake,
                               enabled_protocols=['other'], obj_as1={'x': 'y'})
        OtherFake.fetchable = {}

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual([], OtherFake.sent)

    def test_receive_handle_from_user_not_bridged(self):
        alice, _ = self.make_alice_bob()
        # not bridged into OtherFake
        alice.enabled_protocols = ['fake']
        alice.put()

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    def test_receive_handle_already_bridged(self):
        alice, bob = self.make_alice_bob()
        bob.enabled_protocols = ['eefake']
        bob.put()

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual([], OtherFake.sent)

    def test_receive_handle_already_requested(self):
        alice, bob = self.make_alice_bob()
        bob.sent_dms = [DM(protocol='eefake', type='request_bridging')]
        bob.put()

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)

    @mock.patch.object(dms, 'REQUESTS_LIMIT_USER', 2)
    def test_receive_handle_request_rate_limit(self):
        alice, bob = self.make_alice_bob()
        eve = self.make_user(id='other:eve', cls=OtherFake, obj_as1={'x': 'y'})
        frank = self.make_user(id='other:frank', cls=OtherFake, obj_as1={'x': 'y'})

        obj = Object(our_as1=DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB)
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        obj = Object(our_as1={
            **DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB,
            'content': 'other:handle:eve',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))

        self.assertEqual([
            ('https://eefake.brid.gy/#request_bridging-dm-other:bob-2022-01-02T03:04:05+00:00',
              'other:bob:target'),
            ('https://eefake.brid.gy/#request_bridging-dm-other:eve-2022-01-02T03:04:05+00:00',
              'other:eve:target'),
        ], OtherFake.sent)
        self.assertEqual(2, memcache.get('dm-user-requests-eefake-eefake:alice'))

        # over the limit
        OtherFake.sent = []
        ExplicitEnableFake.sent = []
        obj = Object(our_as1={
            **DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB,
            'content': 'other:handle:frank',
        })
        self.assertEqual(('OK', 200), receive(from_user=alice, obj=obj))
        self.assertEqual([], OtherFake.sent)
        self.assertEqual(
            [('https://other.brid.gy/#?-dm-eefake:alice-2022-01-02T03:04:05+00:00',
              'eefake:alice:target')],
            ExplicitEnableFake.sent)
        self.assertEqual(3, memcache.get('dm-user-requests-eefake-eefake:alice'))


    def test_receive_handle_wrong_protocol(self):
        self.make_user(id='other.brid.gy', cls=Web)

        obj = Object(our_as1={
            **DM_EEFAKE_ALICE_REQUESTS_OTHER_BOB,
                             'content': 'fake:eve',
        })
        self.assertEqual(("Couldn't understand DM: foo bar", 304),
                         receive(from_user=Fake(id='fake:user'), obj=obj))
        self.assertEqual([], ExplicitEnableFake.sent)
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], Fake.sent)
