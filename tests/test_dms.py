"""Unit tests for dms.py."""
from dms import maybe_send, receive
from models import DM, Follower, Object
from web import Web

from .testutil import ExplicitEnableFake, Fake, OtherFake, TestCase


class DmsTest(TestCase):
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

    def test_maybe_send_user_missing_obj(self):
        self.make_user(id='other.brid.gy', cls=Web)
        user = OtherFake(id='other:user')
        assert not user.obj

        maybe_send(from_proto=OtherFake, to_user=user, text='nope', type='welcome')
        self.assertEqual([], OtherFake.sent)
        self.assertEqual([], user.sent_dms)

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
