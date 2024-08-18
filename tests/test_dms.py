"""Unit tests for dms.py."""
from dms import maybe_send
from models import DM
from web import Web

from .testutil import Fake, OtherFake, TestCase


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
