"""Unit tests for nostr.py."""
from unittest.mock import patch

from flask_app import app
import ids
from ids import translate_handle, translate_object_id, translate_user_id
from models import Target
from nostr import Nostr
from .testutil import Fake, TestCase


class NostrTest(TestCase):

    def setUp(self):
        common.RUN_TASKS_INLINE = False
