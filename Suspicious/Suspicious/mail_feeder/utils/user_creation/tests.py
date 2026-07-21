from unittest.mock import patch
from django.test import TestCase

from .creation import UserCreationService


class CreateUserEmailFieldTests(TestCase):
    """New auto-created reporters must have .email populated, not just
    .username — api/serializers/investigations.py reads reporter.email for
    the "reported by" column."""

    def test_create_user_sets_email(self):
        service = UserCreationService()
        user = service.create_user("jane.doe@meridian.example")
        self.assertEqual(user.email, "jane.doe@meridian.example")

    def test_create_default_user_sets_email(self):
        service = UserCreationService()
        with patch(
            "mail_feeder.utils.user_creation.creation._suspicious_email",
            return_value="suspicious@meridian.example",
        ):
            user = service.create_default_user()
        self.assertEqual(user.email, "suspicious@meridian.example")
