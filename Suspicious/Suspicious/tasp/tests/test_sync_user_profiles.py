from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from tasp.cron.user_and_cases import sync_user_profiles


class SyncUserProfilesTest(TestCase):
    """P5 regression: sync_user_profiles must only sync active accounts
    so LDAP is not pinged for disabled users and the full User table is
    not loaded per cron tick.
    """

    def setUp(self):
        User = get_user_model()
        User.objects.create_user(username="active1", password="x", is_active=True)
        User.objects.create_user(username="active2", password="x", is_active=True)
        User.objects.create_user(username="inactive1", password="x", is_active=False)

    @patch("tasp.cron.user_and_cases.Ldap.create_user")
    def test_only_active_users_are_synced(self, mock_create):
        sync_user_profiles()
        synced = {call.args[0].username for call in mock_create.call_args_list}
        self.assertEqual(synced, {"active1", "active2"})
