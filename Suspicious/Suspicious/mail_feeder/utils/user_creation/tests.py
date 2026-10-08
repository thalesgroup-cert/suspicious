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


class ReporterResolutionTests(TestCase):
    """Emailed reporters with subdomain addresses must get their own user,
    not the shared default one."""

    def _service(self):
        with patch("mail_feeder.utils.user_creation.creation._own_domains", return_value=["corp.example"]):
            return UserCreationService()

    def setUp(self):
        patcher = patch("mail_feeder.utils.user_creation.creation.create_ldap_user")
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch(
            "mail_feeder.utils.user_creation.creation._suspicious_email",
            return_value="suspicious@corp.example",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_subdomain_sender_gets_a_real_user(self):
        user = self._service().get_or_create_user("jane.doe@uk.corp.example")
        self.assertEqual(user.username, "jane.doe@uk.corp.example")
        self.assertEqual(user.email, "jane.doe@uk.corp.example")

    def test_unknown_domain_falls_back_to_the_shared_user_and_names_the_sender(self):
        with self.assertLogs("tasp.cron.fetch_and_process_emails", "WARNING") as logs:
            user = self._service().get_or_create_user("stranger@elsewhere.example")
        self.assertEqual(user.username, "suspicious@corp.example")
        self.assertTrue(any("stranger@elsewhere.example" in line for line in logs.output))
