from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasNonFileIocs
from connectors.contrib.thehive.challenge import ChallengeToTheHiveService
from url_process.models import URL


class ChallengeAlertRoutingTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="route_u", password="x", first_name="T", last_name="B", email="t@b.test",
        )

    def _service_for(self, case):
        service = ChallengeToTheHiveService.__new__(ChallengeToTheHiveService)
        service.case = case
        service.recipient = None
        service.subject = "irrelevant"
        service.challenger_firstname = case.reporter.first_name
        service.challenger_lastname = case.reporter.last_name
        service.challenger_email = case.reporter.email
        service.challenger_groups = []
        return service

    def test_comments_on_existing_alert_when_thehive_alert_id_set(self):
        case = Case.objects.create(
            description="", reporter=self.user, thehive_alert_id="~alert-999",
            challenge_proposed_result="Safe", challenge_reason="looks like spam",
        )
        service = self._service_for(case)

        with patch("connectors.contrib.thehive.challenge.add_comment_to_item") as mock_comment, \
             patch("connectors.contrib.thehive.challenge_alert.send_challenge_alert") as mock_new_alert, \
             patch("connectors.contrib.thehive.challenge.create_alert_from_challenge_without_mail") as mock_new_alert_nomail:
            service.send_to_thehive()

        mock_comment.assert_called_once()
        args, kwargs = mock_comment.call_args
        self.assertEqual(args[0], "alert")
        self.assertEqual(args[1], "~alert-999")
        self.assertIn("Safe", args[2]["message"])
        self.assertIn("looks like spam", args[2]["message"])
        self.assertTrue(kwargs.get("always_append"))
        mock_new_alert.assert_not_called()
        mock_new_alert_nomail.assert_not_called()

    def test_creates_new_alert_when_no_thehive_alert_id(self):
        case = Case.objects.create(description="", reporter=self.user)
        service = self._service_for(case)

        with patch("connectors.contrib.thehive.challenge.add_comment_to_item") as mock_comment, \
             patch("connectors.contrib.thehive.challenge.ChallengeToTheHiveService._send_thehive_without_mail") as mock_no_mail:
            service.send_to_thehive()

        mock_comment.assert_not_called()
        mock_no_mail.assert_called_once()

    def test_new_alert_id_is_saved_on_case(self):
        """Regression: creating a new alert must persist its id onto the case
        so a follow-up challenge/comment lands on the same alert instead of
        creating another one — previously thehive_alert_id stayed empty forever."""
        url = URL.objects.create(address="http://evil.example")
        case = Case.objects.create(description="", reporter=self.user)
        CaseHasNonFileIocs.objects.create(case=case, url=url)
        case.nonFileIocs = CaseHasNonFileIocs.objects.get(case=case)
        service = self._service_for(case)

        with patch("connectors.contrib.thehive.challenge.add_comment_to_item") as mock_comment, \
             patch(
                 "connectors.contrib.thehive.challenge.create_alert_from_challenge_without_mail",
                 return_value={"_id": "~new-alert-123"},
             ) as mock_new_alert_nomail:
            service.send_to_thehive()

        mock_comment.assert_not_called()
        mock_new_alert_nomail.assert_called_once()
        case.refresh_from_db()
        self.assertEqual(case.thehive_alert_id, "~new-alert-123")

    def test_falls_back_to_a_basic_alert_when_the_full_one_cannot_be_built(self):
        mail = type("Mail", (), {"subject": "Urgent invoice"})()
        case = Case.objects.create(description="", reporter=self.user, challenge_proposed_result="Dangerous",
                                   challenge_reason="phishing for sure")
        service = self._service_for(case)

        with patch("connectors.contrib.thehive.connector._email_settings", side_effect=RuntimeError("boom")), \
             patch("connectors.contrib.thehive.challenge.create_alert_from_challenge_without_mail",
                   return_value={"_id": "~basic"}) as basic:
            service._send_thehive_with_mail("http://hive", "key", case, mail, {})

        self.assertEqual(basic.call_args.kwargs["ioc"], "Urgent invoice")
        self.assertEqual(basic.call_args.kwargs["datatype"], "mail-subject")
        case.refresh_from_db()
        self.assertEqual(case.thehive_alert_id, "~basic")

    def test_a_failed_basic_alert_is_raised_so_the_task_can_retry(self):
        mail = type("Mail", (), {"subject": "Urgent invoice"})()
        case = Case.objects.create(description="", reporter=self.user, challenge_proposed_result="Dangerous",
                                   challenge_reason="phishing for sure")
        service = self._service_for(case)

        with patch("connectors.contrib.thehive.connector._email_settings", side_effect=RuntimeError("boom")), \
             patch("connectors.contrib.thehive.challenge.create_alert_from_challenge_without_mail",
                   side_effect=ConnectionError("thehive down")):
            with self.assertRaises(ConnectionError):
                service._send_thehive_with_mail("http://hive", "key", case, mail, {})
