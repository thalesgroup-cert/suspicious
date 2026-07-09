from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from mail_feeder.models import Mail
from connectors.contrib.thehive.challenge import (
    create_alert_from_challenge,
    create_alert_from_challenge_without_mail,
)


class ChallengeAlertContentTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(username="alert_reporter", password="x")
        self.case = Case.objects.create(
            status="Done", description="", reporter=self.reporter,
            score=10.0, confidence=100.0, results="Dangerous",
            challenge_proposed_result="Safe",
            challenge_reason="This is a newsletter I subscribed to.",
        )
        self.mail = Mail.objects.create(
            subject="s", mail_from="a@b.test", date=timezone.now(), mail_id="test-mail-42",
        )
        self.challenger = {"firstname": "T", "lastname": "B", "email": "t@b.test"}

    def test_alert_description_includes_proposed_result_and_reason(self):
        with patch("connectors.contrib.thehive.challenge.TheHiveApi") as mock_api_cls, \
             patch("connectors.contrib.thehive.challenge.get_s3_client") as mock_s3, \
             patch("connectors.contrib.thehive.challenge.build_mail_attachments_paths", return_value=None):
            mock_s3.return_value.list_buckets.return_value = []
            mock_api = MagicMock()
            mock_api_cls.return_value = mock_api

            create_alert_from_challenge(
                api_url="https://stub", api_key="key",
                case=self.case, mail=self.mail, challenger=self.challenger,
            )

        description = mock_api.alert.create.call_args.kwargs["alert"]["description"]
        self.assertIn("Safe", description)
        self.assertIn("This is a newsletter I subscribed to.", description)

    def test_uses_fetch_mail_files_from_minio_for_eml_content(self):
        with patch("connectors.contrib.thehive.challenge.TheHiveApi") as mock_api_cls, \
             patch("connectors.contrib.thehive.challenge.get_s3_client") as mock_s3, \
             patch(
                 "connectors.contrib.thehive.challenge.fetch_mail_files_from_minio",
                 return_value=("", "raw eml content", "", ""),
             ) as mock_fetch, \
             patch(
                 "connectors.contrib.thehive.challenge.build_mail_attachments_paths",
                 return_value="/tmp/attachments/ticket.eml",
             ) as mock_build_paths:
            mock_api = MagicMock()
            mock_api_cls.return_value = mock_api

            create_alert_from_challenge(
                api_url="https://stub", api_key="key",
                case=self.case, mail=self.mail, challenger=self.challenger,
            )

        mock_fetch.assert_called_once_with(mock_s3.return_value, "test-mail-42")
        mock_build_paths.assert_called_once()
        args, kwargs = mock_build_paths.call_args
        self.assertEqual(args[0], "raw eml content")

    def test_without_mail_alert_description_includes_proposed_result_and_reason(self):
        with patch("connectors.contrib.thehive.challenge.TheHiveApi") as mock_api_cls:
            mock_api = MagicMock()
            mock_api_cls.return_value = mock_api

            create_alert_from_challenge_without_mail(
                api_url="https://stub", api_key="key",
                case=self.case, file=None, ioc="1.2.3.4", datatype="ip",
                challenger=self.challenger,
            )

        description = mock_api.alert.create.call_args.kwargs["alert"]["description"]
        self.assertIn("Safe", description)
        self.assertIn("This is a newsletter I subscribed to.", description)
