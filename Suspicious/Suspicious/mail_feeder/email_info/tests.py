from django.test import TestCase
from unittest.mock import patch, MagicMock
from mail_feeder.email_info.email_info import MailInfoService
from mail_feeder.email_info.models import MailInstanceModel, MailInfoData

from django.test import SimpleTestCase
from pydantic import ValidationError

class MailInstanceModelTests(SimpleTestCase):

    def test_valid_mail_instance(self):
        model = MailInstanceModel(
            reportedBy="user@test.com",
            times_sent=2
        )
        self.assertEqual(model.times_sent, 2)

    def test_invalid_email(self):
        with self.assertRaises(ValidationError):
            MailInstanceModel(
                reportedBy="not-an-email",
                times_sent=1
            )

    def test_invalid_times_sent(self):
        with self.assertRaises(ValidationError):
            MailInstanceModel(
                reportedBy="user@test.com",
                times_sent=0
            )


class MailInfoDataTests(SimpleTestCase):

    def test_default_values(self):
        data = MailInfoData(
            user_email="user@test.com",
            mail_id="123"
        )
        self.assertTrue(data.is_received)
        self.assertFalse(data.is_phishing)

class MailInfoServiceTests(TestCase):

    def setUp(self):
        self.user_creator = MagicMock()
        self.user = MagicMock()
        self.user_creator.get_or_create_user.return_value = self.user
        self.service = MailInfoService(user_creator=self.user_creator)

        self.mail_instance = MagicMock()
        self.mail_instance.reportedBy = "User <user@test.com>"
        self.mail_instance.times_sent = 5

    def test_validate_mail_instance(self):
        validated = self.service._validate_mail_instance(self.mail_instance)
        self.assertIsInstance(validated, MailInstanceModel)
        self.assertEqual(validated.reportedBy, "user@test.com")

    def test_extract_origin_email(self):
        email = self.service._extract_origin_email("User <user@test.com>")
        self.assertEqual(email, "user@test.com")

    def test_build_mail_info_data_not_phishing(self):
        mail = MailInstanceModel(reportedBy="user@test.com", times_sent=3)
        data = self.service._build_mail_info_data(mail, "user@test.com")
        self.assertFalse(data.is_phishing)

    def test_build_mail_info_data_phishing(self):
        mail = MailInstanceModel(reportedBy="user@test.com", times_sent=15)
        data = self.service._build_mail_info_data(mail, "user@test.com")
        self.assertTrue(data.is_phishing)

    @patch("mail_feeder.email_info.email_info.MailInfo")
    def test_save_mail_info(self, mock_mailinfo):
        instance = MagicMock()
        mock_mailinfo.return_value = instance

        data = MailInfoData(
            user_email="user@test.com",
            mail_id="123",
            is_received=True,
            is_phishing=False
        )

        result = self.service._save_mail_info(data, self.mail_instance)

        self.user_creator.get_or_create_user.assert_called_once_with("user@test.com")
        instance.save.assert_called_once()
        self.assertEqual(result, instance)

    @patch("mail_feeder.email_info.email_info.user_acknowledge")
    def test_acknowledge_user_success(self, mock_ack):
        mail_info = MagicMock()
        self.service._acknowledge_user(mail_info)
        mock_ack.assert_called_once_with(mail_info)

    @patch("mail_feeder.email_info.email_info.user_acknowledge")
    def test_acknowledge_user_failure_is_swallowed(self, mock_ack):
        mock_ack.side_effect = Exception("SMTP down")
        mail_info = MagicMock()

        # must NOT raise
        self.service._acknowledge_user(mail_info)

    @patch("mail_feeder.email_info.email_info.MailInfo")
    @patch("mail_feeder.email_info.email_info.user_acknowledge")
    def test_create_mail_info_happy_path(self, mock_ack, mock_mailinfo):
        instance = MagicMock()
        mock_mailinfo.return_value = instance

        self.service.create_mail_info(self.mail_instance)

        self.user_creator.get_or_create_user.assert_called_once()
        instance.save.assert_called_once()
        mock_ack.assert_called_once()
