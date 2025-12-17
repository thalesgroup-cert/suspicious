from django.test import TestCase
from unittest.mock import patch, MagicMock
from mail_feeder.email_handler.email_handler import EmailHandlerService
from mail_feeder.email_handler.models import EmailDataModel
from mail_feeder.models import Mail


class EmailHandlerServiceTests(TestCase):

    def setUp(self):
        self.service = EmailHandlerService()
        self.data = EmailDataModel(
            id="mail-123",
            reportedText="hello",
            headers={"k": "v"},
            sender="a@test.com",
            subject="test"
        )

    def test_email_data_model_invalid_id(self):
        with self.assertRaises(ValueError):
            EmailDataModel(id="   ")

    @patch("mail_feeder.email_handler.email_handler.Mail.objects.filter")
    def test_check_existing_data_none(self, mock_filter):
        mock_filter.return_value = []
        body = self.service._check_existing_data(self.data)
        self.assertEqual(body[0], [])

    @patch("mail_feeder.email_handler.email_handler.increment_field")
    @patch("mail_feeder.email_handler.email_handler.EmailObservablesService.handle_rich_observables")
    @patch("mail_feeder.email_handler.email_handler.Mail.objects.get")
    @patch("mail_feeder.email_handler.email_handler.Mail.objects.filter")
    @patch("mail_feeder.email_handler.email_handler.EmailService.create_mail_instance")
    def test_handle_new_mail_success(
        self, mock_create, mock_filter, mock_get, mock_obs, mock_inc
    ):
        mock_filter.return_value = []

        mail_instance = MagicMock(spec=Mail)
        mail_instance.mail_id = "mail-123"

        mock_create.return_value = MagicMock(
            success=True,
            mail_id=1
        )
        mock_get.return_value = mail_instance

        result = self.service.handle_mail(self.data, "/tmp")

        self.assertEqual(result, mail_instance)
        mock_obs.assert_called_once()
        mock_inc.assert_called_once_with(mail_instance, "times_sent")

    @patch("mail_feeder.email_handler.email_handler.EmailService.create_mail_instance")
    def test_handle_new_mail_creation_failure(self, mock_create):
        mock_create.return_value = None
        result = self.service.handle_mail(self.data, "/tmp")
        self.assertIsNone(result)

    @patch("mail_feeder.email_handler.email_handler.Mail.objects.get")
    @patch("mail_feeder.email_handler.email_handler.EmailService.create_mail_instance")
    def test_handle_new_mail_unsuccessful(self, mock_create, mock_get):
        mock_create.side_effect = Exception("boom")
        mock_get.return_value = MagicMock(mail_id=1)

        result = self.service.handle_mail(self.data, "/tmp")
        self.assertIsNone(result)

    @patch("mail_feeder.email_handler.email_handler.Mail.objects.filter")
    @patch("mail_feeder.email_handler.email_handler.EmailService.create_mail_instance")
    def test_handle_existing_mail_path(self, mock_create, mock_filter):
        existing_mail = MagicMock(spec=Mail)
        mock_filter.return_value = [existing_mail]
        mock_create.return_value = MagicMock(success=True, mail_id=1)

        with patch.object(self.service, "_update_existing_mail") as upd:
            upd.return_value = existing_mail
            result = self.service.handle_mail(self.data, "/tmp")

        self.assertIsNotNone(result)

    @patch("mail_feeder.email_handler.email_handler.EmailService.create_mail_instance")
    def test_handle_mail_exception_propagates(self, mock_create):
        mock_create.side_effect = Exception("boom")
        result = self.service.handle_mail(self.data, "/tmp")
        self.assertIsNone(result)