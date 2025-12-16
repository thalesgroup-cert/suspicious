from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open
from email.message import EmailMessage
import io
from mail_feeder.global_submission.gsubmission import GlobalSubmissionService
from mail_feeder.global_submission.models import MailSubmissionData
from mail_feeder.global_submission.utils import flatten_id_lists, extract_email_address


class GlobalSubmissionServiceTests(TestCase):

    def _submission(self, submitted=True):
        return MailSubmissionData(
            workdir="/tmp/work",
            filename="mail.eml",
            email_id="email123",
            user="user@example.com",
            is_submitted=submitted,
        )

    @patch("mail_feeder.global_submission.gsubmission.MailInfoService")
    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("builtins.open", new_callable=mock_open)
    def test_process_single_email_web_submission_success(
        self, m_open, m_parse, m_handler, m_mailinfo
    ):
        msg = EmailMessage()
        m_parse.return_value = "parsed-mail"

        instance = MagicMock()
        instance.mail_id = "mid"
        m_handler.return_value.handle_mail.return_value = instance

        service = GlobalSubmissionService()

        with patch.object(service, "finalize_submission") as m_finalize:
            result = service.process_single_email(self._submission(submitted=True))

        self.assertEqual(result, instance)
        m_parse.assert_called_once()
        m_handler.return_value.handle_mail.assert_called_once()
        m_finalize.assert_called_once()
        m_mailinfo.return_value.create_mail_info.assert_called_once_with(instance)

    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService.handle_mail")
    @patch("mail_feeder.global_submission.gsubmission.MailInfoService.create_mail_info")
    def test_process_single_email_minio_submission_success(self, mock_mail_info, mock_handle_mail):
        mock_instance = MagicMock()
        mock_handle_mail.return_value = mock_instance
        submission = self._submission(submitted=False)

        # mock open pour renvoyer BytesIO
        with patch("builtins.open", return_value=io.BytesIO(b"From: a@b.com\nTo: x@y.com\nSubject: test\n\nBody")):
            result = self.service.process_single_email(submission)
            self.assertEqual(result, mock_instance)

    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("builtins.open", new_callable=mock_open)
    def test_process_single_email_handler_failure_returns_none(
        self, m_open, m_parse, m_handler
    ):
        m_parse.return_value = "parsed-mail"
        m_handler.return_value.handle_mail.return_value = None

        service = GlobalSubmissionService()
        result = service.process_single_email(self._submission())

        self.assertIsNone(result)

    @patch.object(GlobalSubmissionService, "_handle_common_tasks")
    def test_finalize_submission(self, m_common):
        service = GlobalSubmissionService()
        instance = MagicMock()
        instance.save = MagicMock()

        config = MagicMock()
        config.user_email = "user@example.com"
        config.workdir = "/tmp/work/email123"

        service.finalize_submission(instance, config)

        self.assertEqual(instance.reportedBy, "user@example.com")
        instance.save.assert_called_once()
        m_common.assert_called_once()

    @patch.object(GlobalSubmissionService, "_handle_common_tasks")
    @patch.object(GlobalSubmissionService, "_extract_reported_by_from_user_submission")
    def test_handle_instance_for_minio(self, m_extract, m_common):
        m_extract.return_value = "minio@example.com"
        service = GlobalSubmissionService()

        instance = MagicMock()
        instance.save = MagicMock()

        service._handle_instance_for_minio(instance, "email123", "/tmp/work")

        self.assertEqual(instance.reportedBy, "minio@example.com")
        instance.save.assert_called_once()
        m_common.assert_called_once()

    @patch("os.listdir")
    def test_list_eml_files(self, m_listdir):
        m_listdir.return_value = [
            "a.eml", "b.eml", "x.txt", "pref_1.eml"
        ]

        service = GlobalSubmissionService()
        result = service.list_eml_files("/tmp", prefix="pref")

        self.assertEqual(result, ["pref_1.eml"])


class GlobalSubmissionUtilsTests(TestCase):

    def test_flatten_id_lists(self):
        result = flatten_id_lists([1, 2], [3], 4)
        self.assertEqual(result, [1, 2, 3, 4])

    def test_extract_email_address_valid(self):
        addr = extract_email_address("Alice <alice@example.com>")
        self.assertEqual(addr, "alice@example.com")

    def test_extract_email_address_invalid(self):
        addr = extract_email_address("invalid")
        self.assertIsNone(addr)
