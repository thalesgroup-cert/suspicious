from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open
from io import BytesIO, StringIO

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService
from mail_feeder.global_submission.models import MailSubmissionData
from mail_feeder.global_submission.utils import flatten_id_lists, extract_email_address


class GlobalSubmissionServiceTests(TestCase):

    def setUp(self):
        self.service = GlobalSubmissionService()

    def _submission(self, submitted=False):
        return MailSubmissionData(
            email_id="test-email-id",
            filename="mail.eml",
            workdir="/tmp/workdir",
            user="user@test.com",
            is_submitted=submitted
        )

    # =========================
    # Web submission
    # =========================
    @patch("mail_feeder.global_submission.gsubmission.MailInfoService")
    @patch("mail_feeder.global_submission.gsubmission.Handlers")
    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("mail_feeder.global_submission.gsubmission.email.message_from_binary_file")
    @patch("builtins.open")
    def test_process_single_email_web_submission_success(
        self,
        mock_open,
        mock_msg_from_binary,
        mock_parse_email,
        mock_email_handler_cls,
        mock_handlers_cls,
        mock_mail_info
    ):
        mock_open.return_value = BytesIO(b"raw email")

        submission = self._submission(submitted=True)

        fake_instance = MagicMock()
        fake_instance.mail_id = "mail-db-id"
        fake_instance.reportedBy = None

        mock_msg_from_binary.return_value = MagicMock()
        mock_parse_email.return_value = "parsed-mail"
        mock_email_handler_cls.return_value.handle_mail.return_value = fake_instance

        handlers = mock_handlers_cls.return_value
        handlers.handle_artifacts.return_value = ["a1"]
        handlers.handle_attachments.return_value.ids = ["att1"]
        handlers.handle_attachments.return_value.ai_ids = []

        result = self.service.process_single_email(submission)

        self.assertEqual(result, fake_instance)
        mock_mail_info.return_value.create_mail_info.assert_called_once_with(fake_instance)

    # =========================
    # Handler failure
    # =========================
    @patch.object(GlobalSubmissionService, "finalize_submission")
    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("mail_feeder.global_submission.gsubmission.email.message_from_binary_file")
    @patch("builtins.open", new_callable=mock_open, read_data=b"raw email")
    def test_process_single_email_handler_failure_returns_none(
        self,
        mock_open_file,
        mock_msg_from_file,
        mock_parse_email,
        mock_email_handler_cls,
        mock_finalize,
    ):
        submission = self._submission(submitted=True)

        mock_msg_from_file.return_value = MagicMock()
        mock_parse_email.return_value = "parsed-mail"
        mock_email_handler_cls.return_value.handle_mail.return_value = None

        result = self.service.process_single_email(submission)

        self.assertIsNone(result)
        mock_finalize.assert_not_called()


    # =========================
    # MinIO submission
    # =========================
    @patch("mail_feeder.global_submission.gsubmission.MailInfoService")
    @patch("mail_feeder.global_submission.gsubmission.Handlers")
    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("mail_feeder.global_submission.gsubmission.email.message_from_file")
    @patch("mail_feeder.global_submission.gsubmission.email.message_from_binary_file")
    @patch("builtins.open")
    def test_process_single_email_minio_submission_success(
        self,
        mock_open,
        mock_msg_from_binary,
        mock_msg_from_file,
        mock_parse_email,
        mock_email_handler_cls,
        mock_handlers_cls,
        mock_mail_info
    ):
        def open_side_effect(*args, **kwargs):
            if "rb" in kwargs.get("mode", "rb"):
                return BytesIO(b"raw email")
            return StringIO("From: user@test.com\n")

        mock_open.side_effect = open_side_effect

        submission = self._submission(submitted=False)

        fake_instance = MagicMock()
        fake_instance.mail_id = "mail-db-id"
        fake_instance.reportedBy = None

        mock_msg_from_binary.return_value = MagicMock()
        mock_msg_from_file.return_value = MagicMock(
            get=lambda k: "user@test.com" if k == "From" else None
        )

        mock_parse_email.return_value = "parsed-mail"
        mock_email_handler_cls.return_value.handle_mail.return_value = fake_instance

        handlers = mock_handlers_cls.return_value
        handlers.handle_artifacts.return_value = ["a1"]
        handlers.handle_attachments.return_value.ids = ["att1"]
        handlers.handle_attachments.return_value.ai_ids = []

        result = self.service.process_single_email(submission)

        self.assertEqual(result, fake_instance)
        mock_mail_info.return_value.create_mail_info.assert_called_once_with(fake_instance)

    # =========================
    # finalize_submission
    # =========================
    @patch.object(GlobalSubmissionService, "_handle_common_tasks")
    def test_finalize_submission(self, m_common):
        instance = MagicMock()
        instance.save = MagicMock()

        config = MagicMock()
        config.user_email = "user@example.com"
        config.workdir = "/tmp/work/email123"

        self.service.finalize_submission(instance, config)

        self.assertEqual(instance.reportedBy, "user@example.com")
        instance.save.assert_called_once()
        m_common.assert_called_once()

    # =========================
    # MinIO helper
    # =========================
    @patch.object(GlobalSubmissionService, "_handle_common_tasks")
    @patch.object(GlobalSubmissionService, "_extract_reported_by_from_user_submission")
    def test_handle_instance_for_minio(self, m_extract, m_common):
        m_extract.return_value = "minio@example.com"

        instance = MagicMock()
        instance.save = MagicMock()

        self.service._handle_instance_for_minio(instance, "email123", "/tmp/work")

        self.assertEqual(instance.reportedBy, "minio@example.com")
        instance.save.assert_called_once()
        m_common.assert_called_once()

    # =========================
    # list_eml_files
    # =========================
    @patch("os.listdir")
    def test_list_eml_files(self, m_listdir):
        m_listdir.return_value = ["a.eml", "b.eml", "x.txt", "pref_1.eml"]

        result = self.service.list_eml_files("/tmp", prefix="pref")

        self.assertEqual(result, ["pref_1.eml"])


class GlobalSubmissionUtilsTests(TestCase):

    def test_flatten_id_lists(self):
        self.assertEqual(flatten_id_lists([1, 2], [3], 4), [1, 2, 3, 4])

    def test_extract_email_address_valid(self):
        self.assertEqual(
            extract_email_address("Alice <alice@example.com>"),
            "alice@example.com"
        )

    def test_extract_email_address_invalid(self):
        self.assertIsNone(extract_email_address("invalid"))
