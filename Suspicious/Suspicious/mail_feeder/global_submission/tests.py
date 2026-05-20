from unittest import TestCase
from unittest.mock import patch, MagicMock, mock_open
from io import BytesIO

import django.test

from mail_feeder.global_submission.gsubmission import GlobalSubmissionService
from mail_feeder.global_submission.models import MailSubmissionData
from mail_feeder.global_submission.utils import flatten_id_lists, extract_email_address


def _make_handlers_mock(mock_handlers_cls):
    """
    Module-level helper that builds a Handlers mock with the expected return shapes:
      - handle_artifacts -> ArtifactJobLauncherService-like mock (has dispatch_pending)
      - handle_attachments -> AttachmentDispatchResult-like mock (has .services, .ai_archive)
      - handle_mail_header -> list of intents
      - handle_mail_body -> list of intents
    """
    handlers = mock_handlers_cls.return_value

    artifact_service = MagicMock()
    artifact_service.dispatch_pending = MagicMock()
    handlers.handle_artifacts.return_value = artifact_service

    attachment_result = MagicMock()
    attachment_result.services = []
    attachment_result.ai_archive = None
    handlers.handle_attachments.return_value = attachment_result

    handlers.handle_mail_header.return_value = []
    handlers.handle_mail_body.return_value = []

    return handlers


class GlobalSubmissionServiceTests(TestCase):

    def setUp(self):
        self.service = GlobalSubmissionService()

    def _submission(self, submitted=False):
        return MailSubmissionData(
            email_id="test-email-id",
            filename="mail.eml",
            workdir="/tmp/workdir",
            user="user@test.com",
            bucket_name=None,
            is_submitted=submitted
        )

    def _make_handlers_mock(self, mock_handlers_cls):
        return _make_handlers_mock(mock_handlers_cls)

    # =========================
    # Web submission
    # =========================
    @patch("mail_feeder.global_submission.gsubmission.MailInfoService")
    @patch.object(GlobalSubmissionService, "_handle_common_tasks")
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
        mock_common_tasks,
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
    @patch.object(GlobalSubmissionService, "_handle_instance_for_minio")
    @patch("mail_feeder.global_submission.gsubmission.EmailHandlerService")
    @patch("mail_feeder.global_submission.gsubmission.parse_email")
    @patch("mail_feeder.global_submission.gsubmission.email.message_from_binary_file")
    @patch("builtins.open")
    def test_process_single_email_minio_submission_success(
        self,
        mock_open,
        mock_msg_from_binary,
        mock_parse_email,
        mock_email_handler_cls,
        mock_minio_handler,
        mock_mail_info
    ):
        mock_open.return_value = BytesIO(b"raw email")

        submission = self._submission(submitted=False)

        fake_instance = MagicMock()
        fake_instance.mail_id = "mail-db-id"
        fake_instance.reportedBy = None

        mock_msg_from_binary.return_value = MagicMock()
        mock_parse_email.return_value = "parsed-mail"
        mock_email_handler_cls.return_value.handle_mail.return_value = fake_instance

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

        self.service._handle_instance_for_minio(instance, "email123", "/tmp/work", "")

        self.assertEqual(instance.reportedBy, "minio@example.com")
        instance.save.assert_called_once()
        m_common.assert_called_once()

    # =========================
    # list_eml_files
    # =========================
    @patch("os.listdir")
    def test_list_eml_files(self, m_listdir):
        m_listdir.return_value = ["a.eml", "b.eml", "x.txt", "pref_1.eml"]

        # list_eml_files excludes files that START WITH the prefix
        result = self.service.list_eml_files("/tmp", prefix="pref")

        self.assertEqual(result, ["a.eml", "b.eml"])


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


class HandleCommonTasksOrderingTest(django.test.TestCase):
    """Verify dispatch happens strictly after Case creation."""

    @patch("mail_feeder.global_submission.gsubmission.CortexJob")
    @patch("mail_feeder.global_submission.gsubmission.CaseCreatorService")
    @patch("mail_feeder.global_submission.gsubmission.UserCreationService")
    @patch("mail_feeder.global_submission.gsubmission.Handlers")
    def test_create_case_runs_before_dispatch_pending(
        self, mock_handlers_cls, mock_user_cls, mock_case_cls, mock_cortex_cls
    ):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        real_user = User.objects.create_user(username="ordering_test_user", password="x")

        # Setup: Handlers() returns the mock helper shape
        handlers_mock = _make_handlers_mock(mock_handlers_cls)
        mock_user_cls.return_value.get_or_create_user.return_value = real_user

        order_log = []
        fake_case = MagicMock()
        fake_case.id = 42
        mock_case_cls.return_value.create_case.side_effect = lambda *a, **kw: (
            order_log.append("create_case") or fake_case
        )

        artifact_svc = handlers_mock.handle_artifacts.return_value
        artifact_svc.dispatch_pending.side_effect = lambda case: order_log.append("artifact_dispatch")

        # Add one attachment service
        att_svc = MagicMock()
        att_svc.dispatch_pending.side_effect = lambda case: order_log.append("attachment_dispatch")
        handlers_mock.handle_attachments.return_value.services = [att_svc]

        service = GlobalSubmissionService()
        instance = MagicMock()
        instance.reportedBy = "x@example.com"
        instance.mail_id = "m1"
        service._handle_common_tasks(instance, "email-1", "mail.zip", "bucket")

        self.assertEqual(order_log[0], "create_case")
        self.assertIn("artifact_dispatch", order_log[1:])
        self.assertIn("attachment_dispatch", order_log[1:])
