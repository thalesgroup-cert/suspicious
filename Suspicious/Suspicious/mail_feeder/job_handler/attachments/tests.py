from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from mail_feeder.job_handler.attachments.attachments import AttachmentJobLauncherService


class AttachmentDispatchPendingTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.reporter = User.objects.create_user(
            username="attachment_dispatch_user", password="x"
        )
        self.case = Case.objects.create(
            status="On Going", description="", reporter=self.reporter
        )
        self.service = AttachmentJobLauncherService()
        self.file = MagicMock(name="file_model")
        self.hash = MagicMock(name="hash_model")
        self.service.pending_dispatch_intents = [
            (self.file, "file"),
            (self.hash, "hash"),
        ]

    @patch("mail_feeder.job_handler.attachments.attachments.CortexJob")
    def test_dispatches_file_and_hash_with_case(self, mock_cortex_cls):
        mock_cortex = mock_cortex_cls.return_value
        mock_cortex.launch_cortex_jobs.return_value = [1, 2]
        result = self.service.dispatch_pending(self.case)

        self.assertEqual(mock_cortex.launch_cortex_jobs.call_count, 2)
        mock_cortex.launch_cortex_jobs.assert_any_call(self.file, "file", case=self.case)
        mock_cortex.launch_cortex_jobs.assert_any_call(self.hash, "hash", case=self.case)
        self.assertEqual(self.service.pending_dispatch_intents, [])
        # Each call returns [1, 2] → result is [1, 2, 1, 2]
        self.assertEqual(sorted(result), [1, 1, 2, 2])

    @patch("mail_feeder.job_handler.attachments.attachments.CortexJob")
    def test_exception_swallowed_intents_cleared(self, mock_cortex_cls):
        mock_cortex_cls.return_value.launch_cortex_jobs.side_effect = Exception("boom")
        result = self.service.dispatch_pending(self.case)
        self.assertEqual(result, [])
        self.assertEqual(self.service.pending_dispatch_intents, [])
