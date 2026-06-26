"""A single malformed email in a submission must not abort the whole batch.

Before the per-email guard, a parse failure (e.g. EmailDataModel rejecting a
missing From) propagated out of the email loop, aborted the remaining emails,
and rolled the submission back to `todo` — so the cron retried the poisoned
submission forever. Each email is now processed in isolation: failures are
logged and skipped, the rest proceed.
"""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from mail_feeder.minio_submission.minio import MinioEmailService


class PerEmailResilienceTests(TestCase):
    @patch("mail_feeder.minio_submission.minio._resolve_user")
    @patch("mail_feeder.minio_submission.minio.glo")
    def test_one_bad_email_does_not_abort_submission(self, mock_glo, mock_resolve):
        mock_resolve.return_value = MagicMock(email="rep@corp.test")
        inst = MagicMock()
        inst.list_eml_files.return_value = ["bad.eml", "good.eml"]
        # First email blows up (e.g. ValidationError), second succeeds.
        inst.process_single_email.side_effect = [ValueError("missing From"), None]
        mock_glo.return_value = inst

        # Must not raise despite the first email failing.
        MinioEmailService().process_emails_from_minio_workdir(
            workdir="/tmp/x/sub-1", bucket_name="b", reported_by="rep@corp.test",
        )

        # Both emails were attempted (the bad one did not short-circuit the good one).
        self.assertEqual(inst.process_single_email.call_count, 2)
