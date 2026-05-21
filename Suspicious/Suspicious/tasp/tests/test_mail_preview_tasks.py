"""Tests for the mail-preview Celery tasks.

- render_mail_preview: render+store one mail's preview from its MinIO
  archive. Here we only assert the no-op safety branch (missing mail);
  the render orchestration itself is covered by the helper unit tests
  in mail_feeder/tests/test_preview_jobs.py.
- sweep_missing_mail_previews: the self-healing backfill. We assert the
  real selection query and fan-out, patching only the enqueue boundary.
"""
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from mail_feeder.models import Mail, MailArchive
from tasp.tasks import render_mail_preview, sweep_missing_mail_previews


class RenderMailPreviewTaskTest(TestCase):
    def test_missing_mail_is_a_noop(self):
        # Must not raise / retry when the mail row is gone.
        result = render_mail_preview.apply(args=[999_999]).get()
        self.assertIsNone(result)


class SweepMissingMailPreviewsTest(TestCase):
    def _mail(self, *, key="", bucket=None):
        mail = Mail.objects.create(
            subject="t", date=timezone.now(), preview_object_key=key,
        )
        if bucket is not None:
            MailArchive.objects.create(mail=mail, bucket_name=bucket)
        return mail

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_enqueues_only_fetchable_rows_missing_a_preview(self, delay):
        fetchable = self._mail(key="", bucket="case-bucket")
        self._mail(key="", bucket=None)               # no archive -> skip
        self._mail(key="", bucket="")                 # empty bucket -> skip
        self._mail(key="9.png", bucket="case-bucket")  # already has preview -> skip

        sweep_missing_mail_previews.apply(args=[]).get()

        enqueued = {call.args[0] for call in delay.call_args_list}
        self.assertEqual(enqueued, {fetchable.pk})

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_respects_limit(self, delay):
        for _ in range(3):
            self._mail(key="", bucket="case-bucket")

        sweep_missing_mail_previews.apply(args=[2]).get()

        self.assertEqual(delay.call_count, 2)

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_no_rows_no_enqueue(self, delay):
        self._mail(key="done.png", bucket="case-bucket")

        sweep_missing_mail_previews.apply(args=[]).get()

        delay.assert_not_called()
