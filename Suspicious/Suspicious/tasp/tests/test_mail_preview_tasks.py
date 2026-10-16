"""Tests for the mail-preview Celery tasks.

- render_mail_preview: render+store one mail's preview from its MinIO
  archive. Here we only assert the no-op safety branch (missing mail);
  the render orchestration itself is covered by the helper unit tests
  in mail_feeder/tests/test_preview_jobs.py.
- sweep_missing_mail_previews: the self-healing backfill. We assert the
  real selection query and fan-out, patching only the enqueue boundary.
"""
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from mail_feeder.models import Mail, MailArchive
from tasp.tasks import (
    _PREVIEW_COOLDOWN_TTL,
    _preview_cooldown_key,
    render_mail_preview,
    sweep_missing_mail_previews,
)

_REGEN = "mail_feeder.utils.email_preview.preview_jobs.regenerate_mail_preview"
_STORAGE = "mail_feeder.utils.email_preview.preview_jobs.build_storage_client"


class RenderMailPreviewTaskTest(TestCase):
    def setUp(self):
        cache.clear()

    def _mail(self):
        return Mail.objects.create(subject="t", date=timezone.now())

    def test_missing_mail_is_a_noop(self):
        result = render_mail_preview.apply(args=[999_999]).get()
        self.assertIsNone(result)

    @patch(_REGEN, return_value="skipped")
    @patch(_STORAGE)
    def test_skipped_outcome_sets_cooldown(self, _storage, _regen):
        mail = self._mail()
        render_mail_preview.apply(args=[mail.pk]).get()
        self.assertTrue(cache.get(_preview_cooldown_key(mail.pk)))

    @patch(_REGEN, return_value="ok")
    @patch(_STORAGE)
    def test_ok_outcome_sets_no_cooldown(self, _storage, _regen):
        mail = self._mail()
        render_mail_preview.apply(args=[mail.pk]).get()
        self.assertIsNone(cache.get(_preview_cooldown_key(mail.pk)))

    @patch(_REGEN, return_value="failed")
    @patch(_STORAGE)
    def test_failed_render_retries_before_cooling_down(self, _storage, regen):
        mail = self._mail()
        with patch.object(render_mail_preview, "retry", side_effect=RuntimeError("retry")):
            result = render_mail_preview.apply(args=[mail.pk], retries=0, throw=False)
        self.assertTrue(result.failed())
        self.assertIsNone(cache.get(_preview_cooldown_key(mail.pk)))

    @patch(_REGEN, return_value="failed")
    @patch(_STORAGE)
    def test_exhausted_retries_set_cooldown(self, _storage, regen):
        mail = self._mail()
        with patch.object(render_mail_preview, "retry", side_effect=RuntimeError("retry")):
            render_mail_preview.apply(
                args=[mail.pk], retries=render_mail_preview.max_retries, throw=False,
            )
        self.assertTrue(cache.get(_preview_cooldown_key(mail.pk)))

    @patch(_REGEN)
    @patch(_STORAGE)
    def test_cooldown_short_circuits_render(self, _storage, regen):
        mail = self._mail()
        cache.set(_preview_cooldown_key(mail.pk), 1, _PREVIEW_COOLDOWN_TTL)
        render_mail_preview.apply(args=[mail.pk]).get()
        regen.assert_not_called()


class SweepMissingMailPreviewsTest(TestCase):
    def setUp(self):
        cache.clear()

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
        self._mail(key="", bucket=None)
        self._mail(key="", bucket="")
        self._mail(key="9.png", bucket="case-bucket")

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
    def test_cooling_rows_are_skipped_and_do_not_use_up_the_limit(self, delay):
        stuck = self._mail(key="", bucket="case-bucket")
        fresh = self._mail(key="", bucket="case-bucket")
        cache.set(_preview_cooldown_key(stuck.pk), 1, _PREVIEW_COOLDOWN_TTL)

        sweep_missing_mail_previews.apply(args=[1]).get()

        enqueued = {call.args[0] for call in delay.call_args_list}
        self.assertEqual(enqueued, {fresh.pk})

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_no_rows_no_enqueue(self, delay):
        self._mail(key="done.png", bucket="case-bucket")

        sweep_missing_mail_previews.apply(args=[]).get()

        delay.assert_not_called()
