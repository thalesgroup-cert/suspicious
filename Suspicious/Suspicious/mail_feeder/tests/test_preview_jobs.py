"""Unit tests for the shared mail-preview (re)generation helper.

The helper orchestrates: locate the mail's MinIO archive -> fetch the
.eml -> render PNG -> stamp (bucket, key) on the row. All IO is injected
(`fetch_eml` callable + `renderer` object) so these tests exercise the
real branching/temp-file logic with in-memory fakes, never a live MinIO
or wkhtmltopdf.
"""
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from mail_feeder.models import Mail, MailArchive
from mail_feeder.utils.email_preview.preview_jobs import (
    enqueue_preview_render,
    regenerate_mail_preview,
)


class FakeRenderer:
    """Stand-in for Eml2PngRenderer.

    `render_eml_path_to_png_bytes` asserts the helper actually wrote the
    fetched bytes to a temp file on disk; `save_preview_to_mail` mimics
    the real MinIO upload by stamping (bucket, key) on the row.
    """

    def __init__(self, png=b"PNGDATA"):
        self.png = png

    def render_eml_path_to_png_bytes(self, path):
        assert path.exists(), "helper must write the eml to a real temp file"
        assert path.read_bytes(), "temp file should contain the fetched eml bytes"
        return self.png

    def save_preview_to_mail(self, mail, png_bytes):
        mail.preview_bucket = "mail-previews"
        mail.preview_object_key = f"{mail.pk}.png"
        mail.save(update_fields=["preview_bucket", "preview_object_key"])


class RegenerateMailPreviewTest(TestCase):
    def _mail(self):
        return Mail.objects.create(subject="t", date=timezone.now())

    def test_skips_when_no_archive(self):
        mail = self._mail()
        outcome = regenerate_mail_preview(
            mail, fetch_eml=lambda a: b"x", renderer=FakeRenderer(),
        )
        self.assertEqual(outcome, "skipped")
        self.assertEqual(mail.preview_object_key, "")

    def test_skips_when_archive_bucket_empty(self):
        mail = self._mail()
        MailArchive.objects.create(mail=mail, bucket_name="")
        outcome = regenerate_mail_preview(
            mail, fetch_eml=lambda a: b"x", renderer=FakeRenderer(),
        )
        self.assertEqual(outcome, "skipped")

    def test_skips_when_eml_bytes_empty(self):
        mail = self._mail()
        MailArchive.objects.create(mail=mail, bucket_name="case-bucket")
        outcome = regenerate_mail_preview(
            mail, fetch_eml=lambda a: b"", renderer=FakeRenderer(),
        )
        self.assertEqual(outcome, "skipped")

    def test_failed_when_fetch_raises(self):
        mail = self._mail()
        MailArchive.objects.create(mail=mail, bucket_name="case-bucket")

        def boom(_archive):
            raise RuntimeError("minio down")

        outcome = regenerate_mail_preview(
            mail, fetch_eml=boom, renderer=FakeRenderer(),
        )
        self.assertEqual(outcome, "failed")

    def test_failed_when_renderer_returns_none(self):
        mail = self._mail()
        MailArchive.objects.create(mail=mail, bucket_name="case-bucket")
        outcome = regenerate_mail_preview(
            mail, fetch_eml=lambda a: b"eml", renderer=FakeRenderer(png=None),
        )
        self.assertEqual(outcome, "failed")
        self.assertEqual(mail.preview_object_key, "")

    def test_ok_stamps_preview_key_and_passes_bucket_to_fetch(self):
        mail = self._mail()
        MailArchive.objects.create(mail=mail, bucket_name="case-bucket")
        seen = {}

        def fetch(archive):
            seen["bucket"] = archive.bucket_name
            return b"raw eml bytes"

        outcome = regenerate_mail_preview(mail, fetch_eml=fetch, renderer=FakeRenderer())

        self.assertEqual(outcome, "ok")
        self.assertEqual(seen["bucket"], "case-bucket")
        mail.refresh_from_db()
        self.assertEqual(mail.preview_object_key, f"{mail.pk}.png")
        self.assertEqual(mail.preview_bucket, "mail-previews")


class EnqueuePreviewRenderTest(TestCase):
    """Lazy on-miss enqueue used by MailPreviewView, deduped via the cache."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_enqueues_once_within_dedup_window(self, delay):
        self.assertTrue(enqueue_preview_render(5))
        self.assertFalse(enqueue_preview_render(5))
        delay.assert_called_once_with(5)

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_distinct_mails_each_enqueue(self, delay):
        self.assertTrue(enqueue_preview_render(1))
        self.assertTrue(enqueue_preview_render(2))
        self.assertEqual(delay.call_count, 2)

    @patch("tasp.tasks.render_mail_preview.delay")
    def test_window_expiry_allows_reenqueue(self, delay):
        self.assertTrue(enqueue_preview_render(9))
        cache.clear()
        self.assertTrue(enqueue_preview_render(9))
        self.assertEqual(delay.call_count, 2)
