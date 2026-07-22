"""Unit tests for the mail-preview MinIO bucket sweep.

All MinIO access is mocked — these tests exercise the age/size matching
logic and the "never touch the Mail row" contract, never a live bucket.
"""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from mail_feeder.utils.email_preview.retention import purge_mail_previews


def _fake_object(name, size, last_modified):
    obj = mock.MagicMock()
    obj.object_name = name
    obj.size = size
    obj.last_modified = last_modified
    return obj


class PurgeMailPreviewsTest(SimpleTestCase):
    def _client(self, objects):
        client = mock.MagicMock()
        client.bucket_exists.return_value = True
        client.list_objects.return_value = objects
        return client

    def test_requires_at_least_one_criterion(self):
        with self.assertRaises(ValueError):
            purge_mail_previews()

    def test_deletes_objects_older_than_cutoff(self):
        now = timezone.now()
        old = _fake_object("1.png", 1000, now - timedelta(days=100))
        recent = _fake_object("2.png", 1000, now - timedelta(days=1))
        client = self._client([old, recent])

        with mock.patch(
            "mail_feeder.utils.email_preview.retention.get_s3_client",
            return_value=client,
        ):
            result = purge_mail_previews(older_than_days=90)

        client.remove_object.assert_called_once_with("mail-previews", "1.png")
        self.assertEqual(result.deleted_count, 1)
        self.assertEqual(result.deleted_bytes, 1000)

    def test_deletes_objects_over_size_regardless_of_age(self):
        now = timezone.now()
        big_recent = _fake_object("1.png", 20 * 1024 * 1024, now)
        small_recent = _fake_object("2.png", 1000, now)
        client = self._client([big_recent, small_recent])

        with mock.patch(
            "mail_feeder.utils.email_preview.retention.get_s3_client",
            return_value=client,
        ):
            result = purge_mail_previews(min_size_mb=15)

        client.remove_object.assert_called_once_with("mail-previews", "1.png")
        self.assertEqual(result.deleted_count, 1)

    def test_dry_run_never_calls_remove_object(self):
        now = timezone.now()
        old = _fake_object("1.png", 1000, now - timedelta(days=100))
        client = self._client([old])

        with mock.patch(
            "mail_feeder.utils.email_preview.retention.get_s3_client",
            return_value=client,
        ):
            result = purge_mail_previews(older_than_days=90, dry_run=True)

        client.remove_object.assert_not_called()
        self.assertEqual(result.deleted_count, 1)

    def test_missing_bucket_is_a_noop(self):
        client = mock.MagicMock()
        client.bucket_exists.return_value = False

        with mock.patch(
            "mail_feeder.utils.email_preview.retention.get_s3_client",
            return_value=client,
        ):
            result = purge_mail_previews(older_than_days=90)

        client.list_objects.assert_not_called()
        self.assertEqual(result.deleted_count, 0)

    def test_delete_failure_is_recorded_not_raised(self):
        now = timezone.now()
        old = _fake_object("1.png", 1000, now - timedelta(days=100))
        client = self._client([old])
        client.remove_object.side_effect = Exception("network down")

        with mock.patch(
            "mail_feeder.utils.email_preview.retention.get_s3_client",
            return_value=client,
        ):
            result = purge_mail_previews(older_than_days=90)

        self.assertEqual(result.deleted_count, 0)
        self.assertEqual(result.errors, ["1.png"])
