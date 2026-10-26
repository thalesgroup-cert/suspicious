"""Unit tests for the mail-preview bucket sweep, run against FakeObjectStore."""
import io
from dataclasses import replace
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from common.storage.fake import FakeObjectStore
from mail_feeder.utils.email_preview.retention import purge_mail_previews

PATCH = "mail_feeder.utils.email_preview.retention.get_store"


def _store(*objects):
    """objects: (name, size, last_modified); the fake records modification times."""
    store = FakeObjectStore()
    store.ensure_bucket("mail-previews")
    for name, size, modified in objects:
        store.put("mail-previews", name, io.BytesIO(b"x" * size), length=size)
        info = store._buckets["mail-previews"][name]
        store._buckets["mail-previews"][name] = replace(info, last_modified=modified)
    return store


def _keys(store):
    return [o.name for o in store.list("mail-previews")]


class PurgeMailPreviewsTest(SimpleTestCase):
    def test_requires_at_least_one_criterion(self):
        with self.assertRaises(ValueError):
            purge_mail_previews()

    def test_deletes_objects_older_than_cutoff(self):
        now = timezone.now()
        store = _store(("1.png", 1000, now - timedelta(days=100)),
                       ("2.png", 1000, now - timedelta(days=1)))
        with mock.patch(PATCH, return_value=store):
            result = purge_mail_previews(older_than_days=90)
        self.assertEqual(_keys(store), ["2.png"])
        self.assertEqual(result.deleted_count, 1)
        self.assertEqual(result.deleted_bytes, 1000)

    def test_deletes_objects_over_size_regardless_of_age(self):
        now = timezone.now()
        store = _store(("1.png", 20 * 1024 * 1024, now), ("2.png", 1000, now))
        with mock.patch(PATCH, return_value=store):
            result = purge_mail_previews(min_size_mb=15)
        self.assertEqual(_keys(store), ["2.png"])
        self.assertEqual(result.deleted_count, 1)

    def test_dry_run_deletes_nothing(self):
        store = _store(("1.png", 1000, timezone.now() - timedelta(days=100)))
        with mock.patch(PATCH, return_value=store):
            result = purge_mail_previews(older_than_days=90, dry_run=True)
        self.assertEqual(_keys(store), ["1.png"])
        self.assertEqual(result.deleted_count, 1)

    def test_missing_bucket_is_a_noop(self):
        with mock.patch(PATCH, return_value=FakeObjectStore()):
            result = purge_mail_previews(older_than_days=90)
        self.assertEqual(result.deleted_count, 0)

    def test_delete_failure_is_recorded_not_raised(self):
        store = _store(("1.png", 1000, timezone.now() - timedelta(days=100)))
        store.delete = mock.Mock(side_effect=Exception("network down"))
        with mock.patch(PATCH, return_value=store):
            result = purge_mail_previews(older_than_days=90)
        self.assertEqual(result.deleted_count, 0)
        self.assertEqual(result.errors, ["1.png"])
