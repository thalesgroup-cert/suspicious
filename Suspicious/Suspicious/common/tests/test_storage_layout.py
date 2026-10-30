import io
from unittest import mock

from django.test import SimpleTestCase

from common.storage.fake import FakeObjectStore
from common.storage.layout import resolve_submission_location


def store_with(*buckets):
    store = FakeObjectStore()
    for bucket in buckets:
        store.ensure_bucket(bucket)
    return store


class ResolveSubmissionLocationTest(SimpleTestCase):
    def test_a_bucket_named_like_the_submission_is_the_legacy_layout(self):
        with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            self.assertEqual(resolve_submission_location(store_with("sub-1", "feeder"), "sub-1"), ("sub-1", ""))

    def test_otherwise_the_feeder_bucket_and_the_submission_prefix(self):
        with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            self.assertEqual(resolve_submission_location(store_with("feeder"), "sub-1"), ("feeder", "sub-1/"))
            self.assertEqual(resolve_submission_location(store_with("feeder"), "sub-1/"), ("feeder", "sub-1/"))

    def test_none_without_a_feeder_bucket_or_when_the_config_cannot_be_read(self):
        with mock.patch("settings.config.get_section", return_value={}):
            self.assertIsNone(resolve_submission_location(store_with(), "sub-1"))
        with mock.patch("settings.config.get_section", side_effect=RuntimeError("no db")):
            self.assertIsNone(resolve_submission_location(store_with(), "sub-1"))
