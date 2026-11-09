from unittest import mock

from django.test import SimpleTestCase

from common.storage import StoreError
from common.storage.fake import FakeObjectStore
from common.storage.layout import resolve_submission_location


def store_with(*buckets):
    store = FakeObjectStore()
    for bucket in buckets:
        store.ensure_bucket(bucket)
    return store


class S3NamedStore(FakeObjectStore):
    """bucket_exists as S3 answers it: a name S3 cannot hold (uppercase, ``_``) is a 400, invalid."""

    def bucket_exists(self, bucket):
        if bucket != bucket.lower() or "_" in bucket:
            raise StoreError("invalid", "400 Bad Request", bucket=bucket)
        return super().bucket_exists(bucket)


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

    def test_an_id_s3_cannot_name_a_bucket_after_is_in_the_feeder_bucket(self):
        # The feeder keeps the reporter's case and turns "+" or spaces into "_" in a prefix-layout id.
        store = S3NamedStore()
        store.ensure_bucket("feeder")
        with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
            for sub in ("John.Doe-submission-261007071836", "john_doe-submission-261007071836"):
                with self.subTest(sub=sub):
                    self.assertEqual(resolve_submission_location(store, sub), ("feeder", f"{sub}/"))
        with mock.patch("settings.config.get_section", return_value={}):
            self.assertIsNone(resolve_submission_location(store, "John.Doe-submission-261007071836"))

    def test_any_other_store_error_from_the_bucket_check_propagates(self):
        for code in ("unavailable", "access_denied"):
            store = store_with("feeder")
            store.bucket_exists = mock.Mock(side_effect=StoreError(code, "boom"))
            with self.subTest(code=code), self.assertRaises(StoreError) as caught:
                with mock.patch("settings.config.get_section", return_value={"feeder_bucket": "feeder"}):
                    resolve_submission_location(store, "sub-1")
            self.assertEqual(caught.exception.code, code)
