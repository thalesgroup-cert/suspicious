import io

from django.test import SimpleTestCase

from common.storage import StoreError
from common.storage.fake import FakeObjectStore

from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    _find_mail_bucket,
    fetch_mail_files_from_minio,
)

MAIL = "261007071836-7a54e9fcb2f6"


def fake_store(buckets):
    store = FakeObjectStore()
    for bucket, objects in buckets.items():
        store.ensure_bucket(bucket)
        for name, data in objects.items():
            store.put(bucket, name, io.BytesIO(data), length=len(data))
    return store


# Four reporters whose submissions landed in the same second share the suffix.
SAME_SECOND = {
    "camila.reyes-submission-261007071836": {"261007071836-aaaaaaaaaaaa/x.eml": b"A"},
    "haruto.sato-submission-261007071836": {f"{MAIL}/mail.eml": b"B", f"{MAIL}/attachments/f.pdf": b"%PDF"},
}


class FindBucketTest(SimpleTestCase):
    def test_picks_the_bucket_that_actually_holds_the_mail(self):
        self.assertEqual(
            _find_mail_bucket(fake_store(SAME_SECOND), MAIL), "haruto.sato-submission-261007071836"
        )

    def test_returns_none_when_no_bucket_has_it(self):
        self.assertIsNone(_find_mail_bucket(fake_store({"a-submission-1": {}}), "999-abc"))


class _Failing(FakeObjectStore):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def list_buckets(self):
        raise StoreError(self.code, "boom")


class OutageTest(SimpleTestCase):
    def test_not_found_is_treated_as_missing(self):
        self.assertIsNone(_find_mail_bucket(_Failing("not_found"), MAIL))
        self.assertEqual(fetch_mail_files_from_minio(_Failing("not_found"), MAIL), ("", "", "", ""))

    def test_other_errors_propagate(self):
        for code in ("unavailable", "access_denied"):
            with self.subTest(code=code):
                with self.assertRaises(StoreError):
                    _find_mail_bucket(_Failing(code), MAIL)
                with self.assertRaises(StoreError):
                    fetch_mail_files_from_minio(_Failing(code), MAIL)

    def test_listing_failure_after_bucket_found_propagates(self):
        class ListFails(FakeObjectStore):
            def list(self, bucket, prefix="", recursive=True):
                if recursive and prefix == MAIL:
                    raise StoreError("unavailable", "boom")
                return super().list(bucket, prefix, recursive)

        store = ListFails()
        store.ensure_bucket("h-submission-261007071836")
        store.put("h-submission-261007071836", f"{MAIL}/m.eml", io.BytesIO(b"x"))
        with self.assertRaises(StoreError):
            fetch_mail_files_from_minio(store, MAIL)
