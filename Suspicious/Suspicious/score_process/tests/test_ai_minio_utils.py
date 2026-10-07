import io
import zipfile
from types import SimpleNamespace

from django.test import SimpleTestCase

from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    _find_mail_bucket,
    build_mail_zip_from_minio,
)

MAIL = "261007071836-7a54e9fcb2f6"


class FakeMinio:
    """buckets: {name: {object_name: bytes}}"""

    def __init__(self, buckets):
        self.buckets = buckets

    def list_buckets(self):
        return [SimpleNamespace(name=n) for n in self.buckets]

    def list_objects(self, bucket, prefix="", recursive=False):
        return [SimpleNamespace(object_name=n) for n in self.buckets[bucket] if n.startswith(prefix)]

    def get_object(self, bucket, name):
        data = self.buckets[bucket][name]
        return SimpleNamespace(read=lambda: data, close=lambda: None, release_conn=lambda: None)


# Four reporters whose submissions landed in the same second share the suffix.
SAME_SECOND = {
    "camila.reyes-submission-261007071836": {"261007071836-aaaaaaaaaaaa/x.eml": b"A"},
    "haruto.sato-submission-261007071836": {f"{MAIL}/mail.eml": b"B", f"{MAIL}/attachments/f.pdf": b"%PDF"},
}


class FindBucketTest(SimpleTestCase):
    def test_picks_the_bucket_that_actually_holds_the_mail(self):
        self.assertEqual(
            _find_mail_bucket(FakeMinio(SAME_SECOND), MAIL), "haruto.sato-submission-261007071836"
        )

    def test_returns_none_when_no_bucket_has_it(self):
        self.assertIsNone(_find_mail_bucket(FakeMinio({"a-submission-1": {}}), "999-abc"))


class ZipTest(SimpleTestCase):
    def test_zip_comes_from_the_right_bucket(self):
        name, data = build_mail_zip_from_minio(FakeMinio(SAME_SECOND), MAIL, "haruto")
        self.assertEqual(
            sorted(zipfile.ZipFile(io.BytesIO(data)).namelist()), ["attachments/f.pdf", "mail.eml"]
        )
        self.assertTrue(name.endswith(f"{MAIL}.zip"))

    def test_never_returns_an_empty_zip(self):
        # bucket found by name but nothing stored for this mail
        self.assertEqual(
            build_mail_zip_from_minio(FakeMinio({"a-submission-261007071836": {}}), MAIL, "a"), ("", b"")
        )
