import io

from django.test import SimpleTestCase

from common.storage.fake import FakeObjectStore

from score_process.scoring.cortex_analyzers.contrib.ai_minio_utils import (
    _find_mail_bucket,
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
