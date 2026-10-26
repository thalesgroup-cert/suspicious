"""fetch_eml_bytes must resolve both storage layouts.

Legacy: bucket-per-submission — `bucket_name` is a real bucket holding
the .eml at the root.

Portable prefix contract: one shared feeder bucket, the submission id is
a *prefix* (not a bucket). MailArchive.bucket_name still carries the
submission id, so fetch must fall back to feeder_bucket + prefix when no
bucket of that name exists — otherwise list_objects raises NoSuchBucket
and the mail preview never renders.
"""
import io
from unittest.mock import patch

from django.test import TestCase

from common.storage.fake import FakeObjectStore
from mail_feeder.utils.email_preview.preview_jobs import fetch_eml_bytes


class _Storage:
    def __init__(self, client):
        self.client = client


def _fake(objects):
    store = FakeObjectStore()
    for bucket, names in objects.items():
        store.ensure_bucket(bucket)
        for n in names:
            store.put(bucket, n, io.BytesIO(n.encode()))
    return store


class FetchEmlBytesTest(TestCase):
    def test_legacy_bucket_per_submission(self):
        client = _fake({"case-bucket": ["user_submission.eml", "msg.eml"]})
        data = fetch_eml_bytes(_Storage(client), "case-bucket")
        self.assertEqual(data, b"msg.eml")

    @patch("settings.config.get_section", return_value={"feeder_bucket": "suspicious-feeder"})
    def test_prefix_contract_falls_back_to_feeder_bucket(self, _gs):
        client = _fake({"suspicious-feeder": [
            "sub-1/260-aaa/260-aaa.eml",
            "sub-1/reporter-submission.eml",
            "sub-1/attachments/x.eml",
            "sub-2/other.eml",
        ]})
        data = fetch_eml_bytes(_Storage(client), "sub-1")
        key = data.decode()
        self.assertTrue(key.startswith("sub-1/"), key)
        self.assertNotIn("reporter-submission.eml", key)

    def test_returns_none_when_no_eml(self):
        client = _fake({"case-bucket": ["a.txt"]})
        self.assertIsNone(fetch_eml_bytes(_Storage(client), "case-bucket"))
