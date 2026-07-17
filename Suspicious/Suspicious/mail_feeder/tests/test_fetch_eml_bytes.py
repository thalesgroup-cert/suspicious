"""fetch_eml_bytes must resolve both storage layouts.

Legacy: bucket-per-submission — `bucket_name` is a real bucket holding
the .eml at the root.

Portable prefix contract: one shared feeder bucket, the submission id is
a *prefix* (not a bucket). MailArchive.bucket_name still carries the
submission id, so fetch must fall back to feeder_bucket + prefix when no
bucket of that name exists — otherwise list_objects raises NoSuchBucket
and the mail preview never renders.
"""
from unittest.mock import patch

from django.test import TestCase

from mail_feeder.utils.email_preview.preview_jobs import fetch_eml_bytes


class _Obj:
    def __init__(self, name):
        self.object_name = name


class _Resp:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d

    def close(self):
        pass

    def release_conn(self):
        pass


class _Client:
    def __init__(self, buckets, objects):
        self._buckets = set(buckets)
        self._objects = objects
        self.got = None

    def bucket_exists(self, b):
        return b in self._buckets

    def list_objects(self, bucket, prefix="", recursive=False):
        return [_Obj(n) for n in self._objects.get(bucket, []) if n.startswith(prefix)]

    def get_object(self, bucket, key):
        self.got = (bucket, key)
        return _Resp(b"EMLBYTES")


class _Storage:
    def __init__(self, client):
        self.client = client


class FetchEmlBytesTest(TestCase):
    def test_legacy_bucket_per_submission(self):
        client = _Client(
            buckets={"case-bucket"},
            objects={"case-bucket": ["user_submission.eml", "msg.eml"]},
        )
        data = fetch_eml_bytes(_Storage(client), "case-bucket")
        self.assertEqual(data, b"EMLBYTES")
        self.assertEqual(client.got, ("case-bucket", "msg.eml"))

    @patch("settings.config.get_section", return_value={"feeder_bucket": "suspicious-feeder"})
    def test_prefix_contract_falls_back_to_feeder_bucket(self, _gs):
        client = _Client(
            buckets={"suspicious-feeder"},
            objects={
                "suspicious-feeder": [
                    "sub-1/260-aaa/260-aaa.eml",
                    "sub-1/reporter-submission.eml",
                    "sub-1/attachments/x.eml",
                    "sub-2/other.eml",
                ]
            },
        )
        data = fetch_eml_bytes(_Storage(client), "sub-1")
        self.assertEqual(data, b"EMLBYTES")
        bucket, key = client.got
        self.assertEqual(bucket, "suspicious-feeder")
        self.assertTrue(key.startswith("sub-1/"), key)
        self.assertNotIn("reporter-submission.eml", key)
        self.assertFalse(key.startswith("sub-2/"), key)

    def test_returns_none_when_no_eml(self):
        client = _Client(buckets={"case-bucket"}, objects={"case-bucket": ["a.txt"]})
        self.assertIsNone(fetch_eml_bytes(_Storage(client), "case-bucket"))
