from unittest.mock import MagicMock
from django.test import SimpleTestCase
from common.clients import ensure_bucket


class EnsureBucketTest(SimpleTestCase):
    def test_creates_when_missing(self):
        client = MagicMock()
        client.bucket_exists.return_value = False
        ensure_bucket(client, "shots")
        client.make_bucket.assert_called_once_with("shots")

    def test_noop_when_present(self):
        client = MagicMock()
        client.bucket_exists.return_value = True
        ensure_bucket(client, "shots")
        client.make_bucket.assert_not_called()
