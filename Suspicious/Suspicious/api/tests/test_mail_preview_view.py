"""MailPreviewView must build its MinIO client from the shared storage.s3
client, not the legacy (unset) MINIO_STORAGE_* settings.

Regression: the view returned 404 "Preview storage unavailable" for a
mail that *had* a rendered preview, because _minio_client() only read
settings.MINIO_STORAGE_* (unconfigured under the storage.s3 runtime
config) and returned None.
"""
from unittest.mock import patch

from django.test import TestCase

from api.views.mail_preview import MailPreviewView


class MailPreviewClientTest(TestCase):
    @patch("common.clients.get_s3_client")
    def test_uses_shared_s3_client(self, mock_get):
        sentinel = object()
        mock_get.return_value = sentinel
        self.assertIs(MailPreviewView._minio_client(), sentinel)

    @patch("common.clients.get_s3_client", return_value=None)
    def test_falls_back_to_none_when_unconfigured(self, _mock_get):
        # No storage.s3 client and no legacy MINIO_STORAGE_* settings.
        with self.settings(
            MINIO_STORAGE_ENDPOINT=None,
            MINIO_STORAGE_ACCESS_KEY=None,
            MINIO_STORAGE_SECRET_KEY=None,
        ):
            self.assertIsNone(MailPreviewView._minio_client())
