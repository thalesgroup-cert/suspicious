from unittest import mock

from django.test import SimpleTestCase

from case_handler.case_utils.form_handlers.mail.minio import MinioManager


class GeneratePresignedUrlTest(SimpleTestCase):
    def _manager_with_presign_client(self, fake_client):
        with mock.patch(
            "case_handler.case_utils.form_handlers.mail.minio.get_s3_client",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "case_handler.case_utils.form_handlers.mail.minio.get_s3_presign_client",
            return_value=fake_client,
        ):
            return MinioManager()

    def test_get_uses_presign_client_not_internal_client(self):
        fake_presign = mock.MagicMock()
        fake_presign.presigned_get_object.return_value = "https://public/signed"
        manager = self._manager_with_presign_client(fake_presign)

        url = manager.generate_presigned_url("bucket", "obj.eml")

        self.assertEqual(url, "https://public/signed")
        fake_presign.presigned_get_object.assert_called_once_with(
            "bucket", "obj.eml", expires=7 * 24 * 3600
        )
        manager.client.presigned_get_object.assert_not_called()

    def test_put_uses_presign_client(self):
        fake_presign = mock.MagicMock()
        fake_presign.presigned_put_object.return_value = "https://public/put"
        manager = self._manager_with_presign_client(fake_presign)

        url = manager.generate_presigned_url("bucket", "obj.eml", method="put")

        self.assertEqual(url, "https://public/put")

    def test_returns_none_when_presign_client_unavailable(self):
        with mock.patch(
            "case_handler.case_utils.form_handlers.mail.minio.get_s3_client",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "case_handler.case_utils.form_handlers.mail.minio.get_s3_presign_client",
            side_effect=Exception("boom"),
        ):
            manager = MinioManager()

        self.assertIsNone(manager.generate_presigned_url("bucket", "obj.eml"))
