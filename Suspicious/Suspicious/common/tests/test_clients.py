from unittest import mock

from django.test import SimpleTestCase


class GetS3ClientTest(SimpleTestCase):
    def test_builds_minio_from_storage_section(self):
        section = {
            "endpoint": "rustfs:9000", "access_key": "ak",
            "secret_key": "sk", "secure": False,
        }
        with mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.Minio") as minio_cls:
            from common.clients import get_s3_client
            get_s3_client()
        minio_cls.assert_called_once_with(
            endpoint="rustfs:9000", access_key="ak", secret_key="sk", secure=False
        )
