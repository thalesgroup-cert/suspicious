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


class GetS3PresignClientTest(SimpleTestCase):
    def test_uses_public_endpoint_when_set(self):
        section = {
            "endpoint": "rustfs:9000", "public_endpoint": "localhost:35002",
            "access_key": "ak", "secret_key": "sk", "secure": False,
        }
        with mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.Minio") as minio_cls:
            from common.clients import get_s3_presign_client
            get_s3_presign_client()
        minio_cls.assert_called_once_with(
            endpoint="localhost:35002", access_key="ak", secret_key="sk", secure=False
        )

    def test_falls_back_to_internal_endpoint_when_unset(self):
        section = {
            "endpoint": "rustfs:9000", "access_key": "ak",
            "secret_key": "sk", "secure": False,
        }
        with mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.Minio") as minio_cls:
            from common.clients import get_s3_presign_client
            get_s3_presign_client()
        minio_cls.assert_called_once_with(
            endpoint="rustfs:9000", access_key="ak", secret_key="sk", secure=False
        )


class GetChromaClientTest(SimpleTestCase):
    def test_builds_http_client_from_section(self):
        section = {"host": "chromadb", "port": 8000}
        with mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        chroma_mod.HttpClient.assert_called_once()
        kwargs = chroma_mod.HttpClient.call_args.kwargs
        self.assertEqual((kwargs["host"], kwargs["port"]), ("chromadb", 8000))

    def test_uses_defaults_when_keys_absent(self):
        section = {}
        with mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        kwargs = chroma_mod.HttpClient.call_args.kwargs
        self.assertEqual(kwargs["host"], "chromadb")
        self.assertEqual(kwargs["port"], 8000)
