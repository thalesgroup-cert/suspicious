from typing import Optional
from minio import Minio
from minio.error import S3Error
from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound


class StorageClient:
    def __init__(self, config: dict):
        self.client = self._init_client(config)

    @staticmethod
    def _init_client(conf: dict) -> Optional[Minio]:
        try:
            return Minio(
                endpoint=conf["endpoint"],
                access_key=conf["access_key"],
                secret_key=conf["secret_key"],
                secure=conf.get("secure", False),
            )
        except Exception:
            return None

    def stream_object(self, bucket: str, object_name: str) -> StreamingHttpResponse:
        if not self.client:
            raise NotFound("Storage backend unavailable")

        try:
            obj = self.client.get_object(bucket, object_name)
        except S3Error:
            raise NotFound("Object not found in storage")

        response = StreamingHttpResponse(
            obj.stream(32 * 1024),
            content_type="application/octet-stream",
        )
        response["Content-Disposition"] = (
            f'attachment; filename="{object_name}"'
        )
        return response
