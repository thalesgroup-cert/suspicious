from django.http import StreamingHttpResponse
from rest_framework.exceptions import APIException, NotFound

from common.storage import ObjectStore, StoreError, get_store

_CHUNK_SIZE = 32 * 1024


class StorageUnavailable(APIException):
    status_code = 503
    default_detail = "Storage backend unavailable"
    default_code = "storage_unavailable"


class _Chunks:
    """Streams an already opened object. close() releases it even if iteration
    never started, which a bare generator would not do."""

    def __init__(self, cm, stream):
        self._cm, self._stream, self._open = cm, stream, True

    def __iter__(self):
        try:
            yield from self._stream.iter_chunks(_CHUNK_SIZE)
        finally:
            self.close()

    def close(self):
        if self._open:
            self._open = False
            self._cm.__exit__(None, None, None)


def open_chunks(store: ObjectStore, bucket: str, key: str) -> _Chunks:
    """Open the object now, so a missing key raises StoreError before the
    response starts."""
    cm = store.open(bucket, key)
    return _Chunks(cm, cm.__enter__())


class StorageClient:
    def __init__(self):
        try:
            self.client = get_store()
        except Exception:
            self.client = None

    def stream_object(self, bucket: str, object_name: str) -> StreamingHttpResponse:
        if not self.client:
            raise NotFound("Storage backend unavailable")

        try:
            chunks = open_chunks(self.client, bucket, object_name)
        except StoreError as exc:
            if exc.code != "not_found":
                raise StorageUnavailable("Storage backend unavailable") from exc
            raise NotFound("Object not found in storage") from exc

        response = StreamingHttpResponse(
            chunks,
            content_type="application/octet-stream",
        )
        response["Content-Disposition"] = (
            f'attachment; filename="{object_name}"'
        )
        return response
