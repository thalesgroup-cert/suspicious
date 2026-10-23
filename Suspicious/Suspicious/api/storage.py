from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound

from common.storage import ObjectStore, StoreError, get_store

_CHUNK_SIZE = 32 * 1024


def open_chunks(store: ObjectStore, bucket: str, key: str):
    """Open the object now (so a missing key raises StoreError here) and return a
    generator that streams it and closes it when exhausted or discarded."""
    cm = store.open(bucket, key)
    stream = cm.__enter__()

    def gen():
        try:
            yield from stream.iter_chunks(_CHUNK_SIZE)
        finally:
            cm.__exit__(None, None, None)

    return gen()


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
        except StoreError:
            raise NotFound("Object not found in storage")

        response = StreamingHttpResponse(
            chunks,
            content_type="application/octet-stream",
        )
        response["Content-Disposition"] = (
            f'attachment; filename="{object_name}"'
        )
        return response
