import logging
from pathlib import Path
from datetime import timedelta
from typing import Optional, Dict

from common.storage import ObjectStore, StoreError, get_presign_store, get_store

logger = logging.getLogger(__name__)

TAG_STATUS_TODO = "To Do"
TAG_KEY_STATUS = "Status"


class MinioManager:
    """
    A utility class to manage MinIO interactions: client initialization,
    bucket lifecycle, file uploads, and presigned URL generation.
    """

    def __init__(self):
        """
        Initialize the MinIO client from the shared ``storage.s3`` runtime config.
        """
        self.client = self._default_client()
        self.presign_client = self._presign_client()

    def _default_client(self) -> Optional[ObjectStore]:
        """
        Create and return a MinIO client from the shared ``storage.s3`` config.

        Returns:
            ObjectStore | None: Initialized client or None on failure.
        """
        try:
            client = get_store()
            logger.info("Object store initialized via get_store()")
            return client
        except Exception as e:
            logger.critical("Failed to initialize MinIO client: %s", e, exc_info=True)
            return None

    def _presign_client(self) -> Optional[ObjectStore]:
        """
        Client for signing browser-facing URLs (storage.s3.public_endpoint).

        Returns:
            ObjectStore | None: Initialized client or None on failure.
        """
        try:
            return get_presign_store()
        except Exception as e:
            logger.critical("Failed to initialize MinIO presign client: %s", e, exc_info=True)
            return None

    def bucket_exists(self, bucket_name: str) -> bool:
        """
        Check if a bucket exists in MinIO.

        Args:
            bucket_name (str): Name of the bucket to check.

        Returns:
            bool: True if bucket exists, False otherwise.
        """
        if not self.client:
            return False
        try:
            exists = self.client.bucket_exists(bucket_name)
            logger.debug("Bucket '%s' exists? %s", bucket_name, exists)
            return exists
        except StoreError as e:
            logger.error("Error checking bucket existence '%s': %s", bucket_name, e)
            return False

    def ensure_bucket(self, bucket_name: str, tags: Optional[Dict[str, str]] = None) -> bool:
        """
        Ensure bucket exists, create it if necessary, and optionally apply tags.

        Args:
            bucket_name (str): Target bucket name.
            tags (Dict[str, str], optional): Tags to set on creation.

        Returns:
            bool: True if bucket exists or was created; False on error.
        """
        if not self.client:
            logger.error("MinIO client unavailable.")
            return False

        try:
            if not self.bucket_exists(bucket_name):
                self.client.ensure_bucket(bucket_name)
                logger.info("Created bucket '%s'", bucket_name)
                if tags:
                    self.client.set_bucket_labels(bucket_name, tags)
                    logger.info("Applied tags to bucket '%s': %s", bucket_name, tags)
            return True
        except StoreError as e:
            logger.error("Store error during ensure_bucket('%s'): %s", bucket_name, e)
        except Exception as e:
            logger.error("Unexpected error during ensure_bucket('%s'): %s", bucket_name, e, exc_info=True)
        return False

    def upload_file(self, bucket_name: str, file_path: Path, object_name: str, tags: Optional[Dict[str, str]] = None):
        """
        Upload a single file to a specified bucket with optional tags.

        Args:
            bucket_name (str): Target bucket name.
            file_path (Path): Local file path to upload.
            object_name (str): Destination path/name in bucket.
            tags (Dict[str, str], optional): Tags to set on the object.
        """
        if not self.client:
            logger.error("MinIO client unavailable for upload.")
            return
        try:
            with file_path.open('rb') as data:
                size = file_path.stat().st_size
                self.client.put(
                    bucket_name,
                    object_name,
                    data,
                    length=size,
                    content_type="application/octet-stream",
                    tags=tags or None,
                )
                logger.info("Uploaded '%s' to '%s/%s' (tags: %s)", file_path, bucket_name, object_name, tags or {})
        except StoreError as e:
            logger.error("Store error uploading '%s': %s", file_path, e)
        except Exception as e:
            logger.error("Error uploading '%s': %s", file_path, e, exc_info=True)

    def upload_directory(self, source_dir: Path, bucket_name: str, base_object_path: str = "", default_tags: Optional[Dict[str, str]] = None):
        """
        Upload all files in a directory to a MinIO bucket, preserving structure.

        Args:
            source_dir (Path): Local directory to upload.
            bucket_name (str): Target bucket name.
            base_object_path (str): Base prefix in bucket for objects.
            default_tags (Dict[str, str], optional): Tags to apply to each file.
        """
        if not source_dir.is_dir():
            logger.error("Source '%s' is not a valid directory.", source_dir)
            return

        ensure_tags = {TAG_KEY_STATUS: TAG_STATUS_TODO}
        if not self.ensure_bucket(bucket_name, tags=ensure_tags):
            logger.error("Cannot upload: bucket '%s' ensure failed.", bucket_name)
            return

        for file_path in source_dir.rglob('*'):
            if file_path.is_file():
                rel = str(file_path.relative_to(source_dir)).replace("\\", "/")
                obj_name = f"{base_object_path.rstrip('/')}/{rel}" if base_object_path else rel
                self.upload_file(bucket_name, file_path, obj_name, default_tags)

    def generate_presigned_url(self, bucket_name: str, object_name: str, expires_seconds: int = 7 * 24 * 3600, method: str = "get") -> Optional[str]:
        """
        Generate a presigned URL for object GET or PUT operations.

        Args:
            bucket_name (str): Target bucket name.
            object_name (str): Target object name/path.
            expires_seconds (int): Expiry time in seconds (default: 7 days).
            method (str): 'get' for download or 'put' for upload.

        Returns:
            str | None: Presigned URL or None on failure.
        """
        if not self.presign_client:
            logger.error("MinIO presign client unavailable for presigned URL.")
            return None
        expires = timedelta(seconds=expires_seconds)
        try:
            if method.lower() == "get":
                return self.presign_client.presign_get(bucket_name, object_name, expires)
            return self.presign_client.presign_put(bucket_name, object_name, expires)
        except Exception as e:
            logger.error("Failed to generate presigned URL for '%s/%s': %s", bucket_name, object_name, e)
            return None
