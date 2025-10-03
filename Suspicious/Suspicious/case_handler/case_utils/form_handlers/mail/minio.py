import logging
from pathlib import Path
from typing import Optional, Dict
from minio import Minio
from minio.error import S3Error
from minio.commonconfig import Tags

logger = logging.getLogger(__name__)

TAG_STATUS_TODO = "To Do"
TAG_KEY_STATUS = "Status"


class MinioManager:
    """
    A utility class to manage MinIO interactions: client initialization,
    bucket lifecycle, file uploads, and presigned URL generation.
    """

    def __init__(self, endpoint: str, access_key: str, secret_key: str, secure: bool = False):
        """
        Initialize the MinIO client.

        Args:
            endpoint (str): MinIO server endpoint (e.g., 'localhost:9000').
            access_key (str): Access key for authentication.
            secret_key (str): Secret key for authentication.
            secure (bool): Whether to use TLS (HTTPS). Default is False.
        """
        self.client = self._init_client(endpoint, access_key, secret_key, secure)

    def _init_client(self, endpoint: str, access_key: str, secret_key: str, secure: bool) -> Optional[Minio]:
        """
        Create and return a MinIO client instance.

        Returns:
            Minio | None: Initialized client or None on failure.
        """
        try:
            client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
            logger.info("MinIO client initialized: %s", endpoint)
            return client
        except Exception as e:
            logger.critical("Failed to initialize MinIO client: %s", e, exc_info=True)
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
        except S3Error as e:
            logger.error("Error checking bucket existence '%s': %s", bucket_name, e)
            return False

    def ensure_bucket(self, bucket_name: str, tags: Optional[Dict[str, str]] = None, region: Optional[str] = None) -> bool:
        """
        Ensure bucket exists, create it if necessary, and optionally apply tags.

        Args:
            bucket_name (str): Target bucket name.
            tags (Dict[str, str], optional): Tags to set on creation.
            region (str, optional): Region for bucket creation.

        Returns:
            bool: True if bucket exists or was created; False on error.
        """
        if not self.client:
            logger.error("MinIO client unavailable.")
            return False

        try:
            if not self.bucket_exists(bucket_name):
                if region:
                    self.client.make_bucket(bucket_name, location=region)
                else:
                    self.client.make_bucket(bucket_name)
                logger.info("Created bucket '%s'%s", bucket_name, f" in region {region}" if region else "")
                if tags:
                    tag_obj = Tags()
                    for k, v in tags.items():
                        tag_obj[k] = v
                    self.client.set_bucket_tags(bucket_name, tag_obj)
                    logger.info("Applied tags to bucket '%s': %s", bucket_name, tags)
            return True
        except S3Error as e:
            logger.error("MinIO S3Error during ensure_bucket('%s'): %s", bucket_name, e)
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
                tag_obj = Tags() if tags else None
                if tags:
                    for k, v in tags.items():
                        tag_obj[k] = v

                self.client.put_object(
                    bucket_name,
                    object_name,
                    data,
                    size,
                    content_type="application/octet-stream",
                    tags=tag_obj
                )
                logger.info("Uploaded '%s' to '%s/%s' (tags: %s)", file_path, bucket_name, object_name, tags or {})
        except S3Error as e:
            logger.error("S3Error uploading '%s': %s", file_path, e)
        except Exception as e:
            logger.error("Error uploading '%s': %s", file_path, e, exc_info=True)

    def upload_directory(self, source_dir: Path, bucket_name: str, base_object_path: str = "", default_tags: Optional[Dict[str, str]] = None, region: Optional[str] = None):
        """
        Upload all files in a directory to a MinIO bucket, preserving structure.

        Args:
            source_dir (Path): Local directory to upload.
            bucket_name (str): Target bucket name.
            base_object_path (str): Base prefix in bucket for objects.
            default_tags (Dict[str, str], optional): Tags to apply to each file.
            region (str, optional): Region used when creating bucket.
        """
        if not source_dir.is_dir():
            logger.error("Source '%s' is not a valid directory.", source_dir)
            return

        ensure_tags = {TAG_KEY_STATUS: TAG_STATUS_TODO}
        if not self.ensure_bucket(bucket_name, tags=ensure_tags, region=region):
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
        if not self.client:
            logger.error("MinIO client unavailable for presigned URL.")
            return None
        try:
            if method.lower() == "get":
                return self.client.presigned_get_object(bucket_name, object_name, expires=expires_seconds)
            return self.client.presigned_put_object(bucket_name, object_name, expires=expires_seconds)
        except Exception as e:
            logger.error("Failed to generate presigned URL for '%s/%s': %s", bucket_name, object_name, e)
            return None
