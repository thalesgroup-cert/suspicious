import pathlib
import typing


import minio
import minio.error
import minio.commonconfig


import classes.models.mail_tags
import classes.models.configs.internals.minio


class MinioService:
    __minio_client: minio.Minio | None = None

    def __init__(
        self, config: classes.models.configs.internals.minio.MinioConfig
    ) -> None:
        self.__config = config

    def connect(self):
        self.__minio_client = minio.Minio(
            self.__config.endpoint,
            access_key=self.__config.access_key,
            secret_key=self.__config.secret_key,
            secure=self.__config.secure,
        )

    def __bucket_exists(self, bucket_name: str) -> bool:
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")

        return self.__minio_client.bucket_exists(bucket_name)

    def __make_bucket(self, bucket_name: str) -> None:
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")
        if len(bucket_name) > 63:
            bucket_name = bucket_name[:63]
        self.__minio_client.make_bucket(bucket_name)

    def __assign_bucket_tags(self, bucket_name: str, tags_to_set: dict[str, str]):
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")

        bucket_tags = minio.commonconfig.Tags()
        for key, value in tags_to_set.items():
            bucket_tags[key] = value
        self.__minio_client.set_bucket_tags(bucket_name, bucket_tags)

    def ensure_bucket_exists_and_tagged(
        self, bucket_name: str, tags_to_set: typing.Optional[dict[str, str]] = None
    ) -> None:
        """
        Ensures a MinIO bucket exists. If not, creates it and applies tags.
        If it exists, checks if tags need to be updated (optional behavior, currently only sets on creation).

        Args:
            bucket_name: Name of the bucket.
            tags_to_set: A dictionary of tags to apply if the bucket is created.
        """
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")

        if self.__bucket_exists(bucket_name=bucket_name):
            return None

        try:
            self.__make_bucket(bucket_name=bucket_name)
            if tags_to_set is not None:
                self.__assign_bucket_tags(
                    bucket_name=bucket_name, tags_to_set=tags_to_set
                )
        except minio.error.S3Error as e:
            raise Exception(f"MinIO S3Error concerning bucket '{bucket_name}': {e}")
        except Exception as e:
            raise Exception(
                f"Unexpected error concerning bucket '{bucket_name}': {e}"
            ) from e

    def upload_file(
        self,
        bucket_name: str,
        file_path: pathlib.Path,
        object_name: typing.Optional[str] = None,
        default_tags: typing.Optional[dict[str, str]] = None,
    ):
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")

        if not file_path.exists():
            raise Exception(f"{file_path} does not exist.")

        if not file_path.is_file():
            raise Exception(f"{file_path} is not a file.")

        if object_name is None:
            object_name = file_path.as_posix()

        object_tags: minio.commonconfig.Tags | None = None
        if default_tags is not None:
            object_tags = minio.commonconfig.Tags(for_object=True)
            for k, v in default_tags.items():
                object_tags[k] = v

        file_stat = file_path.stat()

        with open(file_path, "rb") as f_data:
            try:
                self.__minio_client.put_object(
                    bucket_name=bucket_name,
                    object_name=object_name,
                    data=f_data,
                    length=file_stat.st_size,
                    content_type="application/octet-stream",
                    tags=object_tags,
                )
            except minio.error.S3Error as e:
                raise Exception(
                    f"MinIO S3Error uploading '{file_path.name}' as '{object_name}': {e}"
                )

    def upload_directory(
        self,
        source_dir: pathlib.Path,
        bucket_name: str,
        base_object_path: typing.Optional[str] = None,
        default_tags: typing.Optional[dict[str, str]] = None,
    ):
        """
        Uploads all files from a local directory to a specified MinIO bucket and path.
        typing.Optionally applies default tags to each uploaded object.

        Args:
            client: Initialized MinIO client.
            source_dir: Path object for the local directory to upload.
            bucket_name: Name of the target MinIO bucket.
            base_object_path: typing.Optional base path within the bucket for uploaded objects.
            default_tags: typing.Optional dictionary of tags to apply to each object.
        """
        if self.__minio_client is None:
            raise Exception(f"MinIO client not available for bucket '{bucket_name}'.")

        if not source_dir.is_dir():
            raise Exception(
                f"Source '{source_dir}' is not a directory or does not exist."
            )

        bucket_creation_tags = {
            classes.models.mail_tags.MailTag.STATUS.value: classes.models.mail_tags.MailTag.TODO.value
        }

        try:
            self.ensure_bucket_exists_and_tagged(bucket_name, bucket_creation_tags)
        except Exception as e:
            raise Exception(
                f"Cannot upload to MinIO bucket '{bucket_name}' as it could not be ensured/created."
            ) from e

        for file_path in source_dir.rglob("*"):
            if not file_path.is_file():
                continue

            relative_file_path = file_path.relative_to(source_dir)

            minio_file_path = (
                pathlib.Path(base_object_path, relative_file_path)
                if base_object_path is not None
                else relative_file_path
            )

            try:
                self.upload_file(
                    bucket_name=bucket_name,
                    file_path=file_path,
                    object_name=minio_file_path.as_posix(),
                    default_tags=default_tags,
                )

            except Exception as e:
                raise Exception(
                    f"Failed to upload '{file_path.name}' as '{minio_file_path}': {e}",
                ) from e

    @property
    def is_connected(self) -> bool:
        return self.__minio_client is not None
