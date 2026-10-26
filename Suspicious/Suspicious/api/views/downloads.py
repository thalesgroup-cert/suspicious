import logging
import tempfile
import zipfile

from django.http import FileResponse
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView

from api.permissions.settings import IsAdminOrCERT

from case_handler.models import Case
from mail_feeder.models import MailArchive
from api.audit import log_cert_download
from api.storage import StorageClient, StorageUnavailable
from common.storage import StoreError

logger = logging.getLogger(__name__)


def get_request_ip(request) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return request.META.get("REMOTE_ADDR")


class DownloadCaseArchiveView(APIView):
    permission_classes = [IsAdminOrCERT]

    def get(self, request, case_id: int):

        case = self._get_case(case_id)
        archive = self._get_archive(case)
        storage = self._get_storage_client()

        zip_file = self._build_zip_archive(storage=storage, case=case, archive=archive)

        response = FileResponse(
            zip_file,
            as_attachment=True,
            filename=f"case_{case.pk}.zip",
            content_type="application/zip",
        )

        log_cert_download(
            user=request.user,
            case_id=case.pk,
            object_name=f"case_{case.pk}.zip",
            ip=get_request_ip(request),
        )

        logger.info(
            "Archive download served: user_id=%s case_id=%s bucket=%s",
            getattr(request.user, "id", None),
            case.pk,
            archive.bucket_name,
        )

        return response

    def _get_storage_client(self) -> StorageClient:
        storage = StorageClient()
        if not getattr(storage, "client", None):
            raise StorageUnavailable("Storage backend unavailable")

        return storage

    def _build_zip_archive(self, *, storage: StorageClient, case: Case, archive: MailArchive):
        """
        Build the ZIP into a temporary file and return an open file object positioned at start.
        This avoids holding the entire archive in memory while preserving current behavior.
        """
        temp_file = tempfile.TemporaryFile(mode="w+b")

        try:
            try:
                objects = list(storage.client.list(archive.bucket_name, recursive=True))
            except StoreError as exc:
                logger.warning(
                    "Failed to list objects for case archive: case_id=%s bucket=%s error=%s",
                    case.pk,
                    archive.bucket_name,
                    exc,
                )
                raise StorageUnavailable("Unable to access archive storage") from exc

            written_entries = 0

            with zipfile.ZipFile(temp_file, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_file:
                for obj in objects:
                    object_name = getattr(obj, "name", None)
                    if not object_name:
                        continue

                    try:
                        with storage.client.open(archive.bucket_name, object_name) as stream:
                            zip_file.writestr(object_name, stream.read())
                        written_entries += 1
                    except StoreError as exc:
                        if exc.code != "not_found":
                            raise StorageUnavailable("Unable to read archive storage") from exc
                        logger.warning(
                            "Skipping object while building archive zip: case_id=%s bucket=%s object=%s error=%s",
                            case.pk,
                            archive.bucket_name,
                            object_name,
                            exc,
                        )
                        continue

            if written_entries == 0:
                logger.warning(
                    "No objects written to archive zip: case_id=%s bucket=%s",
                    case.pk,
                    archive.bucket_name,
                )
                raise NotFound("Archive is empty or unavailable")

            temp_file.seek(0)
            return temp_file

        except Exception:
            temp_file.close()
            raise

    @staticmethod
    def _get_case(case_id: int) -> Case:
        try:
            return Case.objects.select_related("fileOrMail__mail").get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Case not found") from exc

    @staticmethod
    def _get_archive(case: Case) -> MailArchive:
        file_or_mail = getattr(case, "fileOrMail", None)
        mail = getattr(file_or_mail, "mail", None)

        if not mail:
            raise NotFound("No mail linked to case")

        archive = MailArchive.objects.filter(mail=mail).first()
        if not archive or not archive.bucket_name:
            raise NotFound("Archive not found")

        return archive