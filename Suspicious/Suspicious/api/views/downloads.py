import io
import os
import zipfile
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound, APIException
from django.http import StreamingHttpResponse
from rest_framework.exceptions import APIException
from minio.error import S3Error
from case_handler.models import Case
from mail_feeder.models import MailArchive
from api.storage import StorageClient
from api.audit import log_cert_download
from django.utils import timezone
import json
import logging
from knox.models import AuthToken

logger = logging.getLogger(__name__)

ALLOWED_DOWNLOAD_GROUPS = {"Admin", "CERT"}
CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
logger = logging.getLogger(__name__)

with open(CONFIG_PATH, "r") as f:
    settings = json.load(f)

class StorageUnavailable(APIException):
    status_code = 503
    default_detail = "Storage backend unavailable"
    default_code = "storage_unavailable"


def load_minio_config(path: str):
    try:
        with open(path) as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        logger.warning("Settings file not found: %s", path)
        return None
    except json.JSONDecodeError:
        logger.warning("Settings file contains invalid JSON: %s", path)
        return None

    return config.get("minio")


minio_config = load_minio_config(CONFIG_PATH)
# Generate API Key
def generate_api_key(user, expiration):
    expiry = timezone.timedelta(days=expiration)
    token_instance, raw_key = AuthToken.objects.create(user=user, expiry=expiry)
    return raw_key, token_instance

def user_can_download(user) -> bool:
    return user.groups.filter(name__in=ALLOWED_DOWNLOAD_GROUPS).exists()



# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------
class DownloadCaseArchiveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, case_id: int):
        if not user_can_download(request.user):
            raise PermissionDenied("Not authorized")

        if not minio_config:
            raise StorageUnavailable("Storage backend not configured")

        case = self._get_case(case_id)
        archive = self._get_archive(case)

        storage = StorageClient(minio_config)
        if not storage.client:
            raise StorageUnavailable("Storage backend unavailable")

        try:
            objects = storage.client.list_objects(archive.bucket_name, recursive=True)
        except S3Error:
            raise NotFound("Bucket not found")

        def zip_stream():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for obj in objects:
                    try:
                        data = storage.client.get_object(archive.bucket_name, obj.object_name)
                        zip_file.writestr(obj.object_name, data.read())
                        data.close()
                    except S3Error:
                        continue
            buf.seek(0)
            yield from buf

        response = StreamingHttpResponse(
            zip_stream(),
            content_type="application/zip"
        )
        response['Content-Disposition'] = f'attachment; filename="case_{case.pk}.zip"'

        log_cert_download(
            user=request.user,
            case_id=case.pk,
            object_name=f"case_{case.pk}.zip",
            ip=request.META.get("REMOTE_ADDR"),
        )

        return response

    @staticmethod
    def _get_case(case_id: int) -> Case:
        try:
            return Case.objects.select_related(
                "fileOrMail__mail"
            ).get(pk=case_id)
        except Case.DoesNotExist:
            raise NotFound("Case not found")

    @staticmethod
    def _get_archive(case: Case) -> MailArchive:
        if not case.fileOrMail or not case.fileOrMail.mail:
            raise NotFound("No mail linked to case")

        archive = MailArchive.objects.filter(
            mail=case.fileOrMail.mail
        ).first()

        if not archive or not archive.bucket_name:
            raise NotFound("Archive not found")

        return archive