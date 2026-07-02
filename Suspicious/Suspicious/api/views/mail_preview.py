"""
GET /api/cases/<case_id>/mail-preview.png

Streams the cached PNG preview of the email linked to a case
straight from MinIO, addressed by the explicit (bucket, key) pair on
Mail.preview_bucket / Mail.preview_object_key. The preview is generated
at ingestion time by
`mail_feeder.utils.email_preview.eml2png_renderer.Eml2PngRenderer`.

Returns 404 when:
- the case does not exist
- the case has no linked mail (file-only / IOC-only submission)
- the mail has no rendered preview yet (preview_object_key blank)
- the MinIO object is missing / unreachable
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission
from case_handler.models import Case
from mail_feeder.utils.email_preview.preview_jobs import enqueue_preview_render

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 32 * 1024


class MailPreviewView(APIView):
    """Stream the PNG preview of the email attached to a case."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def get(self, request, case_id: int):
        case = self._get_case(case_id)
        self.check_object_permissions(request, case)

        mail = self._get_mail(case)
        bucket = getattr(mail, "preview_bucket", "") or ""
        key = getattr(mail, "preview_object_key", "") or ""
        if not bucket or not key:
            # Never rendered (or pointer cleared): kick off a background
            # render so a later request can serve it. 404 for now.
            enqueue_preview_render(mail.pk)
            raise NotFound("No preview available")

        client = self._minio_client()
        if client is None:
            raise NotFound("Preview storage unavailable")

        try:
            obj = client.get_object(bucket, key)
        except Exception as exc:
            logger.warning(
                "MinIO get_object failed: case_id=%s bucket=%s key=%s err=%s",
                case.pk, bucket, key, exc,
            )
            # Pointer exists but the object is gone — re-render in the
            # background (deduped) and 404 so the client retries.
            enqueue_preview_render(mail.pk)
            raise NotFound("Preview unavailable") from exc

        response = StreamingHttpResponse(
            _stream(obj), content_type="image/png",
        )
        response["Cache-Control"] = "private, max-age=60"
        response["Content-Disposition"] = (
            f'inline; filename="case_{case.pk}_preview.png"'
        )
        return response

    @staticmethod
    def _get_case(case_id: int) -> Case:
        try:
            return Case.objects.select_related("fileOrMail__mail").get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Case not found") from exc

    @staticmethod
    def _get_mail(case: Case):
        file_or_mail = getattr(case, "fileOrMail", None)
        mail = getattr(file_or_mail, "mail", None) if file_or_mail else None
        if not mail:
            raise NotFound("No mail linked to case")
        return mail

    @staticmethod
    def _minio_client():
        # Prefer the platform-wide client (storage.s3 runtime config) — the
        # same source the renderer/upload and the rest of the backend use.
        # Fall back to legacy django-minio-storage MINIO_STORAGE_* settings.
        try:
            from common.clients import get_s3_client
            client = get_s3_client()
            if client is not None:
                return client
        except Exception:
            logger.exception(
                "get_s3_client failed for mail preview view; "
                "falling back to MINIO_STORAGE_*"
            )

        endpoint = getattr(settings, "MINIO_STORAGE_ENDPOINT", None)
        access_key = getattr(settings, "MINIO_STORAGE_ACCESS_KEY", None)
        secret_key = getattr(settings, "MINIO_STORAGE_SECRET_KEY", None)
        if not (endpoint and access_key and secret_key):
            logger.error("MinIO storage settings missing for mail preview view")
            return None
        try:
            from minio import Minio
            return Minio(
                endpoint=endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=bool(getattr(settings, "MINIO_STORAGE_USE_HTTPS", False)),
            )
        except Exception:
            logger.exception("Failed to build MinIO client for mail preview view")
            return None


def _stream(obj):
    try:
        for chunk in obj.stream(_CHUNK_SIZE):
            yield chunk
    finally:
        try:
            obj.close()
            obj.release_conn()
        except Exception:
            pass
