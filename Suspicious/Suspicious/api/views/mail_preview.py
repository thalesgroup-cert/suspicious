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

from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission, submission_queryset
from api.storage import open_chunks
from case_handler.models import Case
from common.storage import get_store
from mail_feeder.utils.email_preview.preview_jobs import enqueue_preview_render

logger = logging.getLogger(__name__)


class MailPreviewView(APIView):
    """Stream the PNG preview of the email attached to a case."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def get(self, request, case_id: int):
        case = self._get_case(case_id, request.user)
        self.check_object_permissions(request, case)

        mail = self._get_mail(case)
        bucket = getattr(mail, "preview_bucket", "") or ""
        key = getattr(mail, "preview_object_key", "") or ""
        if not bucket or not key:
            enqueue_preview_render(mail.pk)
            raise NotFound("No preview available")

        try:
            store = get_store()
        except Exception:
            logger.exception("get_store failed for mail preview view")
            raise NotFound("Preview storage unavailable")

        try:
            chunks = open_chunks(store, bucket, key)
        except Exception as exc:
            logger.warning(
                "Object store open failed: case_id=%s bucket=%s key=%s err=%s",
                case.pk, bucket, key, exc,
            )
            enqueue_preview_render(mail.pk)
            raise NotFound("Preview unavailable") from exc

        response = StreamingHttpResponse(
            chunks, content_type="image/png",
        )
        response["Cache-Control"] = "private, max-age=60"
        response["Content-Disposition"] = (
            f'inline; filename="case_{case.pk}_preview.png"'
        )
        return response

    @staticmethod
    def _get_case(case_id: int, user) -> Case:
        try:
            return submission_queryset(
                Case.objects.select_related("fileOrMail__mail"), user
            ).get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Case not found") from exc

    @staticmethod
    def _get_mail(case: Case):
        file_or_mail = getattr(case, "fileOrMail", None)
        mail = getattr(file_or_mail, "mail", None) if file_or_mail else None
        if not mail:
            raise NotFound("No mail linked to case")
        return mail
