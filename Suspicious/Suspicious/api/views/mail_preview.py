"""
GET /api/cases/<case_id>/mail-preview.png

Streams the cached PNG preview of the email linked to a case
(`Mail.preview_png`). The preview is generated at ingestion time by
`mail_feeder.utils.email_preview.eml2png_renderer.Eml2PngRenderer`.

Returns 404 when:
- the case does not exist
- the case has no linked mail (file-only / IOC-only submission)
- the mail has no rendered preview yet
"""
from __future__ import annotations

import logging

from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission
from case_handler.models import Case

logger = logging.getLogger(__name__)


class MailPreviewView(APIView):
    """Stream the PNG preview of the email attached to a case."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def get(self, request, case_id: int):
        case = self._get_case(case_id)
        self.check_object_permissions(request, case)

        mail = self._get_mail(case)
        preview = getattr(mail, "preview_png", None)
        if not preview or not getattr(preview, "name", ""):
            raise NotFound("No preview available")

        try:
            fh = preview.open("rb")
        except Exception as exc:
            logger.warning(
                "Failed to open mail preview for case_id=%s mail_id=%s: %s",
                case.pk, mail.pk, exc,
            )
            raise NotFound("Preview unavailable") from exc

        response = StreamingHttpResponse(
            _stream(fh), content_type="image/png",
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


def _stream(fh, chunk_size: int = 32 * 1024):
    try:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            yield chunk
    finally:
        try:
            fh.close()
        except Exception:
            pass
