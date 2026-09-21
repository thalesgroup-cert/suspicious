"""GET /api/cases/<case_id>/screenshot.png

Streams the page screenshot captured by a screenshot analyzer
(Lookyloo_Screenshot / Urlscan.io_Scan) for a case, straight from MinIO,
addressed by AnalyzerReport.screenshot_bucket / screenshot_key.

404 when the case has no captured screenshot or the MinIO object is
unreachable. ?report=<id> selects a specific report's screenshot (IOC
groups carry many URLs, hence many candidate screenshots).
"""
from __future__ import annotations

import logging

from django.db.models import Case as WhenCase, IntegerField, Value, When
from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission
from api.utils.analyzer_reports import reports_for_case
from case_handler.models import Case
from common.clients import get_s3_client

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 32 * 1024


class CaseScreenshotView(APIView):
    """Stream a screenshot analyzer's captured page image for a case."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def get(self, request, case_id: int):
        try:
            case = Case.objects.get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Case not found") from exc
        self.check_object_permissions(request, case)

        candidates = reports_for_case(case).exclude(screenshot_key="")

        raw_report_id = request.query_params.get("report")
        if raw_report_id not in (None, ""):
            try:
                report_id = int(raw_report_id)
            except (TypeError, ValueError) as exc:
                raise NotFound("Unknown report") from exc
            report = candidates.filter(pk=report_id).first()
        else:
            report = (
                candidates.annotate(
                    _pref=WhenCase(
                        When(analyzer__name__icontains="lookyloo", then=Value(0)),
                        default=Value(1),
                        output_field=IntegerField(),
                    )
                )
                .order_by("_pref", "-last_update")
                .first()
            )
        if report is None:
            raise NotFound("No screenshot available")

        try:
            obj = get_s3_client().get_object(
                report.screenshot_bucket, report.screenshot_key
            )
        except Exception as exc:
            logger.warning(
                "MinIO get_object failed: case_id=%s bucket=%s key=%s err=%s",
                case.pk, report.screenshot_bucket, report.screenshot_key, exc,
            )
            raise NotFound("Screenshot unavailable") from exc

        response = StreamingHttpResponse(_stream(obj), content_type="image/png")
        response["Cache-Control"] = "private, max-age=300"
        response["Content-Disposition"] = (
            f'inline; filename="case_{case.pk}_screenshot.png"'
        )
        return response


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
