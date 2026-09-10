"""Downloadable per-case IOC analysis report (HTML)."""
import base64
import logging

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import StaticHTMLRenderer
from rest_framework.views import APIView

from api.utils.observable_report import assemble_observables
from api.views.investigations import IsInvestigator
from case_handler.models import Case
from common.clients import get_s3_client
from cortex_job.models import AnalyzerReport

logger = logging.getLogger(__name__)

# Total bytes of screenshot data embedded across one report. A downloaded HTML
# file can't authenticate to /api/…, so screenshots must be inlined as data
# URIs — but not without a ceiling.
_REPORT_IMG_CAP = 6 * 1024 * 1024


def _inline_screenshots(observables):
    """Embed each observable's page screenshot as a base64 ``data:`` URI,
    fetched from MinIO, until the running total exceeds ``_REPORT_IMG_CAP``.
    Past the cap (or on a fetch failure) the row is marked ``screenshot_omitted``
    so the template can render a note instead.
    """
    used = 0
    client = None
    for o in observables:
        url = o.get("screenshot_url")
        o["screenshot_data_uri"] = None
        o["screenshot_omitted"] = False
        if not url:
            continue
        o["screenshot_omitted"] = True  # until an image is actually inlined
        if used >= _REPORT_IMG_CAP:
            continue  # budget already blown — don't touch the DB or MinIO
        report_id = url.split("report=")[-1]
        try:
            rep = (
                AnalyzerReport.objects.filter(pk=report_id)
                .exclude(screenshot_key="")
                .first()
            )
            if rep is None:
                continue
            client = client or get_s3_client()
            data = client.get_object(
                rep.screenshot_bucket, rep.screenshot_key
            ).read()
        except Exception as exc:
            logger.warning("report screenshot inline failed: report=%s err=%s",
                           report_id, exc)
            continue
        if used + len(data) > _REPORT_IMG_CAP:
            used = _REPORT_IMG_CAP  # budget spent: skip the rest without fetching
            continue
        used += len(data)
        o["screenshot_data_uri"] = (
            "data:image/png;base64," + base64.b64encode(data).decode()
        )
        o["screenshot_omitted"] = False
    return observables


class CaseReportView(APIView):
    permission_classes = [IsAuthenticated, IsInvestigator]
    # ponytail: html renderer so DRF's ?format=html negotiation doesn't 404;
    # the view still returns a plain HttpResponse, untouched by the renderer.
    renderer_classes = [StaticHTMLRenderer]

    def get(self, request, case_id):
        case = get_object_or_404(Case, pk=case_id)
        observables = assemble_observables(case, full=True) if case.observable_group_id else []
        observables = _inline_screenshots(observables)
        html = render_to_string(
            "case_report/report.html",
            {"case": case, "observables": observables, "generated_at": timezone.now()},
        )
        resp = HttpResponse(html, content_type="text/html")
        resp["Content-Disposition"] = f'attachment; filename="case-{case.id}-report.html"'
        return resp
