"""Downloadable per-case IOC analysis report (HTML)."""
import base64
import logging

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, StaticHTMLRenderer
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission, submission_queryset
from api.utils.case_report_markdown import build_markdown_report
from api.utils.case_report_model import build_case_report
from api.utils.report_facts import LEGEND
from case_handler.models import Case
from common.storage import get_store
from cortex_job.models import AnalyzerReport

logger = logging.getLogger(__name__)

# Total bytes of screenshot data embedded across one report. A downloaded HTML
# file can't authenticate to /api/…, so screenshots must be inlined as data
# URIs: but not without a ceiling.
_REPORT_IMG_CAP = 6 * 1024 * 1024


def _inline_screenshots(blocks):
    """Embed each block's page screenshot as a base64 ``data:`` URI,
    fetched from the object store, until the running total exceeds
    ``_REPORT_IMG_CAP``. Past the cap (or on a fetch failure) the block is
    marked ``screenshot_omitted`` so the template can render a note instead.
    """
    used = 0
    store = None
    for b in blocks:
        url = b.screenshot_url
        b.screenshot_data_uri = None
        b.screenshot_omitted = False
        if not url:
            continue
        b.screenshot_omitted = True  # until an image is actually inlined
        if used >= _REPORT_IMG_CAP:
            continue  # budget already blown: don't touch the DB or the store
        report_id = url.split("report=")[-1]
        try:
            rep = (
                AnalyzerReport.objects.filter(pk=report_id)
                .exclude(screenshot_key="")
                .first()
            )
            if rep is None:
                continue
            store = store or get_store()
            with store.open(rep.screenshot_bucket, rep.screenshot_key) as stream:
                data = stream.read()
        except Exception as exc:
            logger.warning("report screenshot inline failed: report=%s err=%s",
                           report_id, exc)
            continue
        if used + len(data) > _REPORT_IMG_CAP:
            used = _REPORT_IMG_CAP  # budget spent: skip the rest without fetching
            continue
        used += len(data)
        b.screenshot_data_uri = (
            "data:image/png;base64," + base64.b64encode(data).decode()
        )
        b.screenshot_omitted = False
    return blocks


def _load_report(request, view, case_id):
    case = get_object_or_404(
        submission_queryset(
            Case.objects.select_related(
                "reporter", "fileOrMail__mail", "fileOrMail__file__linked_hash",
                "ai_assessment", "campaign_membership__campaign",
            ),
            request.user,
        ),
        pk=case_id,
    )
    view.check_object_permissions(request, case)
    return case, build_case_report(case, request, now=timezone.now())


class CaseReportView(APIView):
    permission_classes = [IsAuthenticated, CanAccessSubmission]
    # ponytail: html renderer so DRF's ?format=html negotiation doesn't 404;
    # the view still returns a plain HttpResponse, untouched by the renderer.
    renderer_classes = [StaticHTMLRenderer]

    def get(self, request, case_id):
        case, report = _load_report(request, self, case_id)
        _inline_screenshots(report.blocks + ([report.case_analysis] if report.case_analysis else []))
        html = render_to_string("case_report/report.html", {"report": report, "legend": LEGEND})
        resp = HttpResponse(html, content_type="text/html")
        resp["Content-Disposition"] = f'attachment; filename="case-{case.id}-report.html"'
        return resp


class MarkdownRenderer(BaseRenderer):
    media_type = "text/markdown"
    format = "md"
    charset = "utf-8"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data if isinstance(data, bytes) else str(data).encode("utf-8")


class CaseReportMarkdownView(APIView):
    """The case report as Markdown, for tickets, wikis and chat."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]
    renderer_classes = [MarkdownRenderer]

    def get(self, request, case_id):
        case, report = _load_report(request, self, case_id)
        text = build_markdown_report(report)
        resp = HttpResponse(text, content_type="text/markdown; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="case-{case.id}-report.md"'
        return resp
