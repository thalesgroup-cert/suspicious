"""POST /api/submissions/<id>/urls/<url_id>/analyze/ — on-demand re-analysis.

Promotes a `skipped` (or stale `reused`) URL to `pending` and dispatches Cortex
for that single URL. Reuses CanAccessSubmission so only the submission owner (or
an elevated role) can trigger it; a URL not belonging to an accessible
submission returns 404.
"""
import logging

from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission
from api.serializers.submissions import case_url_ids
from case_handler.models import Case
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from url_process.models import URL

logger = logging.getLogger(__name__)


class SubmissionUrlAnalyzeView(APIView):
    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def post(self, request, submission_id: int, url_id: int):
        case = get_object_or_404(Case, pk=submission_id)
        self.check_object_permissions(request, case)

        # Fix 1: Bind url_id to the submission — prevents horizontal IDOR.
        if url_id not in case_url_ids(case):
            raise Http404

        url = get_object_or_404(URL, pk=url_id)

        if url.analysis_status in (URL.AnalysisStatus.PENDING, URL.AnalysisStatus.ANALYZED):
            return Response({"status": "already_pending", "url_id": url.id},
                            status=status.HTTP_200_OK)

        # Fix 2: Capture prior state before mutating so we can roll back on failure.
        prior_status = url.analysis_status
        prior_analyzed_url_id = url.analyzed_url_id

        url.analysis_status = URL.AnalysisStatus.PENDING
        url.analyzed_url = None
        url.save(update_fields=["analysis_status", "analyzed_url"])

        try:
            CortexJob().launch_cortex_jobs(value=url, data_type="url", case=case)
        except Exception:
            logger.exception("On-demand URL analysis dispatch failed (url=%s case=%s)",
                             url.id, case.id)
            # Restore prior state so subsequent calls are not stuck in PENDING.
            url.analysis_status = prior_status
            url.analyzed_url_id = prior_analyzed_url_id
            url.save(update_fields=["analysis_status", "analyzed_url"])
            return Response({"status": "dispatch_failed", "url_id": url.id},
                            status=status.HTTP_502_BAD_GATEWAY)

        return Response({"status": "queued", "url_id": url.id},
                        status=status.HTTP_202_ACCEPTED)
