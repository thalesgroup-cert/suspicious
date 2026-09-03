"""Downloadable per-case IOC analysis report (HTML)."""
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


class CaseReportView(APIView):
    permission_classes = [IsAuthenticated, IsInvestigator]
    # ponytail: html renderer so DRF's ?format=html negotiation doesn't 404;
    # the view still returns a plain HttpResponse, untouched by the renderer.
    renderer_classes = [StaticHTMLRenderer]

    def get(self, request, case_id):
        case = get_object_or_404(Case, pk=case_id)
        observables = assemble_observables(case, full=True) if case.observable_group_id else []
        html = render_to_string(
            "case_report/report.html",
            {"case": case, "observables": observables, "generated_at": timezone.now()},
        )
        resp = HttpResponse(html, content_type="text/html")
        resp["Content-Disposition"] = f'attachment; filename="case-{case.id}-report.html"'
        return resp
