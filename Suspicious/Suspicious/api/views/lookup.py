from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.utils.indicators import parse_indicators
from api.views.investigations import IsInvestigator
from connectors.contrib.thehive.phishing import ioc_level_to_verdict
from cortex_job.models import AnalyzerReport
from domain_process.models import Domain
from hash_process.models import Hash
from ip_process.models import IP
from url_process.models import URL

# type -> (model, value column, AnalyzerReport FK). Rows are not unique on
# value, so the newest few are inspected and the first one that was actually
# analyzed wins.
_LOOKUP = {
    "url": (URL, "address", "url"),
    "ip": (IP, "address", "ip"),
    "domain": (Domain, "value", "domain"),
    "hash": (Hash, "value", "hash"),
}
_CANDIDATES = 5


def _latest_analyzed(model, column: str, fk: str, value: str):
    """(row, newest report date) for the newest analyzed row with this value,
    or (None, None). ``ioc_level`` defaults to "info" on a row nobody analyzed,
    so only a row with an AnalyzerReport counts as a known verdict."""
    rows = model.objects.filter(**{column: value}).order_by("-id")[:_CANDIDATES]
    for row in rows:
        latest = (
            AnalyzerReport.objects.filter(**{fk: row})
            .order_by("-creation_date")
            .values_list("creation_date", flat=True)
            .first()
        )
        if latest is not None:
            return row, latest
    return None, None


class ObservableLookupView(APIView):
    """Verdict already on file for one observable, without creating a case.

    Meant for reputation-style callers (a SOAR ``!url`` / ``!ip`` / ``!file`` /
    ``!domain`` command) that need an answer for a value that may have been
    analyzed before. ``known: false`` means nothing is on file: submit it.
    """

    permission_classes = [IsAuthenticated, IsInvestigator]

    @extend_schema(
        summary="Look up the stored verdict of an observable",
        parameters=[
            OpenApiParameter(name="type", type=str, location=OpenApiParameter.QUERY, required=True,
                enum=sorted(_LOOKUP), description="Observable type."),
            OpenApiParameter(name="value", type=str, location=OpenApiParameter.QUERY, required=True,
                description="The URL, IP, domain or hash. Defanged values are accepted."),
        ],
    )
    def get(self, request):
        kind = (request.query_params.get("type") or "").strip().lower()
        raw = request.query_params.get("value") or ""
        if kind not in _LOOKUP:
            raise ValidationError({"type": f"Must be one of: {', '.join(sorted(_LOOKUP))}."})

        parsed = [p for p in parse_indicators(raw) if p.type]
        if len(parsed) != 1 or parsed[0].type != kind:
            raise ValidationError({"value": f"Not a single valid {kind}."})
        value = parsed[0].value.lower() if kind == "hash" else parsed[0].value

        model, column, fk = _LOOKUP[kind]
        row, last_analyzed = _latest_analyzed(model, column, fk, value)
        if row is None:
            return Response({"type": kind, "value": value, "known": False})
        return Response({
            "type": kind,
            "value": value,
            "known": True,
            "verdict": ioc_level_to_verdict(row.ioc_level),
            "score": row.ioc_score,
            "confidence": row.ioc_confidence,
            "last_analyzed": last_analyzed.isoformat(),
        })
