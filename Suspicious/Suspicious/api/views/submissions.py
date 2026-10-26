import logging

from django.db.models import Q
from django.http import Http404
from django.utils import timezone
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView, RetrieveAPIView, get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.submissions import (
    CanAccessSubmission,
    CanChallengeSubmission,
    has_elevated_view,
    submission_queryset,
    user_has_submission_elevated_access,
)
from api.serializers.challenge import SubmissionChallengeSerializer
from api.serializers.submissions import (
    normalize_case_result,
    normalize_case_status,
    AdminSubmissionDetailsSerializer,
    SubmissionDetailsSerializer,
    SubmissionListSerializer,
)
from api.audit import log_thehive_push
from api.utils.analyzer_reports import reports_for_case
from api.views.downloads import get_request_ip
from api.views.investigations import IsInvestigator, _dedup_analyzer_reports
from case_handler.models import Case
from tasp.services.challenge import CaseChallengeService, notify_and_record_challenge

logger = logging.getLogger(__name__)


CASE_LIST_SELECT_RELATED = (
    "fileOrMail",
    "fileOrMail__file",
    "fileOrMail__mail",
    "nonFileIocs",
    "nonFileIocs__url",
    "nonFileIocs__ip",
    "nonFileIocs__hash",
)

CASE_DETAIL_SELECT_RELATED = CASE_LIST_SELECT_RELATED + (
    "reporter",
    "last_update_by",
)


def case_analyzer_reports(case) -> list:
    """Newest AnalyzerReport per (analyzer, target) across every observable of a
    case. Shared by the submission detail and ticket views.

    Byte-equivalent to what the investigation detail builds: same targets, same
    select_related, same ``-creation_date, -pk`` order, same Python dedup.
    """
    return _dedup_analyzer_reports(reports_for_case(case))


class SubmissionPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class SubmissionListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SubmissionListSerializer
    pagination_class = SubmissionPagination

    ORDERING_MAP = {
        "created_at": "creation_date",
        "-created_at": "-creation_date",
        "id": "id",
        "-id": "-id",
        "status": "status",
        "-status": "-status",
        "result": "results",
        "-result": "-results",
    }

    def _is_truthy(self, value: str) -> bool:
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def get_base_queryset(self):
        return Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED)

    def get_queryset(self):
        queryset = submission_queryset(self.get_base_queryset(), self.request.user)

        mine = self.request.query_params.get("mine")
        if self._is_truthy(mine):
            queryset = queryset.filter(reporter=self.request.user)

        external_ref = (self.request.query_params.get("external_ref") or "").strip()
        if external_ref:
            queryset = queryset.filter(external_ref=external_ref)

        search = (self.request.query_params.get("search") or "").strip()
        if search:
            id_q = Q(pk=int(search)) if search.isdigit() else Q()
            # .distinct(): observable_group__artifacts is a reverse FK, so the
            # join fans a group case out to one row per indicator.
            queryset = queryset.filter(
                id_q
                | Q(description__icontains=search)
                | Q(reporter__email__icontains=search)
                | Q(reporter__username__icontains=search)
                | Q(fileOrMail__mail__subject__icontains=search)
                | Q(fileOrMail__file__file_path__icontains=search)
                | Q(nonFileIocs__url__address__icontains=search)
                | Q(nonFileIocs__ip__address__icontains=search)
                | Q(nonFileIocs__hash__value__icontains=search)
                | Q(observable_group__artifacts__url__address__icontains=search)
                | Q(observable_group__artifacts__ip__address__icontains=search)
                | Q(observable_group__artifacts__hash__value__icontains=search)
                | Q(observable_group__artifacts__domain__value__icontains=search)
            ).distinct()

        ordering = self.request.query_params.get("ordering", "-created_at")
        db_ordering = self.ORDERING_MAP.get(ordering)
        if db_ordering is None:
            raise ValidationError(
                {
                    "ordering": (
                        "Unsupported ordering field. Allowed values: "
                        f"{', '.join(self.ORDERING_MAP.keys())}."
                    )
                }
            )

        return queryset.order_by(db_ordering, "-id")

    @extend_schema(
        summary="List submissions",
        parameters=[
            OpenApiParameter(name="mine", type=bool, location=OpenApiParameter.QUERY, required=False,
                description="When true, restricts results to the authenticated user's submissions."),
            OpenApiParameter(name="search", type=str, location=OpenApiParameter.QUERY, required=False,
                description="Case-insensitive substring match across id, description, reporter, "
                            "mail subject, file path, url/ip/hash."),
            OpenApiParameter(name="external_ref", type=str, location=OpenApiParameter.QUERY, required=False,
                description="Exact match on the external_ref given at submission time."),
            OpenApiParameter(name="ordering", type=str, location=OpenApiParameter.QUERY, required=False,
                enum=["created_at", "-created_at", "id", "-id", "status", "-status", "result", "-result"],
                description="Ordering field."),
            OpenApiParameter(name="page", type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name="page_size", type=int, location=OpenApiParameter.QUERY, required=False,
                description="Maximum 100."),
        ],
        examples=[OpenApiExample("Only my submissions", value={"mine": True, "ordering": "-created_at"}, request_only=True)],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class SubmissionDetailsView(RetrieveAPIView):
    permission_classes = [IsAuthenticated, CanAccessSubmission]
    lookup_url_kwarg = "submission_id"

    def get_queryset(self):
        queryset = (
            Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED)
            .prefetch_related(
                "fileOrMail__mail__mail_attachments",
                "fileOrMail__mail__mail_artifacts",
                "fileOrMail__mail__mail_artifacts__artifactIsUrl",
                "fileOrMail__mail__mail_artifacts__artifactIsUrl__url",
                "fileOrMail__mail__mail_artifacts__artifactIsIp",
                "fileOrMail__mail__mail_artifacts__artifactIsHash",
                "fileOrMail__mail__mail_artifacts__artifactIsDomain",
                "fileOrMail__mail__mail_artifacts__artifactIsMailAddress",
            )
        )
        return submission_queryset(queryset, self.request.user)

    def get_serializer_class(self):
        if user_has_submission_elevated_access(self.request.user):  # raw itself is gated per case
            return AdminSubmissionDetailsSerializer
        return SubmissionDetailsSerializer

    def get_object(self):
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs[self.lookup_url_kwarg])
        self.check_object_permissions(self.request, obj)
        return obj

    def _get_analyzer_reports_queryset(self, obj: Case):
        # No .distinct() needed: every filter is a plain equality/IN on
        # AnalyzerReport's own FK columns, and every select_related() relation
        # is forward FK/O2O: structurally can't fan out into duplicate rows.
        return case_analyzer_reports(obj)

    @extend_schema(summary="Retrieve submission details")
    def retrieve(self, request, *args, **kwargs):
        obj = self.get_object()
        analyzer_reports = list(self._get_analyzer_reports_queryset(obj))

        serializer = self.get_serializer(
            obj,
            context={
                **self.get_serializer_context(),
                "analyzer_reports": analyzer_reports,
            },
        )
        return Response(serializer.data)


class SubmissionChallengeView(APIView):
    permission_classes = [IsAuthenticated, CanChallengeSubmission]

    def get_object(self, submission_id: int):
        obj = get_object_or_404(
            Case.objects.only("id", "reporter_id", "is_challenged", "is_challengeable", "status"),
            pk=submission_id,
            reporter_id=self.request.user.id,  # someone else's id is a 404, like a missing one
        )
        self.check_object_permissions(self.request, obj)
        return obj

    @extend_schema(summary="Challenge a submission")
    def post(self, request, submission_id: int):
        obj = self.get_object(submission_id)

        serializer = SubmissionChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if obj.is_challenged:
            raise ValidationError({"detail": "Submission already challenged."})
        if not obj.is_challengeable:
            raise ValidationError({"detail": "Submission cannot be challenged."})

        try:
            CaseChallengeService(obj, logger).mark_challenged(
                serializer.validated_data["proposed_result"], serializer.validated_data["reason"])
        except ValueError:  # lost a race with another challenge of the same case
            raise ValidationError({"detail": "Submission already challenged."})

        try:
            notify_and_record_challenge(obj, logger)
        except Exception:
            logger.exception("Challenge notify failed for case %s", obj.id)

        return Response({"detail": "Challenge submitted."}, status=status.HTTP_200_OK)


_RECOMMENDED_ACTION = {
    "Dangerous": "Block the listed observables at the perimeter and notify the reporter; "
                 "treat as a confirmed threat.",
    "Suspicious": "Review the listed observables against the analyzer evidence; block if confirmed.",
    "Safe": "No action required; close the case.",
    "Inconclusive": "Insufficient signal, escalate for manual analyst review.",
}


def build_ticket(case) -> dict:
    """The ticket-shaped SOAR payload for a case: verdict, observables with
    their per-IOC verdict, and an analyzer summary."""
    from connectors.contrib.thehive.phishing import THEHIVE_SEVERITY, ticket_observables
    from score_process.scoring.classification import derive_threat_classification
    from score_process.scoring.health import analysis_health
    from score_process.scoring.sources import source_verdict_from_report

    reports = case_analyzer_reports(case)
    by_verdict: dict = {}
    analyzers: list = []
    for rep in reports:
        sv = source_verdict_from_report(rep)
        by_verdict[sv.verdict] = by_verdict.get(sv.verdict, 0) + 1
        if sv.name not in analyzers:
            analyzers.append(sv.name)

    result = str(case.results)
    return {
        "case_id": case.id,
        "external_ref": case.external_ref,
        "generated_at": timezone.now().isoformat(),
        "title": f"Suspicious case #{case.id}: {result}",
        "verdict": {
            "result": result,
            "score": case.final_score,
            "confidence": case.final_confidence,
            "severity": THEHIVE_SEVERITY.get(result, 2),
            "tlp": 2,
            "pap": 2,
            "ai_classification": case.category_ai or case.results_ai,
            "rationale": list(case.verdict_rationale or []),
        },
        "threat_classification": derive_threat_classification(case, reports),
        "analysis_health": analysis_health(reports),
        "observables": ticket_observables(case),
        "analyzer_summary": {
            "total_reports": len(reports),
            "by_verdict": by_verdict,
            "analyzers": analyzers,
        },
        "recommended_action": _RECOMMENDED_ACTION.get(
            result, _RECOMMENDED_ACTION["Inconclusive"]
        ),
    }


def build_verdict(case) -> dict:
    """Compact poll payload for an automation waiting on a case.

    ``done`` is the one field a poller needs: while it is false ``result`` is
    null, because ``Case.results`` holds a placeholder until scoring finishes.
    Per-observable verdicts and analysis health are added only once done, so a
    poll in flight stays one indexed read.
    """
    from case_handler.lifecycle import LifecycleState
    from score_process.scoring.health import analysis_health

    done = case.lifecycle_state in (LifecycleState.FINALIZED, LifecycleState.CONTESTED)
    body = {
        "case_id": case.id,
        "external_ref": case.external_ref,
        "status": normalize_case_status(case.status),
        "done": done,
        "created_at": case.creation_date.isoformat() if case.creation_date else None,
        "finalized_at": case.finalized_at.isoformat() if case.finalized_at else None,
        "result": None,
        "score": None,
        "confidence": None,
        "ai_classification": None,
        "is_allowlisted": case.is_allowlisted,
    }
    if not done:
        return body

    from connectors.contrib.thehive.phishing import ticket_observables

    body.update(
        result=normalize_case_result(case.results),
        score=case.final_score,
        confidence=case.final_confidence,
        ai_classification=case.category_ai or case.results_ai,
        analysis_health=analysis_health(case_analyzer_reports(case)),
        observables=ticket_observables(case),
    )
    return body


class SubmissionVerdictView(APIView):
    """Poll target for automations: status, ``done`` and, once done, the verdict.
    Open to the reporter (the account that submitted) and to investigators."""

    permission_classes = [IsAuthenticated, CanAccessSubmission]

    @extend_schema(summary="Compact verdict for a submission (poll until done)")
    def get(self, request, submission_id: int):
        queryset = submission_queryset(
            Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED), request.user
        )
        case = get_object_or_404(queryset, pk=submission_id)
        self.check_object_permissions(request, case)
        return Response(build_verdict(case))


class SubmissionTicketView(APIView):
    """GET: the ticket-shaped SOAR payload for a case (verdict, per-IOC
    verdicts, analyzer summary). POST: push that payload to TheHive as an
    alert: creating one, or updating the case's existing alert."""

    permission_classes = [IsAuthenticated, IsInvestigator]

    def _case(self, submission_id: int) -> Case:
        case = get_object_or_404(
            submission_queryset(
                Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED), self.request.user
            ),
            pk=submission_id,
        )
        if not has_elevated_view(self.request.user, case):
            raise Http404  # a reporter (even a CISO) has no analyst ticket
        return case

    @extend_schema(summary="Ticket-shaped SOAR payload for a submission")
    def get(self, request, submission_id: int):
        return Response(build_ticket(self._case(submission_id)))

    @extend_schema(summary="Push a submission's ticket to TheHive as an alert")
    def post(self, request, submission_id: int):
        from connectors.contrib.thehive.phishing import TheHivePushError, push_ticket
        from connectors.delivery import get_state
        from connectors.registry import registry

        case = self._case(submission_id)

        if not get_state("thehive").enabled:
            return Response({"detail": "TheHive connector is not enabled."},
                            status=status.HTTP_409_CONFLICT)
        cfg = registry.instantiate("thehive").config
        url, key = cfg.get("url"), cfg.get("api_key")
        if not url or not key:
            return Response({"detail": "TheHive connector is not configured."},
                            status=status.HTTP_409_CONFLICT)

        ip = get_request_ip(request)
        try:
            result = push_ticket(
                case, build_ticket(case), url=url, key=key,
                pushed_by=request.user.get_username(),
            )
        except TheHivePushError as exc:
            log_thehive_push(
                user=request.user, case_id=case.id, alert_id=case.thehive_alert_id,
                outcome="failed", ip=ip, error=str(exc),
            )
            return Response({"detail": "TheHive push failed."},
                            status=status.HTTP_502_BAD_GATEWAY)
        log_thehive_push(
            user=request.user, case_id=case.id, alert_id=result["alert_id"],
            outcome=result["status"], ip=ip,
        )
        return Response(result, status=status.HTTP_200_OK)
