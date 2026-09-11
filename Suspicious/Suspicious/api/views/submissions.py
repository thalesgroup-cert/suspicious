import logging

from django.db.models import Q
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
    user_has_submission_elevated_access,
)
from api.serializers.challenge import SubmissionChallengeSerializer
from api.serializers.submissions import (
    AdminSubmissionDetailsSerializer,
    SubmissionDetailsSerializer,
    SubmissionListSerializer,
)
from api.utils.analyzer_reports import reports_for_case
from api.views.investigations import IsInvestigator, _dedup_analyzer_reports
from case_handler.models import Case
from tasp.services.challenge import notify_and_record_challenge

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
        queryset = self.get_base_queryset()

        if not user_has_submission_elevated_access(self.request.user):
            queryset = queryset.filter(reporter=self.request.user)

        mine = self.request.query_params.get("mine")
        if self._is_truthy(mine):
            queryset = queryset.filter(reporter=self.request.user)

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
        if not user_has_submission_elevated_access(self.request.user):
            queryset = queryset.filter(reporter=self.request.user)
        return queryset

    def get_serializer_class(self):
        if user_has_submission_elevated_access(self.request.user):
            return AdminSubmissionDetailsSerializer
        return SubmissionDetailsSerializer

    def get_object(self):
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs[self.lookup_url_kwarg])
        self.check_object_permissions(self.request, obj)
        return obj

    def _get_analyzer_reports_queryset(self, obj: Case):
        # No .distinct() needed: every filter is a plain equality/IN on
        # AnalyzerReport's own FK columns, and every select_related() relation
        # is forward FK/O2O — structurally can't fan out into duplicate rows.
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

        from case_handler.lifecycle import LifecycleState, transition

        obj.is_challenged = True
        obj.challenge_proposed_result = serializer.validated_data["proposed_result"]
        obj.challenge_reason = serializer.validated_data.get("reason", "")
        obj.save(update_fields=[
            "is_challenged", "challenge_proposed_result", "challenge_reason", "last_update",
        ])
        if obj.lifecycle_state == LifecycleState.FINALIZED:
            transition(obj, LifecycleState.CONTESTED)
        else:
            obj.status = "Challenged"
            obj.save(update_fields=["status"])

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
    "Inconclusive": "Insufficient signal — escalate for manual analyst review.",
}


def build_ticket(case) -> dict:
    """The ticket-shaped SOAR payload for a case: verdict, observables with
    their per-IOC verdict, and an analyzer summary."""
    from connectors.contrib.thehive.phishing import THEHIVE_SEVERITY, ticket_observables
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
        "generated_at": timezone.now().isoformat(),
        "title": f"Suspicious case #{case.id} — {result}",
        "verdict": {
            "result": result,
            "score": case.final_score,
            "confidence": case.final_confidence,
            "severity": THEHIVE_SEVERITY.get(result, 2),
            "tlp": 2,
            "pap": 2,
            # ponytail: results_ai/category_ai stand-in until roadmap item #2
            # (Case.threat_classification) lands.
            "ai_classification": case.category_ai or case.results_ai,
            "rationale": list(case.verdict_rationale or []),
        },
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


class SubmissionTicketView(APIView):
    """GET: the ticket-shaped SOAR payload for a case (verdict, per-IOC
    verdicts, analyzer summary). POST: push that payload to TheHive as an
    alert — creating one, or updating the case's existing alert."""

    permission_classes = [IsAuthenticated, IsInvestigator]

    def _case(self, submission_id: int) -> Case:
        return get_object_or_404(
            Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED), pk=submission_id
        )

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

        try:
            result = push_ticket(case, build_ticket(case), url=url, key=key)
        except TheHivePushError as exc:
            return Response({"detail": f"TheHive push failed: {exc}"},
                            status=status.HTTP_502_BAD_GATEWAY)
        return Response(result, status=status.HTTP_200_OK)
