from __future__ import annotations

import logging

from django.db.models import Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from case_handler.models import Case
from cortex_job.models import AnalyzerReport
from cortex_job.cortex_utils.case_targets import collect_case_targets
from api.utils.investigation_pagination import InvestigationPagination
from api.serializers.investigations import (
    API_RESULT_TO_INTERNAL,
    API_STATUS_TO_INTERNAL,
    InvestigationDetailsSerializer,
    InvestigationGlobalEditRequestSerializer,
    InvestigationListQuerySerializer,
    InvestigationRowSerializer,
)
from score_process.score_utils.send_mail.service import MailNotificationService

logger = logging.getLogger(__name__)


CASE_LIST_SELECT_RELATED = (
    "reporter",
    "fileOrMail",
    "fileOrMail__file",
    "fileOrMail__mail",
    "nonFileIocs",
    "nonFileIocs__url",
    "nonFileIocs__ip",
    "nonFileIocs__hash",
)

CASE_DETAIL_SELECT_RELATED = (
    "reporter",
    "last_update_by",
    "fileOrMail",
    "fileOrMail__file",
    "fileOrMail__mail",
    "nonFileIocs",
    "nonFileIocs__url",
    "nonFileIocs__ip",
    "nonFileIocs__hash",
)

ANALYZER_REPORT_SELECT_RELATED = (
    "analyzer",
    "url",
    "domain",
    "mail",
    "hash",
    "file",
    "ip",
    "mail_body",
    "mail_header",
)


def user_is_investigator(user) -> bool:
    return user.groups.filter(name__in=["CERT", "CISO", "Admin"]).exists()


class IsInvestigator(BasePermission):
    message = "Not authorized."

    def has_permission(self, request, view) -> bool:
        user = request.user
        return bool(user and user.is_authenticated and user_is_investigator(user))



def _dedup_analyzer_reports(reports) -> list:
    """
    Keep only the most recent AnalyzerReport per (analyzer_id, target_key).

    The queryset is already ordered by -creation_date, -pk so the first
    occurrence of each key is the newest. We preserve that order in the
    returned list so the caller doesn't need to re-sort.

    target_key is the first non-null FK among url/domain/mail/hash/file/ip/
    mail_body/mail_header — same priority as resolve_analyzer_report_target.
    """
    def _target_key(r) -> tuple:
        for attr, label in (
            ("url_id",         "url"),
            ("domain_id",      "domain"),
            ("mail_id",        "mail"),
            ("hash_id",        "hash"),
            ("file_id",        "file"),
            ("ip_id",          "ip"),
            ("mail_body_id",   "mail_body"),
            ("mail_header_id", "mail_header"),
        ):
            val = getattr(r, attr, None)
            if val:
                return (label, val)
        return ("unknown", None)

    seen: set = set()
    result: list = []
    for report in reports:
        key = (report.analyzer_id, _target_key(report))
        if key not in seen:
            seen.add(key)
            result.append(report)
    return result


class InvestigationAccessMixin:
    analyzer_report_select_related = ANALYZER_REPORT_SELECT_RELATED

    def get_case_list_queryset(self):
        return Case.objects.select_related(*CASE_LIST_SELECT_RELATED)

    def get_case_detail_queryset(self):
        return (
            Case.objects.select_related(*CASE_DETAIL_SELECT_RELATED)
            .prefetch_related(
                "fileOrMail__mail__mail_attachments",
                "fileOrMail__mail__mail_artifacts",
                "fileOrMail__mail__mail_artifacts__artifactIsUrl",
                "fileOrMail__mail__mail_artifacts__artifactIsIp",
                "fileOrMail__mail__mail_artifacts__artifactIsHash",
                "fileOrMail__mail__mail_artifacts__artifactIsDomain",
                "fileOrMail__mail__mail_artifacts__artifactIsMailAddress",
            )
        )

    def get_case_or_404(self, case_id: int) -> Case:
        try:
            return self.get_case_detail_queryset().get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Investigation not found.") from exc

    def get_analyzer_reports_queryset(self, obj: Case):
        targets = collect_case_targets(obj)
        if not targets:
            return AnalyzerReport.objects.none()

        field_by_type = {
            "file": "file_id", "mail_body": "mail_body_id", "mail_header": "mail_header_id",
            "url": "url_id", "ip": "ip_id", "hash": "hash_id", "domain": "domain_id",
            "mail": "mail_id",
        }
        ids_by_field: dict[str, list[int]] = {}
        for instance, data_type in targets:
            ids_by_field.setdefault(field_by_type[data_type], []).append(instance.pk)

        query = Q()
        for field, ids in ids_by_field.items():
            query |= Q(**{f"{field}__in": ids})

        # No .distinct() needed: every filter above is a plain equality/IN on
        # AnalyzerReport's own FK columns (never a reverse/M2M traversal), and
        # every select_related() relation is forward FK/O2O — this queryset
        # structurally can't fan out into duplicate rows. distinct() was
        # forcing MySQL to sort/dedupe the full 9-table-wide join with no
        # LIMIT to cap it, and _dedup_analyzer_reports() below already
        # de-dupes in Python regardless.
        qs = (
            AnalyzerReport.objects
            .filter(query)
            .select_related(*self.analyzer_report_select_related)
            .order_by("-creation_date", "-pk")
        )
        return _dedup_analyzer_reports(qs)

    def filter_case_queryset(self, queryset, validated_filters: dict):
        search = validated_filters.get("search")
        status_filter = validated_filters.get("status", "ALL")
        type_filter = validated_filters.get("type", "ALL")
        result_filter = validated_filters.get("result", "ALL")
        from_date = validated_filters.get("from_date")
        to_date = validated_filters.get("to_date")
        ordering = validated_filters.get("ordering", "-creation_date")

        if search:
            # ── ID search ────────────────────────────────────────────────────
            id_q = Q(pk=int(search)) if search.strip().isdigit() else Q()

            # ── Text search across all meaningful string fields ───────────────
            text_q = (
                Q(description__icontains=search)
                | Q(reporter__email__icontains=search)
                | Q(reporter__username__icontains=search)
                | Q(fileOrMail__mail__subject__icontains=search)
                | Q(fileOrMail__file__file_path__icontains=search)
                | Q(nonFileIocs__url__address__icontains=search)
                | Q(nonFileIocs__ip__address__icontains=search)
                | Q(nonFileIocs__hash__value__icontains=search)
            )

            queryset = queryset.filter(id_q | text_q)

        if status_filter != "ALL":
            if status_filter == "UNKNOWN":
                queryset = queryset.exclude(status__in=API_STATUS_TO_INTERNAL.values())
            else:
                queryset = queryset.filter(status=API_STATUS_TO_INTERNAL[status_filter])

        if type_filter != "ALL":
            if type_filter == "FILE":
                queryset = queryset.filter(fileOrMail__file_id__isnull=False)
            elif type_filter == "MAIL":
                queryset = queryset.filter(fileOrMail__mail_id__isnull=False)
            elif type_filter == "URL":
                queryset = queryset.filter(nonFileIocs__url_id__isnull=False)
            elif type_filter == "IP":
                queryset = queryset.filter(nonFileIocs__ip_id__isnull=False)
            elif type_filter == "HASH":
                queryset = queryset.filter(nonFileIocs__hash_id__isnull=False)
            elif type_filter == "UNKNOWN":
                queryset = queryset.filter(
                    fileOrMail__file_id__isnull=True,
                    fileOrMail__mail_id__isnull=True,
                    nonFileIocs__url_id__isnull=True,
                    nonFileIocs__ip_id__isnull=True,
                    nonFileIocs__hash_id__isnull=True,
                )

        if result_filter != "ALL":
            if result_filter == "UNKNOWN":
                queryset = queryset.exclude(results__in=API_RESULT_TO_INTERNAL.values())
            elif result_filter in API_RESULT_TO_INTERNAL:
                queryset = queryset.filter(results=API_RESULT_TO_INTERNAL[result_filter])

        if result_filter != "ALL":
            if result_filter == "UNKNOWN":
                queryset = queryset.exclude(results__in=API_RESULT_TO_INTERNAL.values())
            elif result_filter in API_RESULT_TO_INTERNAL:
                queryset = queryset.filter(results=API_RESULT_TO_INTERNAL[result_filter])

        if from_date:
            queryset = queryset.filter(creation_date__date__gte=from_date)

        if to_date:
            queryset = queryset.filter(creation_date__date__lte=to_date)

        if ordering == "id":
            queryset = queryset.order_by("pk")
        elif ordering == "-id":
            queryset = queryset.order_by("-pk")
        elif ordering == "creation_date":
            queryset = queryset.order_by("creation_date", "pk")
        elif ordering == "status":
            queryset = queryset.order_by("status", "-creation_date")
        elif ordering == "-status":
            queryset = queryset.order_by("-status", "-creation_date")
        elif ordering == "result":
            queryset = queryset.order_by("results", "-creation_date")
        elif ordering == "-result":
            queryset = queryset.order_by("-results", "-creation_date")
        else:
            queryset = queryset.order_by("-creation_date", "-pk")

        # No .distinct() needed: every relation touched above (fileOrMail,
        # nonFileIocs, and their file/mail/url/ip/hash children) is a
        # forward FK or O2O from Case's side, never reverse/M2M, so a Case
        # row can't fan out into duplicates through these joins. distinct()
        # here was forcing MySQL to sort/dedupe the whole joined result set
        # before LIMIT applied — measured ~1.6s wasted per page on a 41k-row
        # table for zero effect.
        return queryset


@extend_schema(
    tags=["Investigations"],
    parameters=[
        OpenApiParameter(name="page", type=int, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="page_size", type=int, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="search", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="status", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="type", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="from_date", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="to_date", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="ordering", type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="result",   type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name="sort_field", type=str, location=OpenApiParameter.QUERY),
    ],
    responses={
        200: OpenApiResponse(description="Paginated investigation list."),
        403: OpenApiResponse(description="Not authorized."),
    },
)
class InvestigationListView(InvestigationAccessMixin, APIView):
    permission_classes = [IsAuthenticated, IsInvestigator]
    pagination_class = InvestigationPagination

    def get(self, request):
        filter_serializer = InvestigationListQuerySerializer(data=request.query_params)
        filter_serializer.is_valid(raise_exception=True)

        queryset = self.filter_case_queryset(
            self.get_case_list_queryset(),
            filter_serializer.validated_data,
        )

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(queryset, request, view=self)

        serializer = InvestigationRowSerializer(page, many=True, context={"request": request})
        return paginator.get_paginated_response(serializer.data)


@extend_schema(
    tags=["Investigations"],
    responses={
        200: InvestigationDetailsSerializer,
        403: OpenApiResponse(description="Not authorized."),
        404: OpenApiResponse(description="Investigation not found."),
    },
)
class InvestigationDetailsView(InvestigationAccessMixin, APIView):
    permission_classes = [IsAuthenticated, IsInvestigator]

    def get(self, request, case_id: int):
        obj = self.get_case_or_404(case_id)
        analyzer_reports_qs = self.get_analyzer_reports_queryset(obj)

        serializer = InvestigationDetailsSerializer(
            obj,
            context={
                "request": request,
                "analyzer_reports_qs": analyzer_reports_qs,
            },
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Investigations"],
    request=InvestigationGlobalEditRequestSerializer,
    responses={
        200: InvestigationDetailsSerializer,
        400: OpenApiResponse(description="Validation error."),
        403: OpenApiResponse(description="Not authorized."),
        404: OpenApiResponse(description="Investigation not found."),
    },
)
class InvestigationGlobalEditView(InvestigationAccessMixin, APIView):
    permission_classes = [IsAuthenticated, IsInvestigator]

    def patch(self, request, case_id: int):
        obj = self.get_case_or_404(case_id)

        payload = InvestigationGlobalEditRequestSerializer(data=request.data)
        payload.is_valid(raise_exception=True)

        validated = payload.validated_data
        obj.final_score = validated["score"]
        obj.final_confidence = validated["confidence"]
        obj.results = API_RESULT_TO_INTERNAL[validated["classification"]]
        obj.last_update_by = request.user
        obj.save(
            update_fields=[
                "final_score",
                "final_confidence",
                "results",
                "last_update_by",
                "last_update",
            ]
        )

        try:
            MailNotificationService.from_settings().send_review_email(obj)
        except Exception as exc:
            logger.error(
                "Failed to send modification email for case %s: %s",
                obj.id, exc,
                exc_info=True,
            )

        analyzer_reports_qs = self.get_analyzer_reports_queryset(obj)
        serializer = InvestigationDetailsSerializer(
            obj,
            context={
                "request": request,
                "analyzer_reports_qs": analyzer_reports_qs,
            },
        )
        return Response(serializer.data, status=status.HTTP_200_OK)