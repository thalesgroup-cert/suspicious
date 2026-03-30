from __future__ import annotations

from django.db.models import Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from case_handler.models import Case
from cortex_job.models import AnalyzerReport
from api.utils.investigation_pagination import InvestigationPagination
from api.serializers.investigations import (
    API_RESULT_TO_INTERNAL,
    API_STATUS_TO_INTERNAL,
    InvestigationDetailsSerializer,
    InvestigationGlobalEditRequestSerializer,
    InvestigationListQuerySerializer,
    InvestigationRowSerializer,
)


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
        query = Q()

        file_or_mail = getattr(obj, "fileOrMail", None)
        non_file_iocs = getattr(obj, "nonFileIocs", None)

        if obj.fileOrMail_id and file_or_mail:
            if file_or_mail.file_id:
                query |= Q(file_id=file_or_mail.file_id)

            if file_or_mail.mail_id and getattr(file_or_mail, "mail", None):
                mail = file_or_mail.mail

                if mail.mail_body_id:
                    query |= Q(mail_body_id=mail.mail_body_id)

                if mail.mail_header_id:
                    query |= Q(mail_header_id=mail.mail_header_id)

                attachment_file_ids = list(
                    mail.mail_attachments.exclude(file_id__isnull=True)
                    .values_list("file_id", flat=True)
                )
                if attachment_file_ids:
                    query |= Q(file_id__in=attachment_file_ids)

                url_ids = []
                ip_ids = []
                hash_ids = []
                domain_ids = []
                mail_address_ids = []

                for artifact in mail.mail_artifacts.select_related(
                    "artifactIsUrl",
                    "artifactIsIp",
                    "artifactIsHash",
                    "artifactIsDomain",
                    "artifactIsMailAddress",
                ):
                    if artifact.artifactIsUrl_id and artifact.artifactIsUrl and artifact.artifactIsUrl.url_id:
                        url_ids.append(artifact.artifactIsUrl.url_id)

                    if artifact.artifactIsIp_id and artifact.artifactIsIp and artifact.artifactIsIp.ip_id:
                        ip_ids.append(artifact.artifactIsIp.ip_id)

                    if artifact.artifactIsHash_id and artifact.artifactIsHash and artifact.artifactIsHash.hash_id:
                        hash_ids.append(artifact.artifactIsHash.hash_id)

                    if artifact.artifactIsDomain_id and artifact.artifactIsDomain and artifact.artifactIsDomain.domain_id:
                        domain_ids.append(artifact.artifactIsDomain.domain_id)

                    if (
                        artifact.artifactIsMailAddress_id
                        and artifact.artifactIsMailAddress
                        and artifact.artifactIsMailAddress.mail_address_id
                    ):
                        mail_address_ids.append(artifact.artifactIsMailAddress.mail_address_id)

                if url_ids:
                    query |= Q(url_id__in=url_ids)
                if ip_ids:
                    query |= Q(ip_id__in=ip_ids)
                if hash_ids:
                    query |= Q(hash_id__in=hash_ids)
                if domain_ids:
                    query |= Q(domain_id__in=domain_ids)
                if mail_address_ids:
                    query |= Q(mail_id__in=mail_address_ids)

        if obj.nonFileIocs_id and non_file_iocs:
            if non_file_iocs.url_id:
                query |= Q(url_id=non_file_iocs.url_id)
            if non_file_iocs.ip_id:
                query |= Q(ip_id=non_file_iocs.ip_id)
            if non_file_iocs.hash_id:
                query |= Q(hash_id=non_file_iocs.hash_id)

        if not query.children:
            return AnalyzerReport.objects.none()

        qs = (
            AnalyzerReport.objects
            .filter(query)
            .select_related(*self.analyzer_report_select_related)
            .order_by("-creation_date", "-pk")
            .distinct()
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
            # pk is an integer field — icontains on an integer raises FieldError
            # on MySQL/MariaDB. Use exact match only when the search term is
            # purely numeric.
            id_q = Q(pk=int(search)) if search.strip().isdigit() else Q()

            # ── Text search across all meaningful string fields ───────────────
            #
            # Each nonFileIocs FK traversal goes one level deeper to the actual
            # string column on the related model:
            #   nonFileIocs__url__address     (not nonFileIocs__url)
            #   nonFileIocs__ip__address      (not nonFileIocs__ip)
            #   nonFileIocs__hash__value      (not nonFileIocs__hash)
            #
            # Doing icontains directly on a ForeignKey column (which is an
            # integer in the DB) raises:
            #   FieldError: Unsupported lookup 'icontains' for ForeignKey
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

        return queryset.distinct()


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
        obj.finalScore = validated["score"]
        obj.finalConfidence = validated["confidence"]
        obj.results = API_RESULT_TO_INTERNAL[validated["classification"]]
        obj.last_update_by = request.user
        obj.save(
            update_fields=[
                "finalScore",
                "finalConfidence",
                "results",
                "last_update_by",
                "last_update",
            ]
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