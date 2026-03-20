from django.db.models import Q
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
from api.serializers.submissions import (
    AdminSubmissionDetailsSerializer,
    SubmissionDetailsSerializer,
    SubmissionListSerializer,
)
from case_handler.models import Case
from cortex_job.models import AnalyzerReport


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
            OpenApiParameter(
                name="mine",
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    "When true, restricts results to the authenticated user's submissions. "
                    "For non-elevated users this is effectively always true."
                ),
            ),
            OpenApiParameter(
                name="ordering",
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                enum=[
                    "created_at",
                    "-created_at",
                    "id",
                    "-id",
                    "status",
                    "-status",
                    "result",
                    "-result",
                ],
                description="Ordering field.",
            ),
            OpenApiParameter(
                name="page",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
            ),
            OpenApiParameter(
                name="page_size",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description="Maximum 100.",
            ),
        ],
        examples=[
            OpenApiExample(
                "Only my submissions",
                value={"mine": True, "ordering": "-created_at"},
                request_only=True,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class SubmissionDetailsView(RetrieveAPIView):
    permission_classes = [IsAuthenticated, CanAccessSubmission]
    lookup_url_kwarg = "submission_id"

    def get_queryset(self):
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

    def get_serializer_class(self):
        if user_has_submission_elevated_access(self.request.user):
            return AdminSubmissionDetailsSerializer
        return SubmissionDetailsSerializer

    def get_object(self):
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs[self.lookup_url_kwarg])
        self.check_object_permissions(self.request, obj)
        return obj

    def _get_analyzer_reports_queryset(self, obj: Case):
        filters = Q()

        linked_file_or_mail = getattr(obj, "fileOrMail", None)
        linked_non_file_iocs = getattr(obj, "nonFileIocs", None)

        if obj.fileOrMail_id and linked_file_or_mail is not None:
            if linked_file_or_mail.file_id:
                filters |= Q(file_id=linked_file_or_mail.file_id)

            if linked_file_or_mail.mail_id and getattr(linked_file_or_mail, "mail", None):
                mail = linked_file_or_mail.mail

                # Direct analyzable mail components
                if mail.mail_body_id:
                    filters |= Q(mail_body_id=mail.mail_body_id)

                if mail.mail_header_id:
                    filters |= Q(mail_header_id=mail.mail_header_id)

                # Mail attachments -> AnalyzerReport.file
                attachment_file_ids = list(
                    mail.mail_attachments.exclude(file_id__isnull=True)
                    .values_list("file_id", flat=True)
                )
                if attachment_file_ids:
                    filters |= Q(file_id__in=attachment_file_ids)

                # Mail artifacts -> AnalyzerReport.url/ip/hash/domain/mail(MailAddress)
                artifact_url_ids = []
                artifact_ip_ids = []
                artifact_hash_ids = []
                artifact_domain_ids = []
                artifact_mail_address_ids = []

                for artifact in mail.mail_artifacts.select_related(
                    "artifactIsUrl",
                    "artifactIsIp",
                    "artifactIsHash",
                    "artifactIsDomain",
                    "artifactIsMailAddress",
                ):
                    if (
                        artifact.artifactIsUrl_id
                        and artifact.artifactIsUrl
                        and artifact.artifactIsUrl.url_id
                    ):
                        artifact_url_ids.append(artifact.artifactIsUrl.url_id)

                    if (
                        artifact.artifactIsIp_id
                        and artifact.artifactIsIp
                        and artifact.artifactIsIp.ip_id
                    ):
                        artifact_ip_ids.append(artifact.artifactIsIp.ip_id)

                    if (
                        artifact.artifactIsHash_id
                        and artifact.artifactIsHash
                        and artifact.artifactIsHash.hash_id
                    ):
                        artifact_hash_ids.append(artifact.artifactIsHash.hash_id)

                    if (
                        artifact.artifactIsDomain_id
                        and artifact.artifactIsDomain
                        and artifact.artifactIsDomain.domain_id
                    ):
                        artifact_domain_ids.append(artifact.artifactIsDomain.domain_id)

                    if (
                        artifact.artifactIsMailAddress_id
                        and artifact.artifactIsMailAddress
                        and artifact.artifactIsMailAddress.mail_address_id
                    ):
                        artifact_mail_address_ids.append(
                            artifact.artifactIsMailAddress.mail_address_id
                        )

                if artifact_url_ids:
                    filters |= Q(url_id__in=artifact_url_ids)
                if artifact_ip_ids:
                    filters |= Q(ip_id__in=artifact_ip_ids)
                if artifact_hash_ids:
                    filters |= Q(hash_id__in=artifact_hash_ids)
                if artifact_domain_ids:
                    filters |= Q(domain_id__in=artifact_domain_ids)
                if artifact_mail_address_ids:
                    filters |= Q(mail_id__in=artifact_mail_address_ids)

        if obj.nonFileIocs_id and linked_non_file_iocs is not None:
            if linked_non_file_iocs.url_id:
                filters |= Q(url_id=linked_non_file_iocs.url_id)
            if linked_non_file_iocs.ip_id:
                filters |= Q(ip_id=linked_non_file_iocs.ip_id)
            if linked_non_file_iocs.hash_id:
                filters |= Q(hash_id=linked_non_file_iocs.hash_id)

        if not filters.children:
            return AnalyzerReport.objects.none()

        return (
            AnalyzerReport.objects.filter(filters)
            .select_related(
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
            .order_by("-creation_date", "-id")
            .distinct()
        )

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
            Case.objects.only(
                "id",
                "reporter_id",
                "is_challenged",
                "is_challengeable",
                "status",
            ),
            pk=submission_id,
        )
        self.check_object_permissions(self.request, obj)
        return obj

    @extend_schema(summary="Challenge a submission")
    def post(self, request, submission_id: int):
        obj = self.get_object(submission_id)

        if obj.is_challenged:
            raise ValidationError({"detail": "Submission already challenged."})

        if not obj.is_challengeable:
            raise ValidationError({"detail": "Submission cannot be challenged."})

        obj.is_challenged = True
        obj.status = "Challenged"
        obj.save(update_fields=["is_challenged", "status", "last_update"])

        return Response({"detail": "Challenge submitted."}, status=status.HTTP_200_OK)