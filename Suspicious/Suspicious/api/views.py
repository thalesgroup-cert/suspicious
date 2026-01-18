from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.response import Response
from rest_framework import generics
from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.utils import extend_schema, OpenApiParameter

from case_handler.models import Case
from mail_feeder.models import MailArchive
from dashboard.models import (
    MonthlyCasesSummary,
    UserCasesMonthlyStats,
    MonthlyReporterStats,
    TotalCasesStats,
)

from .serializers import (
    MonthlyCasesSummarySerializer,
    UserCasesMonthlyStatsSerializer,
    MonthlyReporterStatsSerializer,
    TotalCasesStatsSerializer,
)
from .filters import MonthlyCasesSummaryFilter, MonthlyReporterStatsFilter, TotalCasesStatsFilter
from .storage import StorageClient
from .mixins import MonthYearQueryMixin
from .audit import log_cert_download

# ---------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------

ALLOWED_DOWNLOAD_GROUPS = {"Admin", "CERT"}


def user_can_download(user) -> bool:
    return user.groups.filter(name__in=ALLOWED_DOWNLOAD_GROUPS).exists()


# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------

class DownloadCaseArchiveView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("case_id", int, OpenApiParameter.PATH),
        ],
        responses={200: None},
        description="Download case archive (CERT/Admin only)",
    )
    def get(self, request, case_id: int):
        if not user_can_download(request.user):
            raise PermissionDenied("Not authorized")

        case = self._get_case(case_id)
        archive = self._get_archive(case)

        object_name = f"case_{case.reporter}_{case.pk}.zip"

        storage = StorageClient(request.app_settings["minio"])
        response = storage.stream_object(
            archive.bucket_name,
            object_name,
        )

        log_cert_download(
            user=request.user,
            case_id=case.pk,
            object_name=object_name,
            ip=request.META.get("REMOTE_ADDR"),
        )

        return response

    @staticmethod
    def _get_case(case_id: int) -> Case:
        try:
            return Case.objects.select_related(
                "fileOrMail__mail"
            ).get(pk=case_id)
        except Case.DoesNotExist:
            raise NotFound("Case not found")

    @staticmethod
    def _get_archive(case: Case) -> MailArchive:
        if not case.fileOrMail or not case.fileOrMail.mail:
            raise NotFound("No mail linked to case")

        archive = MailArchive.objects.filter(
            mail=case.fileOrMail.mail
        ).first()

        if not archive or not archive.bucket_name:
            raise NotFound("Archive not found")

        return archive

class MonthlyCasesSummaryListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyCasesSummary.objects.all()
    serializer_class = MonthlyCasesSummarySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyCasesSummaryFilter


class MonthlyReporterStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyReporterStats.objects.all()
    serializer_class = MonthlyReporterStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyReporterStatsFilter


class TotalCasesStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = TotalCasesStats.objects.all()
    serializer_class = TotalCasesStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = TotalCasesStatsFilter


class UserCasesMonthlyStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = UserCasesMonthlyStats.objects.all()
    serializer_class = UserCasesMonthlyStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["user", "month", "year"]


class UserCasesMonthlyStatsDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    queryset = UserCasesMonthlyStats.objects.all()
    serializer_class = UserCasesMonthlyStatsSerializer

# ---------------------------------------------------------------------
# Monthly aggregation (with mixin + OpenAPI)
# ---------------------------------------------------------------------

class MonthlyCasesSummaryAggregateView(
    MonthYearQueryMixin,
    APIView,
):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY),
            OpenApiParameter("year", int, OpenApiParameter.QUERY),
        ],
        responses=dict,
        description="Aggregate case stats for a given month/year",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            suspicious_cases=Sum("suspicious_cases"),
            dangerous_cases=Sum("dangerous_cases"),
            safe_cases=Sum("safe_cases"),
            total_cases=Sum("total_cases"),
        )
        return Response(data)


class UserCasesMonthlyStatsAggregateView(
    MonthYearQueryMixin,
    APIView,
):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY),
            OpenApiParameter("year", int, OpenApiParameter.QUERY),
        ],
        responses=dict,
        description="Aggregate user case statistics",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = UserCasesMonthlyStats.objects.filter(
            month=month,
            year=year,
        ).values("user__username").annotate(
            total_cases=Sum("total_cases"),
            total_dangerous=Sum("dangerous_cases"),
            total_safe=Sum("safe_cases"),
        )
        return Response(data)
