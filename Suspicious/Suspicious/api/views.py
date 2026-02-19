from django.db import IntegrityError, transaction
from django.db.models import Sum
from django.http import HttpResponseRedirect, StreamingHttpResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound, APIException
from rest_framework.response import Response
from rest_framework import generics
from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.utils import extend_schema, OpenApiParameter

from case_handler.models import Case, CaseChallengeToken
from mail_feeder.models import MailArchive
from dashboard.models import (
    MonthlyCasesSummary,
    UserCasesMonthlyStats,
    MonthlyReporterStats,
    TotalCasesStats,
)
from knox.models import AuthToken
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
from django.utils import timezone
from tasp.services.challenge import get_submissions_url, run_case_challenge
import json
import io
import zipfile
import os
import logging
from minio.error import S3Error
# ---------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------

ALLOWED_DOWNLOAD_GROUPS = {"Admin", "CERT"}
CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
logger = logging.getLogger(__name__)


class StorageUnavailable(APIException):
    status_code = 503
    default_detail = "Storage backend unavailable"
    default_code = "storage_unavailable"


def load_minio_config(path: str):
    try:
        with open(path) as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        logger.warning("Settings file not found: %s", path)
        return None
    except json.JSONDecodeError:
        logger.warning("Settings file contains invalid JSON: %s", path)
        return None

    return config.get("minio")


minio_config = load_minio_config(CONFIG_PATH)
# Generate API Key
def generate_api_key(user, expiration):
    expiry = timezone.timedelta(days=expiration)
    token_instance, raw_key = AuthToken.objects.create(user=user, expiry=expiry)
    return raw_key, token_instance

def user_can_download(user) -> bool:
    return user.groups.filter(name__in=ALLOWED_DOWNLOAD_GROUPS).exists()


# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------
class DownloadCaseArchiveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, case_id: int):
        if not user_can_download(request.user):
            raise PermissionDenied("Not authorized")

        if not minio_config:
            raise StorageUnavailable("Storage backend not configured")

        case = self._get_case(case_id)
        archive = self._get_archive(case)

        storage = StorageClient(minio_config)
        if not storage.client:
            raise StorageUnavailable("Storage backend unavailable")

        try:
            objects = storage.client.list_objects(archive.bucket_name, recursive=True)
        except S3Error:
            raise NotFound("Bucket not found")

        def zip_stream():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for obj in objects:
                    try:
                        data = storage.client.get_object(archive.bucket_name, obj.object_name)
                        zip_file.writestr(obj.object_name, data.read())
                        data.close()
                    except S3Error:
                        continue
            buf.seek(0)
            yield from buf

        response = StreamingHttpResponse(
            zip_stream(),
            content_type="application/zip"
        )
        response['Content-Disposition'] = f'attachment; filename="case_{case.pk}.zip"'

        log_cert_download(
            user=request.user,
            case_id=case.pk,
            object_name=f"case_{case.pk}.zip",
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


class CaseChallengeTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, case_id: int):
        token = request.query_params.get("token")
        if not token:
            return Response({"detail": "Token is required."}, status=400)

        token_hash = CaseChallengeToken.hash_token(token)
        now = timezone.now()
        try:
            with transaction.atomic():
                token_record = (
                    CaseChallengeToken.objects.select_for_update()
                    .select_related("case", "case__reporter")
                    .filter(
                        token_hash=token_hash,
                        case_id=case_id,
                        used_at__isnull=True,
                        expires_at__gt=now,
                    )
                    .first()
                )
                if not token_record:
                    return Response({"detail": "Invalid or expired token."}, status=400)

                run_case_challenge(token_record.case, logger)
                token_record.mark_used()
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=409)
        except IntegrityError:
            logger.exception("Database integrity error challenging case %s", case_id)
            return Response({"detail": "Database error processing challenge."}, status=500)
        except Exception:
            logger.exception("Unexpected error challenging case %s", case_id)
            return Response({"detail": "Unexpected error processing challenge."}, status=500)

        return HttpResponseRedirect(get_submissions_url())


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
        responses=MonthlyCasesSummarySerializer(many=True),
        description="Aggregate case stats for a given month/year",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).values("user__username", "creation_date__month", "creation_date__year").aggregate(
            suspicious_cases=Sum("suspicious_cases"),
            inconclusive_cases=Sum("inconclusive_cases"),
            failure_cases=Sum("failure_cases"),
            dangerous_cases=Sum("dangerous_cases"),
            safe_cases=Sum("safe_cases"),
            challenged_cases=Sum("challenged_cases"),
            allow_listed_cases=Sum("allow_listed_cases"),
            uncategorized_cases=Sum("uncategorized_cases"),
            spam_cases=Sum("spam_cases"),
            newsletter_cases=Sum("newsletter_cases"),
            classic_phishing_cases=Sum("classic_phishing_cases"),
            clone_cases=Sum("clone_cases"),
            blackmail_cases=Sum("blackmail_cases"),
            whaling_cases=Sum("whaling_cases"),
            internal_cases=Sum("internal_cases"),
            external_cases=Sum("external_cases"),
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
        responses=UserCasesMonthlyStatsSerializer(many=True),
        description="Aggregate user case statistics",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = (
            UserCasesMonthlyStats.objects
            .filter(month=month, year=year)
            .values("user__username", "creation_date__month", "creation_date__year")
            .annotate(
                total_cases=Sum("total_cases"),
                total_safe=Sum("safe_cases"),
                total_dangerous=Sum("dangerous_cases"),
                total_suspicious=Sum("suspicious_cases"),
                total_inconclusive=Sum("inconclusive_cases"),
                total_failure=Sum("failure_cases"),
                total_uncategorized=Sum("uncategorized_cases"),
                total_spam=Sum("spam_cases"),
                total_newsletter=Sum("newsletter_cases"),
                total_classic_phishing=Sum("classic_phishing_cases"),
                total_clone=Sum("clone_cases"),
                total_blackmail=Sum("blackmail_cases"),
                total_whaling=Sum("whaling_cases"),
                total_internal=Sum("internal_cases"),
                total_external=Sum("external_cases"),
                total_challenged=Sum("challenged_cases"),
                total_allow_listed=Sum("allow_listed_cases"),
            )
        )

        return Response(list(data))
