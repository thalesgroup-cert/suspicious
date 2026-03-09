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
    GroupMonthlyStats,
    MonthlyReporterStats,
    TotalCasesStats,
)
from profiles.models import UserProfile, CISOProfile
from knox.models import AuthToken
from .serializers import (
    MonthlyCasesSummarySerializer,
    UserCasesMonthlyStatsSerializer,
    MonthlyReporterStatsSerializer,
    TotalCasesStatsSerializer,
    DashboardSummaryResponseSerializer,
    CampaignClassificationCountsSerializer,
    CampaignPcaResponseSerializer,
    CampaignMailVolumeResponseSerializer,
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

from django.conf import settings
from django.db.models import Sum, Value, IntegerField
from django.db.models.functions import Coalesce
from rest_framework.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework import status

import ast
import re
import numpy as np

from datetime import datetime, timedelta, timezone as dt_timezone
from email.utils import parsedate_to_datetime
from django.http import JsonResponse
from score_process.score_utils.thehive.utils import parse_and_decode_defaultdict, parse_headers


# ---------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------

ALLOWED_DOWNLOAD_GROUPS = {"Admin", "CERT"}
CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
logger = logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"detail": "username and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        token_instance, token = AuthToken.objects.create(user=user)

        return Response({
            "token": token,
            "expiry": token_instance.expiry,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": getattr(user, "email", ""),
                "groups": list(user.groups.values_list("name", flat=True)),
            },
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Deletes the current token used for this request
        request._auth.delete()
        return Response({"detail": "Logged out."})

class HomeSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        month = self._parse_int_query_param(
            request, "month", min_value=1, max_value=12, required=False
        )
        year = self._parse_int_query_param(
            request, "year", min_value=1, required=False
        )

        now = timezone.now()
        if month is None:
            month = now.month
        if year is None:
            year = now.year

        month_str = f"{month:02d}"
        year_str = str(year)

        groups = set(request.user.groups.values_list("name", flat=True))
        is_ciso = "CISO" in groups
        is_cert = "CERT" in groups

        user_profile = UserProfile.objects.filter(user=request.user).first()
        ciso_profile = CISOProfile.objects.filter(user=request.user).first()
        profile = ciso_profile if is_ciso and ciso_profile else user_profile

        user_stats = (
            UserCasesMonthlyStats.objects
            .filter(user=request.user, month=month_str, year=year_str)
            .aggregate(
                total_cases=Sum("total_cases"),
                safe=Sum("safe_cases"),
                inconclusive=Sum("inconclusive_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
            )
        )

        total_cases = int(user_stats["total_cases"] or 0)
        safe = int(user_stats["safe"] or 0)
        inconclusive = int(user_stats["inconclusive"] or 0)
        suspicious = int(user_stats["suspicious"] or 0)
        dangerous = int(user_stats["dangerous"] or 0)

        challenge_cases = Case.objects.filter(
            is_challenged=True,
        ).count()
        
        region = self._clean_profile_value(getattr(profile, "region", None))
        country = self._clean_profile_value(getattr(profile, "country", None))
        gbu = self._clean_profile_value(getattr(profile, "gbu", None))

        ciso_scope = None
        if ciso_profile:
            ciso_scope = self._clean_scope(ciso_profile.scope)

        show_scope_modal = bool(is_ciso and not ciso_scope)

        scope_total_cases = 0
        scope_danger_counts = {
            "safe": 0,
            "inconclusive": 0,
            "suspicious": 0,
            "dangerous": 0,
        }

        if is_ciso and ciso_scope:
            group_stats_qs = GroupMonthlyStats.objects.filter(
                month=month_str,
                year=year_str,
            )

            scope_groups = self._parse_scope_groups(ciso_scope)

            if scope_groups is not None:
                group_stats_qs = group_stats_qs.filter(group_name__in=scope_groups)

            scope_stats = group_stats_qs.aggregate(
                total_cases=Sum("total_cases"),
                safe=Sum("safe_cases"),
                inconclusive=Sum("inconclusive_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
            )

            scope_total_cases = int(scope_stats["total_cases"] or 0)
            scope_danger_counts = {
                "safe": int(scope_stats["safe"] or 0),
                "inconclusive": int(scope_stats["inconclusive"] or 0),
                "suspicious": int(scope_stats["suspicious"] or 0),
                "dangerous": int(scope_stats["dangerous"] or 0),
            }

        spotlight = self._build_spotlight(
            is_ciso=is_ciso,
            is_cert=is_cert,
            total_cases=scope_total_cases if is_ciso else total_cases,
            challenge_cases=challenge_cases,
        )

        payload = {
            "show_scope_modal": show_scope_modal,
            "monthly": {
                "everyone_items": total_cases,
                "scope_items": scope_total_cases if is_ciso else 0,
                "scope_name": ciso_scope,
            },
            "danger_counts": {
                "safe": safe,
                "inconclusive": inconclusive,
                "suspicious": suspicious,
                "dangerous": dangerous,
            },
            "scope_danger_counts": scope_danger_counts if is_ciso else None,
            "suggested_scopes": {
                "region": region,
                "country": country,
                "gbu": gbu,
            },
            "spotlight": spotlight,
        }

        return Response(payload)

    @staticmethod
    def _clean_profile_value(value):
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    @staticmethod
    def _clean_scope(value):
        if value is None:
            return None
        value = str(value).strip()
        if not value or value.lower() == "not defined":
            return None
        return value

    @staticmethod
    def _parse_scope_groups(scope: str):
        """
        Convert a scope string into a list of group names.
        """
        if not scope:
            return []

        normalized = scope.strip()
        if normalized.upper() == "ALL":
            return None

        parts = [part.strip() for part in normalized.split("|")]
        return [part for part in parts if part]

    @staticmethod
    def _build_spotlight(is_ciso: bool, is_cert: bool, total_cases: int, challenge_cases: int):
        if is_ciso:
            return {
                "title": "CISO overview",
                "description": (
                    f"There are {total_cases} items in your current scope this month. "
                    "Use the dashboard to review broader activity and trends."
                ),
                "cta_label": "Open dashboard",
                "cta_path": "/dashboard",
            }

        if is_cert:
            return {
                "title": "Investigation workspace",
                "description": (
                    f"Everyone has submitted {total_cases} cases this month. "
                    f"    - Number of ongoing challenges : {challenge_cases} "
                    "Open Investigation to review and triage cases."
                ),
                "cta_label": "Open investigation",
                "cta_path": "/investigation",
            }

        return {
            "title": "Your monthly activity",
            "description": (
                f"You have submitted {total_cases} item"
                f"{'' if total_cases == 1 else 's'} this month."
            ),
            "cta_label": "Submit an item",
            "cta_path": "/submit",
        }

    @staticmethod
    def _parse_int_query_param(
        request,
        name: str,
        min_value: int = None,
        max_value: int = None,
        required: bool = True,
    ):
        raw_value = request.query_params.get(name)

        if raw_value in (None, ""):
            if required:
                raise ValidationError({name: "This query parameter is required."})
            return None

        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            raise ValidationError({name: "Must be an integer."})

        if min_value is not None and value < min_value:
            raise ValidationError({name: f"Must be >= {min_value}."})
        if max_value is not None and value > max_value:
            raise ValidationError({name: f"Must be <= {max_value}."})

        return value

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


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    DEFAULT_TOP_PREFIXES_LIMIT = 10

    def get(self, request):
        month = self._parse_int_query_param(request, "month", min_value=1, max_value=12)
        year = self._parse_int_query_param(request, "year", min_value=1)
        scope = request.query_params.get("scope", "ALL")

        # At the moment your models do not contain a scope field, so scope can only
        # be echoed back for UI compatibility. Do not use it for filtering until you
        # actually add a scope dimension in the database.
        #
        # If you later add scope-based fields, apply filtering here.
        if not request.user.groups.filter(name="CISO").exists():
            scope = "ALL"

        month_str = str(month)
        year_str = str(year)

        # These tables do not have explicit month/year fields, so we filter by creation_date.
        cases_agg = MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            failure=Coalesce(Sum("failure_cases"), 0),
            safe=Coalesce(Sum("safe_cases"), 0),
            inconclusive=Coalesce(Sum("inconclusive_cases"), 0),
            suspicious=Coalesce(Sum("suspicious_cases"), 0),
            dangerous=Coalesce(Sum("dangerous_cases"), 0),
            classic_phishing=Coalesce(Sum("classic_phishing_cases"), 0),
            clone=Coalesce(Sum("clone_cases"), 0),
            blackmail=Coalesce(Sum("blackmail_cases"), 0),
            whaling=Coalesce(Sum("whaling_cases"), 0),
        )

        reporters_agg = MonthlyReporterStats.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            new_users=Coalesce(Sum("new_reporters"), 0),
            total_reporters=Coalesce(Sum("total_reporters"), 0),
        )

        total_cases_agg = TotalCasesStats.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            total_cases=Coalesce(Sum("total_cases"), 0),
        )

        top_prefixes = self._get_top_prefixes(month_str, year_str, self.DEFAULT_TOP_PREFIXES_LIMIT)

        malicious_total = (
            int(cases_agg["classic_phishing"] or 0)
            + int(cases_agg["clone"] or 0)
            + int(cases_agg["blackmail"] or 0)
            + int(cases_agg["whaling"] or 0)
        )

        payload = {
            "month": month,
            "year": year,
            "scope": scope,
            "kpis": {
                "new_users": int(reporters_agg["new_users"] or 0),
                "total_reporters": int(reporters_agg["total_reporters"] or 0),
                "total_cases": int(total_cases_agg["total_cases"] or 0),
            },
            "danger_counts": {
                "failure": int(cases_agg["failure"] or 0),
                "safe": int(cases_agg["safe"] or 0),
                "inconclusive": int(cases_agg["inconclusive"] or 0),
                "suspicious": int(cases_agg["suspicious"] or 0),
                "dangerous": int(cases_agg["dangerous"] or 0),
                "malicious": malicious_total,
            },
            "top_prefixes": top_prefixes,
        }

        serializer = DashboardSummaryResponseSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    def _get_top_prefixes(self, month: str, year: str, limit: int):
        suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", None)

        qs = UserCasesMonthlyStats.objects.filter(
            month=month,
            year=year,
        )

        if suspicious_email:
            qs = qs.exclude(user__username=suspicious_email)

        rows = (
            qs.select_related("user")
            .order_by("-total_cases", "user__username")
            .values_list("user__username", "total_cases")[:limit]
        )

        result = []
        for username, total_cases in rows:
            label = self._extract_email_prefix(username)
            if not label:
                continue
            result.append({
                "label": label,
                "value": int(total_cases or 0),
            })
        return result

    @staticmethod
    def _extract_email_prefix(value: str) -> str:
        if not value:
            return ""
        local_part, sep, _domain = value.strip().partition("@")
        if sep == "@":
            return local_part
        return value.strip()

    @staticmethod
    def _parse_int_query_param(request, name: str, min_value: int = None, max_value: int = None) -> int:
        raw_value = request.query_params.get(name)
        if raw_value is None:
            raise ValidationError({name: "This query parameter is required."})

        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            raise ValidationError({name: "Must be an integer."})

        if min_value is not None and value < min_value:
            raise ValidationError({name: f"Must be >= {min_value}."})
        if max_value is not None and value > max_value:
            raise ValidationError({name: f"Must be <= {max_value}."})

        return value

class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        groups = list(user.groups.values_list("name", flat=True))

        return Response({
            "id": user.id,
            "username": user.username,
            "email": getattr(user, "email", ""),
            "first_name": getattr(user, "first_name", ""),
            "last_name": getattr(user, "last_name", ""),
            "groups": groups,
            "ciso_scope": "",
        })

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


def _disable_chromadb_telemetry():
    try:
        os.environ.setdefault("CHROMADB_TELEMETRY_ENABLED", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
        os.environ.setdefault("CHROMADB_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CHROMADB_TELEMETRY", "false")
    except Exception:
        pass

    try:
        from chromadb.telemetry import telemetry as _telemetry  # type: ignore

        if hasattr(_telemetry, "TELEMETRY_ENABLED"):
            try:
                _telemetry.TELEMETRY_ENABLED = False  # type: ignore[attr-defined]
            except Exception:
                pass

        inst = getattr(_telemetry, "telemetry_instance", None)
        if inst is not None:
            for attr in ("capture", "capture_event", "capture_span", "flush"):
                if hasattr(inst, attr):
                    setattr(inst, attr, lambda *a, **k: None)
    except Exception:
        pass

    try:
        from chromadb.telemetry import product as _product  # type: ignore

        posthog_mod = getattr(_product, "posthog", None)
        if posthog_mod is not None:
            def _noop_capture(*args, **kwargs):
                return None

            if hasattr(posthog_mod, "capture"):
                posthog_mod.capture = _noop_capture  # type: ignore[assignment]
            client_cls = getattr(posthog_mod, "Posthog", None)
            if client_cls is not None and hasattr(client_cls, "capture"):
                client_cls.capture = _noop_capture  # type: ignore[assignment]
    except Exception:
        pass


def _get_chroma_collection(collection_name: str = "suspicious_mails"):
    try:
        import chromadb  # type: ignore
        from chromadb.config import Settings  # type: ignore
    except Exception as e:
        logger.warning("ChromaDB not available in environment: %s", e)
        return None

    _disable_chromadb_telemetry()

    persist_path = "/app/Suspicious/chromadb"
    errors = []

    attempts = []
    try:
        attempts.append(
            lambda: chromadb.PersistentClient(
                path=persist_path,
                tenant="default_tenant",
                database="default_database",
                settings=Settings(anonymized_telemetry=False),
            )
        )
    except Exception:
        attempts.append(
            lambda: chromadb.PersistentClient(
                path=persist_path,
                settings=Settings(anonymized_telemetry=False),
            )
        )

    def _legacy_client():
        s = Settings(
            is_persistent=True,
            persist_directory=persist_path,
            anonymized_telemetry=False,
        )  # type: ignore[arg-type]
        return chromadb.Client(s)

    attempts.append(_legacy_client)

    client = None
    for factory in attempts:
        try:
            client = factory()
            break
        except Exception as e:
            errors.append(str(e))
            client = None

    if client is None:
        logger.error("Failed to init ChromaDB client: %s", " | ".join(errors))
        return None

    try:
        return client.get_collection(name=collection_name)
    except Exception as e:
        logger.warning("ChromaDB collection '%s' not accessible: %s", collection_name, e)
        return None


def _parse_source_refs(raw):
    if raw is None:
        return ()
    iterable = None
    if isinstance(raw, (list, tuple, set)):
        iterable = list(raw)
    else:
        text = str(raw).strip()
        if not text:
            return ()
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, (list, tuple, set)):
                iterable = list(parsed)
                break
            if isinstance(parsed, str):
                iterable = [parsed]
                break
        if iterable is None:
            stripped = text.strip("[](){}")
            if not stripped:
                return ()
            parts = [segment for segment in re.split(r"[;,]", stripped) if segment]
            iterable = [seg.strip().strip("'\"") for seg in parts]
    if iterable is None:
        return ()
    cleaned = []
    for item in iterable:
        sval = str(item).strip().strip("'\"")
        if sval:
            cleaned.append(sval)
    if not cleaned:
        return ()
    seen = {}
    for val in cleaned:
        if val not in seen:
            seen[val] = None
    return tuple(sorted(seen.keys()))


def _extract_headers_dict(raw):
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    text = str(raw)
    if not text:
        return None
    if "defaultdict" in text:
        try:
            parsed = parse_and_decode_defaultdict(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    try:
        parsed = parse_headers(text)
        if isinstance(parsed, dict):
            return dict(parsed)
    except Exception:
        pass
    return None


def _parse_to_utc_date(val):
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            ts = float(val)
            if ts > 1e12:
                ts = ts / 1000.0
            dt = datetime.fromtimestamp(ts, tz=dt_timezone.utc)
            return dt.date()

        s = str(val).strip()
        if not s:
            return None

        s = s.replace("Z", "+00:00")
        dt = None
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            s2 = s.replace("GMT", "+00:00").replace(",", "")
            try:
                dt = datetime.fromisoformat(s2)
            except Exception:
                core = s
                if "T" in s:
                    core = s.split("T", 1)[0] + "T" + s.split("T", 1)[1][:8]
                core = core[:19]
                try:
                    dt = datetime.fromisoformat(core)
                except Exception:
                    m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
                    if m:
                        return datetime.fromisoformat(m.group(1)).date()
                    return None

        if dt.tzinfo is None:
            return dt.date()
        return dt.astimezone(dt_timezone.utc).date()
    except Exception:
        return None


def _parse_header_datetime(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(str(value))
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=dt_timezone.utc)
        return dt.astimezone(dt_timezone.utc)
    except Exception:
        pass
    fallback_day = _parse_to_utc_date(value)
    if fallback_day is None:
        return None
    return datetime(
        fallback_day.year,
        fallback_day.month,
        fallback_day.day,
        tzinfo=dt_timezone.utc,
    )


def _extract_sent_datetime(meta):
    headers_dict = _extract_headers_dict(meta.get("headers"))
    if not isinstance(headers_dict, dict):
        return None

    candidates = []
    for key in ("Date", "date", "Sent", "Sent-Date", "Sent-date", "sent_date"):
        val = headers_dict.get(key)
        if not val:
            continue
        if isinstance(val, (list, tuple)):
            candidates.extend(val)
        else:
            candidates.append(val)

    for candidate in candidates:
        dt = _parse_header_datetime(candidate)
        if dt is not None:
            return dt
    return None


def _extract_case_id(meta_obj):
    if not isinstance(meta_obj, dict):
        return None
    raw = meta_obj.get("suspicious_case_id")
    if raw is None:
        raw = meta_obj.get("case_id")
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None

class CampaignClassificationCountsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        counts = {"SAFE": 0, "UNWANTED": 0, "DANGEROUS": 0}

        collection = _get_chroma_collection()
        if collection is None:
            serializer = CampaignClassificationCountsSerializer(data=counts)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        def count_for(value: str) -> int:
            try:
                res = collection.get(where={"classification": value})
                ids = res.get("ids", []) if isinstance(res, dict) else []
                return len(ids)
            except Exception as e:
                logger.error("Error counting classification %s: %s", value, e, exc_info=True)
                return 0

        counts["SAFE"] = count_for("SAFE")
        counts["UNWANTED"] = count_for("UNWANTED")
        counts["DANGEROUS"] = count_for("DANGEROUS")

        if counts["UNWANTED"] == 0:
            suspicious = count_for("SUSPICIOUS")
            if suspicious:
                counts["UNWANTED"] = suspicious

        serializer = CampaignClassificationCountsSerializer(data=counts)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
    
class CampaignPcaView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            limit = int(request.query_params.get("limit", "1500"))
        except Exception:
            limit = 1500

        collection = _get_chroma_collection()
        if collection is None:
            payload = {"points": [], "explained_variance": [0.0, 0.0]}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        try:
            try:
                res = collection.get(include=["embeddings", "metadatas"])  # type: ignore[arg-type]
            except Exception:
                res = collection.get()

            if not isinstance(res, dict):
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            ids = res.get("ids") or []

            def _ensure_list(obj):
                if obj is None:
                    return []
                if isinstance(obj, list):
                    return obj
                try:
                    return list(obj)
                except TypeError:
                    return [obj]

            embeddings = _ensure_list(res.get("embeddings"))
            metadatas = _ensure_list(res.get("metadatas"))

            if ids and not embeddings:
                chunk_size = 200

                def _fetch_chunk(id_slice, depth=0):
                    if not id_slice:
                        return [], []
                    try:
                        chunk_res = collection.get(ids=id_slice, include=["embeddings", "metadatas"])  # type: ignore[arg-type]
                    except Exception as chunk_err:
                        if len(id_slice) == 1:
                            logger.error("PCA: failed to fetch embedding for id %s: %s", id_slice[0], chunk_err)
                            return [], []
                        if depth > 10:
                            logger.error("PCA: giving up fetching %d ids after deep recursion: %s", len(id_slice), chunk_err)
                            return [], []
                        mid = len(id_slice) // 2 or 1
                        left_emb, left_meta = _fetch_chunk(id_slice[:mid], depth + 1)
                        right_emb, right_meta = _fetch_chunk(id_slice[mid:], depth + 1)
                        return left_emb + right_emb, left_meta + right_meta

                    chunk_embeddings = _ensure_list(chunk_res.get("embeddings"))
                    chunk_metadatas = _ensure_list(chunk_res.get("metadatas"))
                    return chunk_embeddings, chunk_metadatas

                embeddings_chunks = []
                metadatas_chunks = []
                for start in range(0, len(ids), chunk_size):
                    chunk_ids = ids[start:start + chunk_size]
                    chunk_embeddings, chunk_metadatas = _fetch_chunk(chunk_ids)
                    if chunk_embeddings:
                        embeddings_chunks.extend(chunk_embeddings)
                        metadatas_chunks.extend(chunk_metadatas)

                if embeddings_chunks:
                    embeddings = embeddings_chunks
                    metadatas = metadatas_chunks

            if len(metadatas) < len(embeddings):
                metadatas = metadatas + [None] * (len(embeddings) - len(metadatas))

            dim_buckets = {}
            emb_iter = list(embeddings) if embeddings is not None else []

            for i, emb in enumerate(emb_iter):
                try:
                    vec = np.asarray(emb, dtype=np.float32).reshape(-1)
                    if vec.size == 0:
                        continue
                    if not np.all(np.isfinite(vec)):
                        continue

                    meta = {}
                    if i < len(metadatas):
                        meta = metadatas[i] or {}

                    label = str((meta or {}).get("classification", "UNKNOWN"))
                    dim = int(vec.size)
                    bucket = dim_buckets.setdefault(dim, [])
                    bucket.append((vec, label, meta))
                except Exception:
                    continue

            if not dim_buckets:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            chosen_dim = max(dim_buckets.keys(), key=lambda d: (len(dim_buckets[d]), d))
            selected = dim_buckets[chosen_dim]

            X = [entry[0] for entry in selected]
            labels = [entry[1] for entry in selected]
            metas = [entry[2] for entry in selected]

            n = len(X)
            if n == 0:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            if n == 1:
                single_meta = metas[0] if metas else {}
                single_label = labels[0] if labels else "UNKNOWN"
                payload = {
                    "points": [{
                        "x": 0.0,
                        "y": 0.0,
                        "label": str(single_label or "UNKNOWN"),
                        "suspicious_case_id": _extract_case_id(single_meta),
                        "sourceRefs": list(_parse_source_refs((single_meta or {}).get("sourceRefs"))) if single_meta else [],
                    }],
                    "explained_variance": [0.0, 0.0],
                }
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            X = np.stack(X, axis=0)

            if n > limit > 0:
                idx = np.random.default_rng(seed=42).choice(n, size=limit, replace=False)
                X = X[idx]
                labels = [labels[int(i)] for i in idx]
                metas = [metas[int(i)] for i in idx]
                n = X.shape[0]

            Xc = X - X.mean(axis=0, keepdims=True)

            try:
                U, S, Vt = np.linalg.svd(Xc, full_matrices=False)
            except Exception:
                payload = {"points": [], "explained_variance": [0.0, 0.0]}
                serializer = CampaignPcaResponseSerializer(data=payload)
                serializer.is_valid(raise_exception=True)
                return Response(serializer.data)

            comps = Vt[:2]
            scores = Xc @ comps.T

            ev = S ** 2
            denom = float(ev.sum()) if ev.size else 0.0
            if denom <= 0.0:
                ratios = [0.0, 0.0]
            else:
                ratios = [
                    float(ev[0] / denom),
                    float(ev[1] / denom) if ev.size > 1 else 0.0,
                ]

            points = [
                {
                    "x": float(scores[i, 0]),
                    "y": float(scores[i, 1]),
                    "label": str(labels[i] or "UNKNOWN"),
                    "suspicious_case_id": _extract_case_id(metas[i] if i < len(metas) else None),
                    "sourceRefs": list(_parse_source_refs((metas[i] or {}).get("sourceRefs"))) if i < len(metas) else [],
                }
                for i in range(n)
            ]

            payload = {"points": points, "explained_variance": ratios}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        except Exception as e:
            logger.error("Error computing PCA points: %s", e, exc_info=True)
            payload = {"points": [], "explained_variance": [0.0, 0.0]}
            serializer = CampaignPcaResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

class CampaignMailVolumeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        today_utc = datetime.now(dt_timezone.utc).date()
        start_utc = today_utc - timedelta(days=14)

        all_days = [start_utc + timedelta(days=i) for i in range(15)]
        idx = {d: i for i, d in enumerate(all_days)}
        non_danger = [0] * len(all_days)
        dangerous = [0] * len(all_days)

        collection = _get_chroma_collection()
        if collection is None:
            payload = {
                "dates": [d.isoformat() for d in all_days],
                "non_danger": non_danger,
                "dangerous": dangerous,
                "campaigns": [],
            }
            serializer = CampaignMailVolumeResponseSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data)

        def _ensure_utc(dt):
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=dt_timezone.utc)
            return dt.astimezone(dt_timezone.utc)

        def _format_campaign_name(refs_key, fallback_index):
            if not refs_key:
                return f"Campaign {fallback_index}"
            parts = [ref for ref in refs_key if ref]
            if not parts:
                return f"Campaign {fallback_index}"
            if len(parts) <= 3:
                return ", ".join(parts)
            return ", ".join(parts[:3]) + "…"

        campaign_windows = {}

        try:
            try:
                res = collection.get(include=["metadatas"], limit=100000)  # type: ignore[arg-type]
            except Exception:
                try:
                    res = collection.get(include=["metadatas"])  # type: ignore[arg-type]
                except Exception:
                    res = collection.get()

            if not isinstance(res, dict):
                raise ValueError("Unexpected ChromaDB get() result type")

            metadatas = res.get("metadatas", []) or []
            date_keys = (
                "sent_date", "date", "received_at", "created_at",
                "created", "timestamp", "date_received", "mail_date",
                "headers_date", "date_header", "ingested_at", "submitted_at",
                "time", "ts"
            )
            class_key = "classification"

            for meta in metadatas:
                try:
                    meta = meta or {}
                    refs_key = _parse_source_refs(meta.get("sourceRefs"))
                    sent_dt = _extract_sent_datetime(meta)
                    day = sent_dt.date() if sent_dt else None

                    dval = None
                    if day is None:
                        for k in date_keys:
                            if k in meta and meta[k]:
                                dval = meta[k]
                                break
                        if dval is None:
                            for v in meta.values():
                                potential_day = _parse_to_utc_date(v)
                                if potential_day is not None:
                                    dval = v
                                    break
                        if dval is not None:
                            day = _parse_to_utc_date(dval)

                    if refs_key:
                        if sent_dt is None and day is not None:
                            sent_dt = datetime(day.year, day.month, day.day, tzinfo=dt_timezone.utc)
                        if sent_dt is not None:
                            window = campaign_windows.get(refs_key)
                            if window is None:
                                campaign_windows[refs_key] = {"first": sent_dt, "last": sent_dt}
                            else:
                                if sent_dt < window["first"]:
                                    window["first"] = sent_dt
                                if sent_dt > window["last"]:
                                    window["last"] = sent_dt

                    if day is None:
                        continue
                    if not (start_utc <= day <= today_utc):
                        continue
                    pos = idx.get(day)
                    if pos is None:
                        continue

                    cls = str(meta.get(class_key, "UNKNOWN")).upper()
                    if cls == "DANGEROUS":
                        dangerous[pos] += 1
                    else:
                        non_danger[pos] += 1
                except Exception:
                    continue

        except Exception as e:
            logger.error("Error computing mail volume: %s", e, exc_info=True)

        window_start_dt = datetime(start_utc.year, start_utc.month, start_utc.day, tzinfo=dt_timezone.utc)
        window_end_dt = datetime(today_utc.year, today_utc.month, today_utc.day, tzinfo=dt_timezone.utc) + timedelta(days=1)

        campaigns_out = []
        for idx_num, (refs_key, bounds) in enumerate(campaign_windows.items(), start=1):
            start_dt = _ensure_utc(bounds.get("first"))
            end_dt = _ensure_utc(bounds.get("last"))
            if start_dt is None or end_dt is None:
                continue
            if end_dt < start_dt:
                start_dt, end_dt = end_dt, start_dt
            if end_dt < window_start_dt or start_dt > window_end_dt:
                continue

            clamped_start = max(start_dt, window_start_dt)
            clamped_end = min(end_dt, window_end_dt)
            if clamped_end < clamped_start:
                continue

            campaigns_out.append({
                "name": _format_campaign_name(refs_key, idx_num),
                "start": clamped_start.isoformat(),
                "end": clamped_end.isoformat(),
            })

        payload = {
            "dates": [d.isoformat() for d in all_days],
            "non_danger": non_danger,
            "dangerous": dangerous,
            "campaigns": campaigns_out,
        }
        serializer = CampaignMailVolumeResponseSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)