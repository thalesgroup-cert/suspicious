from dashboard.models import (
    MonthlyCasesSummary,
    UserCasesMonthlyStats,
    MonthlyReporterStats,
    TotalCasesStats,
)

from api.serializers.dashboard import (
    MonthlyCasesSummarySerializer,
    UserCasesMonthlyStatsSerializer,
    MonthlyReporterStatsSerializer,
    TotalCasesStatsSerializer,
    DashboardSummaryResponseSerializer,
)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from django.db.models import Sum
from django.db.models.functions import Coalesce
from django.conf import settings
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics
from drf_spectacular.utils import extend_schema, OpenApiParameter
from api.views.mixins import MonthYearQueryMixin
from api.views.filters import MonthlyCasesSummaryFilter, MonthlyReporterStatsFilter, TotalCasesStatsFilter


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

