from collections import defaultdict

from django.conf import settings
from django.db.models import Sum, Value, CharField, F, Case, When
from django.db.models.functions import Lower, StrIndex, Substr, Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.models import (
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats,
)
from api.serializers.dashboard import (
    DashboardSummaryQuerySerializer,
    DashboardSummaryResponseSerializer,
    MonthlyCasesSummaryAggregateSerializer,
    MonthlyCasesSummarySerializer,
    MonthlyReporterStatsSerializer,
    TotalCasesStatsSerializer,
    UserCasesMonthlyStatsAggregateRowSerializer,
    UserCasesMonthlyStatsSerializer,
)
from api.views.filters import (
    MonthlyCasesSummaryFilter,
    MonthlyReporterStatsFilter,
    TotalCasesStatsFilter,
)
from api.views.mixins import MonthYearQueryMixin
from dashboard.models import UserCasesMonthlyStats, GroupMonthlyStats
from api.serializers.dashboard import TopPrefixesResponseSerializer

class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    DEFAULT_TOP_PREFIXES_LIMIT = 10

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY, required=True),
            OpenApiParameter("year", int, OpenApiParameter.QUERY, required=True),
            OpenApiParameter(
                "scope",
                str,
                OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Dashboard scope. Currently echoed for UI compatibility. "
                    "Data is not scope-filtered unless backend scope support is implemented."
                ),
            ),
        ],
        responses=DashboardSummaryResponseSerializer,
        description="Return the dashboard summary for a given month and year.",
    )
    def get(self, request):
        query = DashboardSummaryQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)

        month = query.validated_data["month"]
        year = query.validated_data["year"]
        requested_scope = query.validated_data.get("scope", "ALL")

        scope = self._resolve_scope(requested_scope=requested_scope)

        payload = self._build_summary_payload(
            month=month,
            year=year,
            scope=scope,
        )

        response_serializer = DashboardSummaryResponseSerializer(instance=payload)
        return Response(response_serializer.data)

    def _resolve_scope(self, requested_scope: str) -> str:
        """
        Scope is currently not backed by a database dimension in these stats tables.
        Until that exists, we only normalize and echo it for eligible users.
        """
        if not self.request.user.groups.filter(name="CISO").exists():
            return "ALL"
        return requested_scope

    def _build_summary_payload(self, *, month: int, year: int, scope: str) -> dict:
        cases_agg = self._get_cases_aggregate(month=month, year=year)
        reporters_agg = self._get_reporters_aggregate(month=month, year=year)
        total_cases_agg = self._get_total_cases_aggregate(month=month, year=year)

        malicious_total = (
            cases_agg["classic_phishing_cases"]
            + cases_agg["clone_cases"]
            + cases_agg["blackmail_cases"]
            + cases_agg["whaling_cases"]
        )

        return {
            "month": month,
            "year": year,
            "scope": scope,
            "kpis": {
                "new_users": reporters_agg["new_users"],
                "total_reporters": reporters_agg["total_reporters"],
                "total_cases": total_cases_agg["total_cases"],
            },
            "danger_counts": {
                "failure": cases_agg["failure_cases"],
                "safe": cases_agg["safe_cases"],
                "inconclusive": cases_agg["inconclusive_cases"],
                "suspicious": cases_agg["suspicious_cases"],
                "dangerous": cases_agg["dangerous_cases"],
                "malicious": malicious_total,
            },
            "top_prefixes": self._get_top_prefixes(
                month=month,
                year=year,
                limit=self.DEFAULT_TOP_PREFIXES_LIMIT,
            ),
        }

    @staticmethod
    def _get_cases_aggregate(*, month: int, year: int) -> dict:
        return MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            failure_cases=Coalesce(Sum("failure_cases"), 0),
            safe_cases=Coalesce(Sum("safe_cases"), 0),
            inconclusive_cases=Coalesce(Sum("inconclusive_cases"), 0),
            suspicious_cases=Coalesce(Sum("suspicious_cases"), 0),
            dangerous_cases=Coalesce(Sum("dangerous_cases"), 0),
            classic_phishing_cases=Coalesce(Sum("classic_phishing_cases"), 0),
            clone_cases=Coalesce(Sum("clone_cases"), 0),
            blackmail_cases=Coalesce(Sum("blackmail_cases"), 0),
            whaling_cases=Coalesce(Sum("whaling_cases"), 0),
        )

    @staticmethod
    def _get_reporters_aggregate(*, month: int, year: int) -> dict:
        return MonthlyReporterStats.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            new_users=Coalesce(Sum("new_reporters"), 0),
            total_reporters=Coalesce(Sum("total_reporters"), 0),
        )

    @staticmethod
    def _get_total_cases_aggregate(*, month: int, year: int) -> dict:
        return TotalCasesStats.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            total_cases=Coalesce(Sum("total_cases"), 0),
        )

    def _get_top_prefixes(self, *, month: int, year: int, limit: int) -> list[dict]:
        month_str = str(month)
        year_str = str(year)
        suspicious_email = getattr(settings, "SUSPICIOUS_EMAIL", None)

        qs = UserCasesMonthlyStats.objects.filter(
            month=month_str,
            year=year_str,
        )

        if suspicious_email:
            qs = qs.exclude(user__username=suspicious_email)

        rows = qs.values_list("user__username", "total_cases")

        totals_by_prefix: dict[str, int] = defaultdict(int)
        for username, total_cases in rows:
            label = self._extract_email_prefix(username)
            if not label:
                continue
            totals_by_prefix[label] += int(total_cases or 0)

        sorted_items = sorted(
            totals_by_prefix.items(),
            key=lambda item: (-item[1], item[0]),
        )[:limit]

        return [
            {"label": label, "value": value}
            for label, value in sorted_items
        ]

    @staticmethod
    def _extract_email_prefix(value: str) -> str:
        if not value:
            return ""
        local_part, sep, _domain = value.strip().partition("@")
        if sep == "@":
            return local_part
        return value.strip()


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


class MonthlyCasesSummaryAggregateView(MonthYearQueryMixin, APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY, required=True),
            OpenApiParameter("year", int, OpenApiParameter.QUERY, required=True),
        ],
        responses=MonthlyCasesSummaryAggregateSerializer,
        description="Aggregate case statistics for a given month and year.",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).aggregate(
            suspicious_cases=Coalesce(Sum("suspicious_cases"), 0),
            inconclusive_cases=Coalesce(Sum("inconclusive_cases"), 0),
            failure_cases=Coalesce(Sum("failure_cases"), 0),
            dangerous_cases=Coalesce(Sum("dangerous_cases"), 0),
            safe_cases=Coalesce(Sum("safe_cases"), 0),
            challenged_cases=Coalesce(Sum("challenged_cases"), 0),
            allow_listed_cases=Coalesce(Sum("allow_listed_cases"), 0),
            uncategorized_cases=Coalesce(Sum("uncategorized_cases"), 0),
            spam_cases=Coalesce(Sum("spam_cases"), 0),
            newsletter_cases=Coalesce(Sum("newsletter_cases"), 0),
            classic_phishing_cases=Coalesce(Sum("classic_phishing_cases"), 0),
            clone_cases=Coalesce(Sum("clone_cases"), 0),
            blackmail_cases=Coalesce(Sum("blackmail_cases"), 0),
            whaling_cases=Coalesce(Sum("whaling_cases"), 0),
            internal_cases=Coalesce(Sum("internal_cases"), 0),
            external_cases=Coalesce(Sum("external_cases"), 0),
        )

        payload = {
            "month": month,
            "year": year,
            **data,
        }

        serializer = MonthlyCasesSummaryAggregateSerializer(instance=payload)
        return Response(serializer.data)


class UserCasesMonthlyStatsAggregateView(MonthYearQueryMixin, APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY, required=True),
            OpenApiParameter("year", int, OpenApiParameter.QUERY, required=True),
        ],
        responses=UserCasesMonthlyStatsAggregateRowSerializer(many=True),
        description="Aggregate per-user case statistics for a given month and year.",
    )
    def get(self, request):
        month, year = self.get_month_year()
        month_str = str(month)
        year_str = str(year)

        rows = (
            UserCasesMonthlyStats.objects.filter(month=month_str, year=year_str)
            .values("user__username")
            .annotate(
                total_cases=Coalesce(Sum("total_cases"), 0),
                total_safe=Coalesce(Sum("safe_cases"), 0),
                total_dangerous=Coalesce(Sum("dangerous_cases"), 0),
                total_suspicious=Coalesce(Sum("suspicious_cases"), 0),
                total_inconclusive=Coalesce(Sum("inconclusive_cases"), 0),
                total_failure=Coalesce(Sum("failure_cases"), 0),
                total_uncategorized=Coalesce(Sum("uncategorized_cases"), 0),
                total_spam=Coalesce(Sum("spam_cases"), 0),
                total_newsletter=Coalesce(Sum("newsletter_cases"), 0),
                total_classic_phishing=Coalesce(Sum("classic_phishing_cases"), 0),
                total_clone=Coalesce(Sum("clone_cases"), 0),
                total_blackmail=Coalesce(Sum("blackmail_cases"), 0),
                total_whaling=Coalesce(Sum("whaling_cases"), 0),
                total_internal=Coalesce(Sum("internal_cases"), 0),
                total_external=Coalesce(Sum("external_cases"), 0),
                total_challenged=Coalesce(Sum("challenged_cases"), 0),
                total_allow_listed=Coalesce(Sum("allow_listed_cases"), 0),
            )
            .order_by("-total_cases", "user__username")
        )

        payload = [
            {
                "username": row["user__username"],
                "month": month,
                "year": year,
                "total_cases": row["total_cases"],
                "total_safe": row["total_safe"],
                "total_dangerous": row["total_dangerous"],
                "total_suspicious": row["total_suspicious"],
                "total_inconclusive": row["total_inconclusive"],
                "total_failure": row["total_failure"],
                "total_uncategorized": row["total_uncategorized"],
                "total_spam": row["total_spam"],
                "total_newsletter": row["total_newsletter"],
                "total_classic_phishing": row["total_classic_phishing"],
                "total_clone": row["total_clone"],
                "total_blackmail": row["total_blackmail"],
                "total_whaling": row["total_whaling"],
                "total_internal": row["total_internal"],
                "total_external": row["total_external"],
                "total_challenged": row["total_challenged"],
                "total_allow_listed": row["total_allow_listed"],
            }
            for row in rows
        ]

        serializer = UserCasesMonthlyStatsAggregateRowSerializer(instance=payload, many=True)
        return Response(serializer.data)

class TopPrefixesView(APIView):
    permission_classes = [IsAuthenticated]

    DEFAULT_LIMIT = 10
    MAX_LIMIT = 50

    def get(self, request, *args, **kwargs):
        ranking_type = request.query_params.get("type", "user")
        month = request.query_params.get("month")
        year = request.query_params.get("year")

        try:
            limit = int(request.query_params.get("limit", self.DEFAULT_LIMIT))
        except (TypeError, ValueError):
            return Response({"detail": "Invalid limit."}, status=status.HTTP_400_BAD_REQUEST)

        if ranking_type not in {"user", "group"}:
            return Response(
                {"detail": "type must be either 'user' or 'group'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        limit = max(1, min(limit, self.MAX_LIMIT))

        if ranking_type == "user":
            rows = self._query_user_prefixes(month=month, year=year, limit=limit)
        else:
            rows = self._query_group_prefixes(month=month, year=year, limit=limit)

        payload = {
            "type": ranking_type,
            "month": month,
            "year": year,
            "data": list(rows),
        }
        return Response(TopPrefixesResponseSerializer(payload).data)

    def _query_user_prefixes(self, month=None, year=None, limit=10):
        qs = UserCasesMonthlyStats.objects.select_related("user")

        if month:
            qs = qs.filter(month=str(month).zfill(2))
        if year:
            qs = qs.filter(year=str(year))

        username_expr = Lower(Coalesce(F("user__username"), Value("")))
        at_pos = StrIndex(username_expr, Value("@"))

        qs = qs.annotate(
            prefix=Case(
                When(
                    **{"user__username__icontains": "@"},
                    then=Substr(username_expr, 1, at_pos - 1),
                ),
                default=username_expr,
                output_field=CharField(),
            )
        )

        return (
            qs.exclude(prefix="")
            .values("prefix")
            .annotate(
                total=Sum("total_cases"),
                safe=Sum("safe_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
                failure=Sum("failure_cases"),
                inconclusive=Sum("inconclusive_cases"),
            )
            .order_by("-total")[:limit]
        )

    def _query_group_prefixes(self, month=None, year=None, limit=10):
        qs = GroupMonthlyStats.objects.all()

        if month:
            qs = qs.filter(month=str(month).zfill(2))
        if year:
            qs = qs.filter(year=str(year))

        group_expr = Lower(Coalesce(F("group_name"), Value("")))
        space_pos = StrIndex(group_expr, Value(" "))

        qs = qs.annotate(
            prefix=Case(
                When(
                    group_name__icontains=" ",
                    then=Substr(group_expr, 1, space_pos - 1),
                ),
                default=group_expr,
                output_field=CharField(),
            )
        )

        return (
            qs.exclude(prefix="")
            .values("prefix")
            .annotate(
                total=Sum("total_cases"),
                safe=Sum("safe_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
                failure=Sum("failure_cases"),
                inconclusive=Sum("inconclusive_cases"),
            )
            .order_by("-total")[:limit]
        )