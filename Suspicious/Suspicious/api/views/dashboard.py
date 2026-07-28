
import django_filters
from django.core.cache import cache
from django.db.models import Sum, Value, CharField, F, Case, When
from django.db.models.functions import Coalesce, Lower, StrIndex, Substr
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, status
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.settings import IsAdminOrCERT

from dashboard.models import (
    GroupMonthlyStats,
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats,
)
from dashboard.snapshot import build_dashboard_payload, get_snapshot
from api.serializers.dashboard import (
    DashboardSummaryQuerySerializer,
    DashboardSummaryResponseSerializer,
    MonthlyCasesSummaryAggregateSerializer,
    MonthlyCasesSummarySerializer,
    MonthlyReporterStatsSerializer,
    TopPrefixesResponseSerializer,
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

DASHBOARD_CACHE_TTL = 120
TOP_PREFIXES_CACHE_TTL = 120


class DashboardLimitOffsetPagination(LimitOffsetPagination):
    default_limit = 100
    max_limit = 1000


class UserCasesMonthlyStatsFilter(django_filters.FilterSet):
    month = django_filters.CharFilter(field_name="month", required=True)
    year = django_filters.CharFilter(field_name="year", required=True)
    user = django_filters.NumberFilter(field_name="user")

    class Meta:
        model = UserCasesMonthlyStats
        fields = ["user", "month", "year"]


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

        snap = get_snapshot(month, year)
        if snap is not None:
            payload = {**snap, "scope": scope}
            return Response(
                DashboardSummaryResponseSerializer(instance=self._scrub(payload)).data
            )

        cache_key = f"dashboard:summary:{year}:{month}:{scope}"
        payload = cache.get(cache_key)
        if payload is None:
            payload = build_dashboard_payload(month=month, year=year, scope=scope)
            cache.set(cache_key, payload, DASHBOARD_CACHE_TTL)

        return Response(DashboardSummaryResponseSerializer(instance=self._scrub(payload)).data)

    def _resolve_scope(self, requested_scope: str) -> str:
        if not self.request.user.groups.filter(name="CISO").exists():
            return "ALL"
        return requested_scope

    def _scrub(self, payload: dict) -> dict:
        return payload


class MonthlyCasesSummaryListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyCasesSummary.objects.all()
    serializer_class = MonthlyCasesSummarySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyCasesSummaryFilter
    pagination_class = DashboardLimitOffsetPagination


class MonthlyReporterStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyReporterStats.objects.all()
    serializer_class = MonthlyReporterStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyReporterStatsFilter
    pagination_class = DashboardLimitOffsetPagination


class TotalCasesStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = TotalCasesStats.objects.all()
    serializer_class = TotalCasesStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = TotalCasesStatsFilter
    pagination_class = DashboardLimitOffsetPagination


class UserCasesMonthlyStatsListView(generics.ListAPIView):
    """List per-user monthly stats. month + year are required filters
    to prevent unbounded scans (e.g. from Power BI imports).

    Per-user breakdowns name individual analysts and their case volumes,
    so access is limited to Admin/CERT — regular reporters only ever see
    org-wide aggregates, never colleague-level figures.
    """
    permission_classes = [IsAdminOrCERT]
    queryset = UserCasesMonthlyStats.objects.select_related("user").all()
    serializer_class = UserCasesMonthlyStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserCasesMonthlyStatsFilter
    pagination_class = DashboardLimitOffsetPagination


class UserCasesMonthlyStatsDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAdminOrCERT]
    queryset = UserCasesMonthlyStats.objects.select_related("user").all()
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

        cache_key = f"dashboard:monthly-cases:{year}:{month}"
        data = cache.get(cache_key)
        if data is None:
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
            cache.set(cache_key, data, DASHBOARD_CACHE_TTL)

        payload = {"month": month, "year": year, **data}
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

        cache_key = f"dashboard:user-stats:{year}:{month}"
        cached = cache.get(cache_key)
        if cached is not None:
            serializer = UserCasesMonthlyStatsAggregateRowSerializer(instance=cached, many=True)
            return Response(serializer.data)

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

        cache.set(cache_key, payload, DASHBOARD_CACHE_TTL)
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

        cache_key = f"dashboard:top-prefixes:{ranking_type}:{year}:{month}:{limit}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(TopPrefixesResponseSerializer(cached).data)

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
        cache.set(cache_key, payload, TOP_PREFIXES_CACHE_TTL)
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
                    user__username__contains="@",
                    then=Substr(
                        username_expr,
                        1,
                        Case(
                            When(pk__isnull=False, then=at_pos - 1),
                            default=Value(0),
                        ),
                    ),
                ),
                default=username_expr,
                output_field=CharField(),
            )
        )

        return (
            qs.exclude(prefix="")
            .values("prefix")
            .annotate(
                total=Coalesce(Sum("total_cases"), 0),
                safe=Coalesce(Sum("safe_cases"), 0),
                suspicious=Coalesce(Sum("suspicious_cases"), 0),
                dangerous=Coalesce(Sum("dangerous_cases"), 0),
                failure=Coalesce(Sum("failure_cases"), 0),
                inconclusive=Coalesce(Sum("inconclusive_cases"), 0),
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
                    group_name__contains=" ",
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
                total=Coalesce(Sum("total_cases"), 0),
                safe=Coalesce(Sum("safe_cases"), 0),
                suspicious=Coalesce(Sum("suspicious_cases"), 0),
                dangerous=Coalesce(Sum("dangerous_cases"), 0),
                failure=Coalesce(Sum("failure_cases"), 0),
                inconclusive=Coalesce(Sum("inconclusive_cases"), 0),
            )
            .order_by("-total")[:limit]
        )