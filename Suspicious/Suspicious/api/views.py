from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Sum

from .models import (
    Kpi, MonthlyCasesSummary, MonthlyReporterStats,
    TotalCasesStats, UserCasesMonthlyStats
)
from .serializers import (
    KpiSerializer, MonthlyCasesSummarySerializer,
    MonthlyReporterStatsSerializer, TotalCasesStatsSerializer,
    UserCasesMonthlyStatsSerializer
)


# List / detail views with filtering
class KpiListView(generics.ListAPIView):
    queryset = Kpi.objects.all()
    serializer_class = KpiSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['month', 'year']


class KpiDetailView(generics.RetrieveAPIView):
    queryset = Kpi.objects.all()
    serializer_class = KpiSerializer


class MonthlyCasesSummaryListView(generics.ListAPIView):
    queryset = MonthlyCasesSummary.objects.all()
    serializer_class = MonthlyCasesSummarySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['id']


class MonthlyReporterStatsListView(generics.ListAPIView):
    queryset = MonthlyReporterStats.objects.all()
    serializer_class = MonthlyReporterStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['id']


class TotalCasesStatsListView(generics.ListAPIView):
    queryset = TotalCasesStats.objects.all()
    serializer_class = TotalCasesStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['id']


class UserCasesMonthlyStatsListView(generics.ListAPIView):
    queryset = UserCasesMonthlyStats.objects.all()
    serializer_class = UserCasesMonthlyStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['user', 'month', 'year']


# Example summary endpoint for aggregated stats
class MonthlyCasesSummaryAggregateView(APIView):
    """
    Returns aggregated totals of all high-level and detailed cases.
    """
    def get(self, request):
        data = MonthlyCasesSummary.objects.aggregate(
            suspicious_cases=Sum('suspicious_cases'),
            inconclusive_cases=Sum('inconclusive_cases'),
            failure_cases=Sum('failure_cases'),
            dangerous_cases=Sum('dangerous_cases'),
            safe_cases=Sum('safe_cases'),
            challenged_cases=Sum('challenged_cases'),
            allow_listed_cases=Sum('allow_listed_cases'),
            uncategorized_cases=Sum('uncategorized_cases'),
            spam_cases=Sum('spam_cases'),
            newsletter_cases=Sum('newsletter_cases'),
            classic_phishing_cases=Sum('classic_phishing_cases'),
            clone_cases=Sum('clone_cases'),
            blackmail_cases=Sum('blackmail_cases'),
            whaling_cases=Sum('whaling_cases'),
            internal_cases=Sum('internal_cases'),
            external_cases=Sum('external_cases'),
        )
        return Response(data)


# Example summary endpoint for user cases
class UserCasesMonthlyStatsAggregateView(APIView):
    """
    Returns total cases per user optionally filtered by month/year.
    """
    def get(self, request):
        filters = {}
        month = request.query_params.get('month')
        year = request.query_params.get('year')
        if month:
            filters['month'] = month
        if year:
            filters['year'] = year

        data = UserCasesMonthlyStats.objects.filter(**filters).values('user__username').annotate(
            total_suspicious=Sum('suspicious_cases'),
            total_inconclusive=Sum('inconclusive_cases'),
            total_failure=Sum('failure_cases'),
            total_dangerous=Sum('dangerous_cases'),
            total_safe=Sum('safe_cases'),
            total_challenged=Sum('challenged_cases'),
            total_allow_listed=Sum('allow_listed_cases'),
        )
        return Response(data)
