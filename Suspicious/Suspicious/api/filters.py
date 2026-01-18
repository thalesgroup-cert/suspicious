import django_filters
from dashboard.models import MonthlyCasesSummary, MonthlyReporterStats, TotalCasesStats

class MonthlyCasesSummaryFilter(django_filters.FilterSet):
    month = django_filters.NumberFilter(field_name='creation_date', lookup_expr='month')
    year = django_filters.NumberFilter(field_name='creation_date', lookup_expr='year')

    class Meta:
        model = MonthlyCasesSummary
        fields = ['id', 'month', 'year']

class MonthlyReporterStatsFilter(django_filters.FilterSet):
    month = django_filters.NumberFilter(field_name='creation_date', lookup_expr='month')
    year = django_filters.NumberFilter(field_name='creation_date', lookup_expr='year')

    class Meta:
        model = MonthlyReporterStats
        fields = ['id', 'month', 'year']

class TotalCasesStatsFilter(django_filters.FilterSet):
    month = django_filters.NumberFilter(field_name='creation_date', lookup_expr='month')
    year = django_filters.NumberFilter(field_name='creation_date', lookup_expr='year')

    class Meta:
        model = TotalCasesStats
        fields = ['id', 'month', 'year']
