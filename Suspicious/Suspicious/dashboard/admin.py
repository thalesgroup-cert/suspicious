from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from .models import (
    Kpi,
    MonthlyCasesSummary,
    MonthlyReporterStats,
    TotalCasesStats,
    UserCasesMonthlyStats,
)


# Resources
class KpiResource(resources.ModelResource):
    class Meta:
        model = Kpi
        fields = ('id', 'month', 'year', 'monthly_cases_summary', 'monthly_reporter_stats', 'total_cases_stats', 'creation_date', 'last_update')
        export_order = fields


class MonthlyCasesSummaryResource(resources.ModelResource):
    class Meta:
        model = MonthlyCasesSummary
        fields = (
            'id', 'suspicious_cases', 'inconclusive_cases', 'failure_cases', 'dangerous_cases',
            'safe_cases', 'challenged_cases', 'allow_listed_cases', 'creation_date', 'last_update',
        )
        export_order = fields


class MonthlyReporterStatsResource(resources.ModelResource):
    class Meta:
        model = MonthlyReporterStats
        fields = ('id', 'new_reporters', 'total_reporters', 'creation_date', 'last_update')
        export_order = fields


class TotalCasesStatsResource(resources.ModelResource):
    class Meta:
        model = TotalCasesStats
        fields = ('id', 'total_cases', 'creation_date', 'last_update')
        export_order = fields


class UserCasesMonthlyStatsResource(resources.ModelResource):
    class Meta:
        model = UserCasesMonthlyStats
        fields = (
            'id', 'user__username', 'suspicious_cases', 'inconclusive_cases', 'failure_cases',
            'dangerous_cases', 'safe_cases', 'challenged_cases', 'allow_listed_cases', 'total_cases',
            'month', 'year', 'creation_date', 'last_update',
        )
        export_order = fields


# Admin classes
@admin.register(Kpi)
class KpiAdmin(ImportExportModelAdmin):
    resource_class = KpiResource
    list_display = ('id', 'month', 'year', 'creation_date', 'last_update')
    list_filter = ('year', 'month', 'creation_date')
    search_fields = ('month', 'year')
    ordering = ('-creation_date',)


@admin.register(MonthlyCasesSummary)
class MonthlyCasesSummaryAdmin(ImportExportModelAdmin):
    resource_class = MonthlyCasesSummaryResource
    list_display = ('id', 'suspicious_cases', 'inconclusive_cases', 'dangerous_cases', 'safe_cases', 'creation_date')
    list_filter = ('creation_date',)
    search_fields = ('id',)
    ordering = ('-creation_date',)


@admin.register(MonthlyReporterStats)
class MonthlyReporterStatsAdmin(ImportExportModelAdmin):
    resource_class = MonthlyReporterStatsResource
    list_display = ('id', 'new_reporters', 'total_reporters', 'creation_date', 'last_update')
    list_filter = ('creation_date',)
    search_fields = ('id',)
    ordering = ('-creation_date',)


@admin.register(TotalCasesStats)
class TotalCasesStatsAdmin(ImportExportModelAdmin):
    resource_class = TotalCasesStatsResource
    list_display = ('id', 'total_cases', 'creation_date', 'last_update')
    list_filter = ('creation_date',)
    search_fields = ('id',)
    ordering = ('-creation_date',)


@admin.register(UserCasesMonthlyStats)
class UserCasesMonthlyStatsAdmin(ImportExportModelAdmin):
    resource_class = UserCasesMonthlyStatsResource
    list_display = ('id', 'user', 'month', 'year', 'total_cases', 'creation_date', 'last_update')
    list_filter = ('month', 'year', 'creation_date')
    search_fields = ('user__username', 'month', 'year')
    ordering = ('-creation_date',)
