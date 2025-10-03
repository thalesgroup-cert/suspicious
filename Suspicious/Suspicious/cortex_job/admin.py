from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from cortex_job.models import Analyzer, AnalyzerReport


# Resources
class AnalyzerResource(resources.ModelResource):
    class Meta:
        model = Analyzer
        fields = (
            'id', 'name', 'weight', 'analyzer_cortex_id', 'analyzer_cortex_2_id',
            'is_active', 'creation_date', 'last_update',
        )
        export_order = fields


class AnalyzerReportResource(resources.ModelResource):
    class Meta:
        model = AnalyzerReport
        fields = (
            'id', 'cortex_job_id', 'type', 'status', 'analyzer__name', 'url__address', 'hash__value',
            'file__file_path', 'ip__address', 'mail_body__fuzzy_hash', 'mail_header__fuzzy_hash',
            'level', 'confidence', 'score', 'category', 'report_summary',
            'report_taxonomy', 'report_full', 'creation_date', 'last_update',
        )
        export_order = fields


# Admin classes
@admin.register(Analyzer)
class AnalyzerAdmin(ImportExportModelAdmin):
    resource_class = AnalyzerResource
    list_display = ('id', 'name', 'weight', 'is_active', 'creation_date', 'last_update')
    list_filter = ('is_active', 'creation_date')
    search_fields = ('name', 'analyzer_cortex_id', 'analyzer_cortex_2_id')
    ordering = ('-creation_date',)


@admin.register(AnalyzerReport)
class AnalyzerReportAdmin(ImportExportModelAdmin):
    resource_class = AnalyzerReportResource
    list_display = ('id', 'analyzer', 'type', 'status', 'level', 'score', 'creation_date')
    list_filter = ('type', 'status', 'level', 'creation_date')
    search_fields = (
        'analyzer__name', 'cortex_job_id', 'url__address', 'hash__value',
        'file__file_path', 'ip__address', 'mail_body__fuzzy_hash', 'mail_header__fuzzy_hash',
    )
    ordering = ('-creation_date',)
