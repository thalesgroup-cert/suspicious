from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from cortex_job.models import Analyzer, AnalyzerReport


class AnalyzerResource(resources.ModelResource):
    class Meta:
        model = Analyzer
        fields = (
            'id', 'name', 'weight', 'analyzer_cortex_id',
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


@admin.register(Analyzer)
class AnalyzerAdmin(ImportExportModelAdmin):
    resource_class = AnalyzerResource
    list_display = ('id', 'name', 'weight', 'is_active', 'creation_date', 'last_update')
    list_filter = ('is_active', 'creation_date')
    search_fields = ('name', 'analyzer_cortex_id')
    ordering = ('-creation_date',)


@admin.register(AnalyzerReport)
class AnalyzerReportAdmin(ImportExportModelAdmin):
    resource_class = AnalyzerReportResource
    list_display = ('id', 'analyzer', 'type', 'status', 'level', 'score', 'creation_date')
    list_filter = ('type', 'status', 'level', 'creation_date')
    list_select_related = ('analyzer',)
    list_per_page = 50
    show_full_result_count = False
    # The changelist never shows the report blobs; loading them per row is the
    # main cost. The change form is unaffected.
    _LIST_DEFER = ('report_full', 'report_summary', 'report_taxonomy', 'enrichment')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        match = request.resolver_match
        if match and match.url_name and match.url_name.endswith('_changelist'):
            qs = qs.defer(*self._LIST_DEFER)
        return qs

    search_fields = ('analyzer__name', 'cortex_job_id')
    ordering = ('-creation_date',)
