from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from case_handler.models import (
    Case,
    CaseArtifact,
    CaseHasFileOrMail,
    CaseHasNonFileIocs,
)


class CaseResource(resources.ModelResource):
    class Meta:
        model = Case
        fields = (
            'id', 'description', 'reporter__username', 'analysis_done',
            'status', 'results', 'final_score', 'final_confidence',
            'is_challenged', 'challenged_result', 'creation_date', 'last_update',
        )
        export_order = fields


class CaseHasFileOrMailResource(resources.ModelResource):
    class Meta:
        model = CaseHasFileOrMail
        fields = (
            'id', 'case__id', 'file__file_path', 'mail__subject', 'creation_date', 'last_update',
        )


class CaseHasNonFileIocsResource(resources.ModelResource):
    class Meta:
        model = CaseHasNonFileIocs
        fields = (
            'id', 'case__id', 'url__address', 'ip__address', 'hash__value', 'creation_date', 'last_update',
        )


class CaseArtifactResource(resources.ModelResource):
    class Meta:
        model = CaseArtifact
        fields = (
            'id', 'case__id', 'artifact_type',
            'file__file_path', 'hash__value', 'url__address',
            'ip__address', 'mail__subject',
            'creation_date', 'last_update',
        )


@admin.register(Case)
class CaseAdmin(ImportExportModelAdmin):
    resource_class = CaseResource
    list_display = ('id', 'description', 'reporter', 'status', 'results', 'is_challenged', 'creation_date')
    list_filter = ('status', 'results', 'is_challenged', 'creation_date')
    list_select_related = ('reporter',)
    search_fields = ('id', 'description', 'reporter__username')
    ordering = ('-creation_date',)


@admin.register(CaseHasFileOrMail)
class CaseHasFileOrMailAdmin(ImportExportModelAdmin):
    resource_class = CaseHasFileOrMailResource
    list_display = ('id', 'case', 'file', 'mail', 'creation_date')
    list_select_related = ('case', 'file', 'mail')
    search_fields = ('case__id', 'file__file_path', 'mail__subject')
    ordering = ('-creation_date',)


@admin.register(CaseHasNonFileIocs)
class CaseHasNonFileIocsAdmin(ImportExportModelAdmin):
    resource_class = CaseHasNonFileIocsResource
    list_display = ('id', 'case', 'url', 'ip', 'hash', 'creation_date')
    list_select_related = ('case', 'url', 'ip', 'hash')
    search_fields = ('case__id', 'url__address', 'ip__address', 'hash__value')
    ordering = ('-creation_date',)


@admin.register(CaseArtifact)
class CaseArtifactAdmin(ImportExportModelAdmin):
    resource_class = CaseArtifactResource
    list_display = (
        'id', 'case', 'artifact_type',
        'file', 'hash', 'url', 'ip', 'mail',
        'creation_date',
    )
    list_filter = ('artifact_type', 'creation_date')
    list_select_related = ('case', 'file', 'hash', 'url', 'ip', 'mail')
    search_fields = (
        'case__id', 'file__file_path', 'hash__value',
        'url__address', 'ip__address', 'mail__subject',
    )
    ordering = ('-creation_date',)
