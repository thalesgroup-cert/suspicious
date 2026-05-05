from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from case_handler.models import (
    Case,
    CaseHasFileOrMail,
    CaseHasNonFileIocs,
    IpInCases,
    UrlInCases,
    HashInCases,
    MailInCases,
    FileInCases,
)


# Resources
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


class IpInCasesResource(resources.ModelResource):
    class Meta:
        model = IpInCases
        fields = ('id', 'ip__address', 'creation_date', 'last_update')


class UrlInCasesResource(resources.ModelResource):
    class Meta:
        model = UrlInCases
        fields = ('id', 'url__address', 'creation_date', 'last_update')


class HashInCasesResource(resources.ModelResource):
    class Meta:
        model = HashInCases
        fields = ('id', 'hash__value', 'creation_date', 'last_update')


class MailInCasesResource(resources.ModelResource):
    class Meta:
        model = MailInCases
        fields = ('id', 'associated_mail__subject', 'creation_date', 'last_update')


class FileInCasesResource(resources.ModelResource):
    class Meta:
        model = FileInCases
        fields = ('id', 'file__file_path', 'creation_date', 'last_update')


# Admin classes
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


@admin.register(IpInCases)
class IpInCasesAdmin(ImportExportModelAdmin):
    resource_class = IpInCasesResource
    list_display = ('id', 'ip', 'creation_date')
    list_select_related = ('ip',)
    search_fields = ('ip__address',)
    ordering = ('-creation_date',)


@admin.register(UrlInCases)
class UrlInCasesAdmin(ImportExportModelAdmin):
    resource_class = UrlInCasesResource
    list_display = ('id', 'url', 'creation_date')
    list_select_related = ('url',)
    search_fields = ('url__address',)
    ordering = ('-creation_date',)


@admin.register(HashInCases)
class HashInCasesAdmin(ImportExportModelAdmin):
    resource_class = HashInCasesResource
    list_display = ('id', 'hash', 'creation_date')
    list_select_related = ('hash',)
    search_fields = ('hash__value',)
    ordering = ('-creation_date',)


@admin.register(MailInCases)
class MailInCasesAdmin(ImportExportModelAdmin):
    resource_class = MailInCasesResource
    list_display = ('id', 'associated_mail', 'creation_date')
    list_select_related = ('associated_mail',)
    search_fields = ('associated_mail__subject',)
    ordering = ('-creation_date',)


@admin.register(FileInCases)
class FileInCasesAdmin(ImportExportModelAdmin):
    resource_class = FileInCasesResource
    list_display = ('id', 'file', 'creation_date')
    list_select_related = ('file',)
    search_fields = ('file__file_path',)
    ordering = ('-creation_date',)
