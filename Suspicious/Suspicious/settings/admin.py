from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from .models import Mailbox, AllowListDomain, AllowListFile, AllowListFiletype, DenyListDomain, DenyListFile, CampaignDomainAllowList


# Resource for Mailbox
class MailboxResource(resources.ModelResource):
    class Meta:
        model = Mailbox
        fields = ('id', 'name', 'username', 'server', 'port', 'creation_date', 'last_update')
        export_order = ('id', 'name', 'username', 'server', 'port', 'creation_date', 'last_update')


@admin.register(Mailbox)
class MailboxAdmin(ImportExportModelAdmin):
    resource_class = MailboxResource
    list_display = ('name', 'username', 'server', 'port', 'creation_date', 'last_update')
    list_filter = ('server', 'port', 'creation_date')
    search_fields = ('name', 'username', 'server')
    ordering = ('creation_date',)


# Resource for AllowListDomain
class AllowListDomainResource(resources.ModelResource):
    class Meta:
        model = AllowListDomain
        fields = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')


@admin.register(AllowListDomain)
class AllowListDomainAdmin(ImportExportModelAdmin):
    resource_class = AllowListDomainResource
    list_display = ('domain', 'user', 'creation_date', 'last_update')
    list_filter = ('domain', 'user', 'creation_date')
    search_fields = ('domain__value', 'user__username')
    ordering = ('creation_date',)


# Resource for AllowListFile
class AllowListFileResource(resources.ModelResource):
    class Meta:
        model = AllowListFile
        fields = ('id', 'linked_file_hash__value', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'linked_file_hash__value', 'user__username', 'creation_date', 'last_update')


@admin.register(AllowListFile)
class AllowListFileAdmin(ImportExportModelAdmin):
    resource_class = AllowListFileResource
    list_display = ('linked_file_hash', 'user', 'creation_date', 'last_update')
    list_filter = ('linked_file_hash', 'user', 'creation_date')
    search_fields = ('linked_file_hash__value', 'user__username')
    ordering = ('creation_date',)


# Resource for AllowListFiletype
class AllowListFiletypeResource(resources.ModelResource):
    class Meta:
        model = AllowListFiletype
        fields = ('id', 'filetype', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'filetype', 'user__username', 'creation_date', 'last_update')


@admin.register(AllowListFiletype)
class AllowListFiletypeAdmin(ImportExportModelAdmin):
    resource_class = AllowListFiletypeResource
    list_display = ('filetype', 'user', 'creation_date', 'last_update')
    list_filter = ('filetype', 'user', 'creation_date')
    search_fields = ('filetype', 'user__username')
    ordering = ('creation_date',)


# Resource for DenyListDomain
class DenyListDomainResource(resources.ModelResource):
    class Meta:
        model = DenyListDomain
        fields = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')


@admin.register(DenyListDomain)
class DenyListDomainAdmin(ImportExportModelAdmin):
    resource_class = DenyListDomainResource
    list_display = ('domain', 'user', 'creation_date', 'last_update')
    list_filter = ('domain', 'user', 'creation_date')
    search_fields = ('domain__value', 'user__username')
    ordering = ('creation_date',)


# Resource for DenyListFile
class DenyListFileResource(resources.ModelResource):
    class Meta:
        model = DenyListFile
        fields = ('id', 'linked_file_hash__value', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'linked_file_hash__value', 'user__username', 'creation_date', 'last_update')


@admin.register(DenyListFile)
class DenyListFileAdmin(ImportExportModelAdmin):
    resource_class = DenyListFileResource
    list_display = ('linked_file_hash', 'user', 'creation_date', 'last_update')
    list_filter = ('linked_file_hash', 'user', 'creation_date')
    search_fields = ('linked_file_hash__value', 'user__username')
    ordering = ('creation_date',)


# Resource for CampaignDomainAllowList
class CampaignDomainAllowListResource(resources.ModelResource):
    class Meta:
        model = CampaignDomainAllowList
        fields = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')
        export_order = ('id', 'domain__value', 'user__username', 'creation_date', 'last_update')


@admin.register(CampaignDomainAllowList)
class CampaignDomainAllowListAdmin(ImportExportModelAdmin):
    resource_class = CampaignDomainAllowListResource
    list_display = ('domain', 'user', 'creation_date', 'last_update')
    list_filter = ('domain', 'user', 'creation_date')
    search_fields = ('domain__value', 'user__username')
    ordering = ('creation_date',)
