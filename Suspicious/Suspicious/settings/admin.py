from django.contrib import admin
from django.contrib.auth import get_user_model

from import_export import fields, resources
from import_export.admin import ImportExportModelAdmin
from import_export.widgets import ForeignKeyWidget

from .models import (
    Mailbox,
    EmailFeederState,
    AllowListDomain,
    WatcherLegitDomain,
    DenyListDomain,
    WatcherMonitoredDomain,
    CampaignDomainAllowList,
    AllowListFile,
    DenyListFile,
    AllowListFiletype,
    RuntimeConfig,
)
from domain_process.models import Domain
from hash_process.models import Hash

User = get_user_model()


# =========================
# Helpers
# =========================
def normalize_value(value):
    if value is None:
        return None
    return str(value).strip().lower()


# =========================
# Mailbox
# =========================
class MailboxResource(resources.ModelResource):
    class Meta:
        model = Mailbox
        fields = (
            "id",
            "name",
            "username",
            "server",
            "port",
            "creation_date",
            "last_update",
        )
        export_order = (
            "id",
            "name",
            "username",
            "server",
            "port",
            "creation_date",
            "last_update",
        )
        import_id_fields = ("id",)


@admin.register(Mailbox)
class MailboxAdmin(ImportExportModelAdmin):
    resource_class = MailboxResource
    list_display = ("name", "username", "server", "port", "creation_date", "last_update")
    list_filter = ("server", "port", "creation_date")
    search_fields = ("name", "username", "server")
    ordering = ("creation_date",)


# =========================
# EmailFeederState
# =========================
class EmailFeederStateResource(resources.ModelResource):
    class Meta:
        model = EmailFeederState
        fields = ("id", "is_running", "updated_at")
        export_order = ("id", "is_running", "updated_at")
        import_id_fields = ("id",)


@admin.register(EmailFeederState)
class EmailFeederStateAdmin(ImportExportModelAdmin):
    resource_class = EmailFeederStateResource
    list_display = ("id", "is_running", "updated_at")
    list_filter = ("is_running", "updated_at")
    search_fields = ()
    ordering = ("-updated_at",)


# =========================
# AllowListDomain
# =========================
class AllowListDomainResource(resources.ModelResource):
    domain = fields.Field(
        column_name="domain__value",
        attribute="domain",
        widget=ForeignKeyWidget(Domain, "value"),
    )
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    def before_import_row(self, row, **kwargs):
        domain_value = normalize_value(row.get("domain__value"))
        if domain_value:
            row["domain__value"] = domain_value
            Domain.objects.get_or_create(value=domain_value)

    class Meta:
        model = AllowListDomain
        fields = ("id", "domain", "user", "creation_date", "last_update")
        export_order = ("id", "domain", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(AllowListDomain)
class AllowListDomainAdmin(ImportExportModelAdmin):
    resource_class = AllowListDomainResource
    list_display = ("domain", "user", "creation_date", "last_update")
    list_filter = ("creation_date",)
    list_select_related = ("domain", "user")
    search_fields = ("domain__value", "user__username")
    ordering = ("-creation_date",)


# =========================
# WatcherLegitDomain
# =========================
class WatcherLegitDomainResource(resources.ModelResource):
    domain = fields.Field(
        column_name="domain__value",
        attribute="domain",
        widget=ForeignKeyWidget(Domain, "value"),
    )

    def before_import_row(self, row, **kwargs):
        domain_value = normalize_value(row.get("domain__value"))
        if domain_value:
            row["domain__value"] = domain_value
            Domain.objects.get_or_create(value=domain_value)

    class Meta:
        model = WatcherLegitDomain
        fields = (
            "id",
            "watcher_id",
            "domain",
            "status",
            "remote_last_update",
            "raw_payload",
            "creation_date",
            "last_update",
        )
        export_order = (
            "id",
            "watcher_id",
            "domain",
            "status",
            "remote_last_update",
            "raw_payload",
            "creation_date",
            "last_update",
        )
        import_id_fields = ("id",)


@admin.register(WatcherLegitDomain)
class WatcherLegitDomainAdmin(ImportExportModelAdmin):
    resource_class = WatcherLegitDomainResource
    list_display = (
        "domain",
        "watcher_id",
        "status",
        "remote_last_update",
        "creation_date",
        "last_update",
    )
    list_filter = ("status", "creation_date", "last_update", "remote_last_update")
    list_select_related = ("domain",)
    search_fields = ("domain__value", "status", "watcher_id")
    ordering = ("-creation_date",)


# =========================
# DenyListDomain
# =========================
class DenyListDomainResource(resources.ModelResource):
    domain = fields.Field(
        column_name="domain__value",
        attribute="domain",
        widget=ForeignKeyWidget(Domain, "value"),
    )
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    def before_import_row(self, row, **kwargs):
        domain_value = normalize_value(row.get("domain__value"))
        if domain_value:
            row["domain__value"] = domain_value
            Domain.objects.get_or_create(value=domain_value)

    class Meta:
        model = DenyListDomain
        fields = ("id", "domain", "user", "creation_date", "last_update")
        export_order = ("id", "domain", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(DenyListDomain)
class DenyListDomainAdmin(ImportExportModelAdmin):
    resource_class = DenyListDomainResource
    list_display = ("domain", "user", "creation_date", "last_update")
    list_filter = ("creation_date",)
    list_select_related = ("domain", "user")
    search_fields = ("domain__value", "user__username")
    ordering = ("-creation_date",)


# =========================
# WatcherMonitoredDomain
# =========================
class WatcherMonitoredDomainResource(resources.ModelResource):
    domain = fields.Field(
        column_name="domain__value",
        attribute="domain",
        widget=ForeignKeyWidget(Domain, "value"),
    )

    def before_import_row(self, row, **kwargs):
        domain_value = normalize_value(row.get("domain__value"))
        if domain_value:
            row["domain__value"] = domain_value
            Domain.objects.get_or_create(value=domain_value)

    class Meta:
        model = WatcherMonitoredDomain
        fields = (
            "id",
            "watcher_id",
            "domain",
            "status",
            "remote_last_update",
            "raw_payload",
            "creation_date",
            "last_update",
        )
        export_order = (
            "id",
            "watcher_id",
            "domain",
            "status",
            "remote_last_update",
            "raw_payload",
            "creation_date",
            "last_update",
        )
        import_id_fields = ("id",)


@admin.register(WatcherMonitoredDomain)
class WatcherMonitoredDomainAdmin(ImportExportModelAdmin):
    resource_class = WatcherMonitoredDomainResource
    list_display = (
        "domain",
        "watcher_id",
        "status",
        "remote_last_update",
        "creation_date",
        "last_update",
    )
    list_filter = ("status", "creation_date", "last_update", "remote_last_update")
    list_select_related = ("domain",)
    search_fields = ("domain__value", "status", "watcher_id")
    ordering = ("-creation_date",)


# =========================
# CampaignDomainAllowList
# =========================
class CampaignDomainAllowListResource(resources.ModelResource):
    domain = fields.Field(
        column_name="domain__value",
        attribute="domain",
        widget=ForeignKeyWidget(Domain, "value"),
    )
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    def before_import_row(self, row, **kwargs):
        domain_value = normalize_value(row.get("domain__value"))
        if domain_value:
            row["domain__value"] = domain_value
            Domain.objects.get_or_create(value=domain_value)

    class Meta:
        model = CampaignDomainAllowList
        fields = ("id", "domain", "user", "creation_date", "last_update")
        export_order = ("id", "domain", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(CampaignDomainAllowList)
class CampaignDomainAllowListAdmin(ImportExportModelAdmin):
    resource_class = CampaignDomainAllowListResource
    list_display = ("domain", "user", "creation_date", "last_update")
    list_filter = ("creation_date",)
    list_select_related = ("domain", "user")
    search_fields = ("domain__value", "user__username")
    ordering = ("-creation_date",)


# =========================
# AllowListFile
# =========================
class AllowListFileResource(resources.ModelResource):
    linked_file_hash = fields.Field(
        column_name="linked_file_hash__value",
        attribute="linked_file_hash",
        widget=ForeignKeyWidget(Hash, "value"),
    )
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    def before_import_row(self, row, **kwargs):
        hash_value = normalize_value(row.get("linked_file_hash__value"))
        if hash_value:
            row["linked_file_hash__value"] = hash_value
            Hash.objects.get_or_create(value=hash_value)

    class Meta:
        model = AllowListFile
        fields = ("id", "linked_file_hash", "user", "creation_date", "last_update")
        export_order = ("id", "linked_file_hash", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(AllowListFile)
class AllowListFileAdmin(ImportExportModelAdmin):
    resource_class = AllowListFileResource
    list_display = ("linked_file_hash", "user", "creation_date", "last_update")
    list_filter = ("creation_date",)
    list_select_related = ("linked_file_hash", "user")
    search_fields = ("linked_file_hash__value", "user__username")
    ordering = ("-creation_date",)


# =========================
# DenyListFile
# =========================
class DenyListFileResource(resources.ModelResource):
    linked_file_hash = fields.Field(
        column_name="linked_file_hash__value",
        attribute="linked_file_hash",
        widget=ForeignKeyWidget(Hash, "value"),
    )
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    def before_import_row(self, row, **kwargs):
        hash_value = normalize_value(row.get("linked_file_hash__value"))
        if hash_value:
            row["linked_file_hash__value"] = hash_value
            Hash.objects.get_or_create(value=hash_value)

    class Meta:
        model = DenyListFile
        fields = ("id", "linked_file_hash", "user", "creation_date", "last_update")
        export_order = ("id", "linked_file_hash", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(DenyListFile)
class DenyListFileAdmin(ImportExportModelAdmin):
    resource_class = DenyListFileResource
    list_display = ("linked_file_hash", "user", "creation_date", "last_update")
    list_filter = ("creation_date",)
    list_select_related = ("linked_file_hash", "user")
    search_fields = ("linked_file_hash__value", "user__username")
    ordering = ("-creation_date",)


# =========================
# AllowListFiletype
# =========================
class AllowListFiletypeResource(resources.ModelResource):
    user = fields.Field(
        column_name="user_id",
        attribute="user",
        widget=ForeignKeyWidget(User, "id"),
    )

    class Meta:
        model = AllowListFiletype
        fields = ("id", "filetype", "user", "creation_date", "last_update")
        export_order = ("id", "filetype", "user", "creation_date", "last_update")
        import_id_fields = ("id",)


@admin.register(AllowListFiletype)
class AllowListFiletypeAdmin(ImportExportModelAdmin):
    resource_class = AllowListFiletypeResource
    list_display = ("filetype", "user", "creation_date", "last_update")
    list_filter = ("filetype", "creation_date")
    list_select_related = ("user",)
    search_fields = ("filetype", "user__username")
    ordering = ("-creation_date",)


# =========================
# RuntimeConfig
# =========================
@admin.register(RuntimeConfig)
class RuntimeConfigAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "updated_at")
    search_fields = ("key",)
    ordering = ("key",)
