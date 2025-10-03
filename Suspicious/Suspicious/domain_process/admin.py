from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from domain_process.models import Domain, DomainInIocs


# Resources
class DomainResource(resources.ModelResource):
    class Meta:
        model = Domain
        fields = (
            'id', 'value', 'category', 'times_sent', 'creation_date', 'last_update'
        )
        export_order = fields


class DomainInIocsResource(resources.ModelResource):
    class Meta:
        model = DomainInIocs
        fields = (
            'id', 'domain__value', 'url__address', 'mail_address__address', 'creation_date', 'last_update'
        )
        export_order = fields


# Admin classes
@admin.register(Domain)
class DomainAdmin(ImportExportModelAdmin):
    resource_class = DomainResource
    list_display = ('id', 'value', 'category', 'times_sent', 'creation_date', 'last_update')
    list_filter = ('category', 'creation_date', 'last_update')
    search_fields = ('value', 'category')
    ordering = ('-creation_date',)


@admin.register(DomainInIocs)
class DomainInIocsAdmin(ImportExportModelAdmin):
    resource_class = DomainInIocsResource
    list_display = ('id', 'domain', 'get_linked_url', 'get_linked_mail', 'creation_date', 'last_update')
    list_filter = ('creation_date', 'last_update')
    search_fields = ('domain__value', 'url__address', 'mail_address__address')
    ordering = ('-creation_date',)

    # Custom display methods for linked fields
    def get_linked_url(self, obj):
        return obj.url.address if obj.url else "-"
    get_linked_url.short_description = "Linked URL"

    def get_linked_mail(self, obj):
        return obj.mail_address.address if obj.mail_address else "-"
    get_linked_mail.short_description = "Linked Mail Address"
