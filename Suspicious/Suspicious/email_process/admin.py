from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from email_process.models import MailAddress


# Resource class
class MailAddressResource(resources.ModelResource):
    class Meta:
        model = MailAddress
        fields = ('id', 'address', 'is_internal', 'creation_date', 'last_update')
        export_order = fields


# Admin class
@admin.register(MailAddress)
class MailAddressAdmin(ImportExportModelAdmin):
    resource_class = MailAddressResource
    list_display = ('id', 'address', 'is_internal', 'creation_date', 'last_update')
    list_filter = ('is_internal', 'creation_date', 'last_update')
    search_fields = ('address',)
    ordering = ('-creation_date',)
