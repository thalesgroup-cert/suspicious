from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from ip_process.models import IP


# Resource class for import/export
class IPResource(resources.ModelResource):
    class Meta:
        model = IP
        fields = (
            'id', 'address', 'ioc_score', 'ioc_confidence', 'ioc_level',
            'times_sent', 'creation_date', 'last_update'
        )
        export_order = fields


# Admin class
@admin.register(IP)
class IPAdmin(ImportExportModelAdmin):
    resource_class = IPResource
    list_display = ('id', 'address', 'ioc_score', 'ioc_confidence', 'ioc_level', 'times_sent', 'creation_date', 'last_update')
    list_filter = ('ioc_level', 'creation_date', 'last_update')
    search_fields = ('address',)
    ordering = ('-creation_date',)
