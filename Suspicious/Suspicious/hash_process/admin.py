from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from hash_process.models import Hash


# Resource class
class HashResource(resources.ModelResource):
    class Meta:
        model = Hash
        fields = (
            'id', 'value', 'ioc_score', 'ioc_confidence', 'ioc_level',
            'hashtype', 'times_sent', 'creation_date', 'last_update'
        )
        export_order = fields


# Admin class
@admin.register(Hash)
class HashAdmin(ImportExportModelAdmin):
    resource_class = HashResource
    list_display = ('id', 'value', 'ioc_score', 'ioc_confidence', 'ioc_level', 'hashtype', 'times_sent', 'creation_date', 'last_update')
    list_filter = ('ioc_level', 'hashtype', 'creation_date', 'last_update')
    search_fields = ('value', 'hashtype')
    ordering = ('-creation_date',)
