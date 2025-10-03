from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from file_process.models import File, HashFromFile


# Resource classes
class FileResource(resources.ModelResource):
    class Meta:
        model = File
        fields = (
            'id', 'linked_hash', 'file_path', 'file_score', 'file_confidence', 
            'file_level', 'tmp_path', 'filetype', 'size', 'other_names', 
            'times_sent', 'creation_date', 'last_update'
        )
        export_order = fields


class HashFromFileResource(resources.ModelResource):
    class Meta:
        model = HashFromFile
        fields = ('id', 'hash', 'file', 'creation_date', 'last_update')
        export_order = fields


# Admin classes
@admin.register(File)
class FileAdmin(ImportExportModelAdmin):
    resource_class = FileResource
    list_display = ('id', 'file_path', 'file_score', 'file_confidence', 'file_level', 'filetype', 'size', 'creation_date', 'last_update')
    list_filter = ('file_level', 'filetype', 'creation_date', 'last_update')
    search_fields = ('file_path', 'filetype', 'other_names')
    ordering = ('-creation_date',)


@admin.register(HashFromFile)
class HashFromFileAdmin(ImportExportModelAdmin):
    resource_class = HashFromFileResource
    list_display = ('id', 'hash', 'file', 'creation_date', 'last_update')
    search_fields = ('hash__value', 'file__file_path')
    ordering = ('-creation_date',)
