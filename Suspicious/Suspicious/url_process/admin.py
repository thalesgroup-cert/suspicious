from django.contrib import admin
from django.db import models
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from .models import URL


class URLResource(resources.ModelResource):
    class Meta:
        model = URL
        fields = (
            'id', 'address', 'ioc_score', 'ioc_confidence', 'ioc_level',
            'times_sent', 'creation_date', 'last_update',
        )
        export_order = (
            'id', 'address', 'ioc_score', 'ioc_confidence', 'ioc_level',
            'times_sent', 'creation_date', 'last_update',
        )


@admin.register(URL)
class URLAdmin(ImportExportModelAdmin):
    resource_class = URLResource
    list_display = ('address', 'ioc_score', 'ioc_confidence', 'ioc_level', 'times_sent', 'creation_date')
    list_filter = ('ioc_level', 'creation_date')
    search_fields = ('address', 'ioc_score', 'ioc_confidence', 'ioc_level')
    ordering = ('creation_date',)

    def increment_times_sent(self, request, queryset):
        rows_updated = queryset.update(times_sent=models.F('times_sent') + 1)
        self.message_user(request, f"{rows_updated} URL(s) updated with incremented 'times_sent'.")
    increment_times_sent.short_description = "Increment 'times_sent' for selected URLs"

    actions = [increment_times_sent]
