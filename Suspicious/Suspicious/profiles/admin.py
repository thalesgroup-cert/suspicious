from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import UserProfile, CISOProfile
from import_export import resources
from import_export.admin import ImportExportModelAdmin


# Resource for UserProfile
class UserProfileResource(resources.ModelResource):
    class Meta:
        model = UserProfile
        fields = (
            'id', 'user__username', 'function', 'gbu', 'country',
            'region', 'wants_acknowledgement', 'wants_results',
            'creation_date', 'last_update',
        )
        export_order = (
            'id', 'user__username', 'function', 'gbu', 'country',
            'region', 'wants_acknowledgement', 'wants_results',
            'creation_date', 'last_update',
        )


# Admin for UserProfile
@admin.register(UserProfile)
class UserProfileAdmin(ImportExportModelAdmin):
    resource_class = UserProfileResource
    list_display = ('user', 'function', 'gbu', 'country', 'region', 'wants_acknowledgement', 'wants_results', 'creation_date')
    list_filter = ('country', 'region', 'gbu', 'wants_acknowledgement', 'wants_results', 'creation_date')
    search_fields = ('user__username', 'function', 'gbu', 'country', 'region')
    ordering = ('creation_date',)
    actions = ['set_acknowledgement', 'unset_acknowledgement']

    # Custom actions
    def set_acknowledgement(self, request, queryset):
        rows_updated = queryset.update(wants_acknowledgement=True)
        self.message_user(request, f"{rows_updated} profile(s) updated to receive acknowledgements.")
    set_acknowledgement.short_description = "Enable acknowledgement for selected profiles"

    def unset_acknowledgement(self, request, queryset):
        rows_updated = queryset.update(wants_acknowledgement=False)
        self.message_user(request, f"{rows_updated} profile(s) updated to not receive acknowledgements.")
    unset_acknowledgement.short_description = "Disable acknowledgement for selected profiles"


# Resource for CISOProfile
class CISOProfileResource(resources.ModelResource):
    class Meta:
        model = CISOProfile
        fields = (
            'id', 'user__username', 'function', 'gbu', 'country',
            'region', 'scope', 'creation_date', 'last_update',
        )
        export_order = (
            'id', 'user__username', 'function', 'gbu', 'country',
            'region', 'scope', 'creation_date', 'last_update',
        )


# Admin for CISOProfile
@admin.register(CISOProfile)
class CISOProfileAdmin(ImportExportModelAdmin):
    resource_class = CISOProfileResource
    list_display = ('user', 'function', 'gbu', 'country', 'region', 'scope', 'creation_date')
    list_filter = ('country', 'region', 'gbu', 'scope', 'creation_date')
    search_fields = ('user__username', 'function', 'gbu', 'country', 'region', 'scope')
    ordering = ('creation_date',)
    readonly_fields = ('scope',)  # Example: Make scope read-only

