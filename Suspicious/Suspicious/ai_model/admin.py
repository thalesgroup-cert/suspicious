from django.contrib import admin

from .models import LabelRecord, LabelSyncState


class ReadOnlyAdmin(admin.ModelAdmin):
    """The ledger is append-only; edits go through ai_model.ledger."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LabelRecord)
class LabelRecordAdmin(ReadOnlyAdmin):
    list_display = ("id", "source", "label", "label_class", "trust", "status", "observed_at")
    list_filter = ("source", "label_class", "trust", "status")
    search_fields = ("message_id_hash", "source_ref")
    exclude = ("embedding", "campaign_embedding")


@admin.register(LabelSyncState)
class LabelSyncStateAdmin(ReadOnlyAdmin):
    list_display = ("folder", "uidvalidity", "last_uid", "last_run_at", "skipped")
