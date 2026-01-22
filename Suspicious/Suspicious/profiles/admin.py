from django.contrib import admin, messages
from django.contrib.auth.models import User
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.utils.safestring import mark_safe
from django import forms

from import_export import resources
from import_export.admin import ImportExportModelAdmin

from knox.models import AuthToken

from .models import UserProfile, CISOProfile, APIKey
from api.views import generate_api_key


# =============================================================================
# API KEY ADMIN (Knox wrapper)
# =============================================================================

class APIKeyForm(forms.ModelForm):
    """
    Admin form to create Knox API keys with controlled expiration and ownership.
    """
    EXPIRATION_CHOICES = (
        (1, "1 day"),
        (7, "7 days"),
        (30, "30 days"),
        (60, "60 days"),
        (90, "90 days"),
        (365, "1 year"),
        (730, "2 years"),
    )

    expiration = forms.ChoiceField(choices=EXPIRATION_CHOICES, required=True)
    user = forms.ModelChoiceField(queryset=User.objects.all(), required=True)

    class Meta:
        model = APIKey
        fields = ("user", "expiration")

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)

        # Default expiration
        if not self.instance.pk:
            self.fields["expiration"].initial = 30

        # Editing existing key → lock fields
        if self.instance.pk:
            self.fields["user"].widget = forms.HiddenInput()
            self.fields["expiration"].widget = forms.HiddenInput()

        # Non-superusers can only create keys for themselves
        if self.request and not self.request.user.is_superuser:
            self.fields["user"].queryset = User.objects.filter(id=self.request.user.id)
            self.fields["user"].initial = self.request.user

    def save(self, commit=True):
        instance = super().save(commit=False)
        expiration_days = int(self.cleaned_data["expiration"])
        instance.get_expiry = timezone.now() + timezone.timedelta(days=expiration_days)

        if commit:
            instance.save()
        return instance


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """
    Admin UI for managing Knox API keys safely.
    Raw tokens are never stored and only displayed once.
    """

    list_display = ("display_user", "display_digest", "display_created", "display_expiry")
    readonly_fields = ("key_details",)
    form = APIKeyForm

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def display_user(self, obj):
        return obj.auth_token.user if obj.auth_token else None

    def display_digest(self, obj):
        return obj.auth_token.digest if obj.auth_token else None

    def display_created(self, obj):
        return obj.auth_token.created if obj.auth_token else None

    def display_expiry(self, obj):
        return obj.auth_token.expiry if obj.auth_token else None

    display_user.short_description = "User"
    display_digest.short_description = "Digest"
    display_created.short_description = "Created"
    display_expiry.short_description = "Expiry"

    # ------------------------------------------------------------------
    # Permissions & queryset scoping
    # ------------------------------------------------------------------

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            qs = qs.filter(auth_token__user=request.user)
        return qs

    def has_view_permission(self, request, obj=None):
        if obj and not request.user.is_superuser:
            return obj.auth_token.user == request.user
        return True

    # ------------------------------------------------------------------
    # Form injection
    # ------------------------------------------------------------------

    def get_form(self, request, obj=None, **kwargs):
        kwargs["form"] = self.form
        form = super().get_form(request, obj, **kwargs)

        class RequestBoundForm(form):
            def __init__(self, *args, **kw):
                kw["request"] = request
                super().__init__(*args, **kw)

        return RequestBoundForm

    # ------------------------------------------------------------------
    # Save logic (token generation)
    # ------------------------------------------------------------------

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            user = form.cleaned_data["user"]
            expiration = int(form.cleaned_data["expiration"])

            raw_key, auth_token = generate_api_key(user, expiration)
            obj.auth_token = auth_token
            obj.save()

            self._notify_key_created(request, raw_key)

        else:
            super().save_model(request, obj, form, change)

    def _notify_key_created(self, request, raw_key: str):
        """
        Display the token once with copy button.
        """
        html = f"""
        <button onclick="navigator.clipboard.writeText('{raw_key}')" 
                style="border:none;background:none;cursor:pointer;">
            📋 Copy API Key
        </button>
        <small style="display:block;margin-top:6px;">
            This key will not be shown again.
        </small>
        """

        messages.success(
            request,
            mark_safe(f"API Key created: <code>{raw_key}</code><br/>{html}"),
        )

    # ------------------------------------------------------------------
    # Readonly handling
    # ------------------------------------------------------------------

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return ["display_user", "display_digest", "display_created", "display_expiry", "key_details"]
        return []

    def get_exclude(self, request, obj=None):
        return ["key"]

    def key_details(self, obj):
        return mark_safe(
            "Algorithm: SHA3-512<br>"
            "Raw API keys are not stored. Regenerate if lost."
        )

    key_details.short_description = "Key details"


# Auto-cleanup Knox token when APIKey is deleted
@receiver(post_delete, sender=APIKey)
def delete_authtoken_on_apikey_delete(sender, instance, **kwargs):
    if instance.auth_token:
        instance.auth_token.delete()


# =============================================================================
# KNOX TOKEN ADMIN (read-only)
# =============================================================================

class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "digest", "created", "expiry")
    readonly_fields = ("user", "digest", "created", "expiry")

    def has_add_permission(self, request):
        return False


# =============================================================================
# USER PROFILE ADMIN
# =============================================================================

class UserProfileResource(resources.ModelResource):
    class Meta:
        model = UserProfile
        fields = (
            "id", "user__username", "function", "gbu", "country", "region",
            "wants_acknowledgement", "wants_results",
            "creation_date", "last_update",
        )
        export_order = fields


@admin.register(UserProfile)
class UserProfileAdmin(ImportExportModelAdmin):
    resource_class = UserProfileResource

    list_display = (
        "user", "function", "gbu", "country", "region",
        "wants_acknowledgement", "wants_results", "creation_date",
    )
    list_filter = ("country", "region", "gbu", "wants_acknowledgement", "wants_results", "creation_date")
    search_fields = ("user__username", "function", "gbu", "country", "region")
    ordering = ("creation_date",)
    actions = ("enable_acknowledgement", "disable_acknowledgement")

    # Actions

    def enable_acknowledgement(self, request, queryset):
        updated = queryset.update(wants_acknowledgement=True)
        self.message_user(request, f"{updated} profile(s) updated.")

    def disable_acknowledgement(self, request, queryset):
        updated = queryset.update(wants_acknowledgement=False)
        self.message_user(request, f"{updated} profile(s) updated.")

    enable_acknowledgement.short_description = "Enable acknowledgements"
    disable_acknowledgement.short_description = "Disable acknowledgements"


# =============================================================================
# CISO PROFILE ADMIN
# =============================================================================

class CISOProfileResource(resources.ModelResource):
    class Meta:
        model = CISOProfile
        fields = (
            "id", "user__username", "function", "gbu", "country",
            "region", "scope", "creation_date", "last_update",
        )
        export_order = fields


@admin.register(CISOProfile)
class CISOProfileAdmin(ImportExportModelAdmin):
    resource_class = CISOProfileResource

    list_display = ("user", "function", "gbu", "country", "region", "scope", "creation_date")
    list_filter = ("country", "region", "gbu", "scope", "creation_date")
    search_fields = ("user__username", "function", "gbu", "country", "region", "scope")
    ordering = ("creation_date",)
    readonly_fields = ("scope",)
