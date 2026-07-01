import copy

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _
from knox.models import AuthToken

DEFAULT_SEMANTIC_COLORS = {
    "result": {
        "safe":         {"main": "#22C55E"},
        "suspicious":   {"main": "#F59E0B"},
        "dangerous":    {"main": "#EF4444"},
        "inconclusive": {"main": "#94A3B8"},
    },
    "status": {
        "done":        {"main": "#22C55E"},
        "in_progress": {"main": "#3B82F6"},
        "new":         {"main": "#94A3B8"},
        "failure":     {"main": "#EF4444"},
        "challenged":  {"main": "#A855F7"},
        "unknown":     {"main": "#64748B"},
    },
}


def merge_semantic_colors(stored: dict | None) -> dict:
    """Overlay user-stored result/status colors on top of the defaults."""
    base = copy.deepcopy(DEFAULT_SEMANTIC_COLORS)
    stored = stored or {}
    for group in ("result", "status"):
        if group in stored and isinstance(stored[group], dict):
            base[group].update(stored[group])
    return base


class SemanticColorsMixin:
    """Adds get_semantic_colors() to profile models holding a
    ``semantic_colors`` JSONField."""

    def get_semantic_colors(self) -> dict:
        return merge_semantic_colors(self.semantic_colors)


class APIKey(models.Model):
    """
    Manages creation, modification, and deletion of user API keys.
    """
    auth_token = models.OneToOneField(AuthToken, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"API Key for {self.auth_token.user.username}"

    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        app_label = 'profiles'

class Theme(models.TextChoices):
    """
    Enumeration of available UI themes.
    """
    MIDNIGHT = "midnight", _("Midnight")
    GRAPHITE = "graphite", _("Graphite")
    SLATE = "slate", _("Slate")
    LIGHT = "light", _("Light")
    PAPER = "paper", _("Paper")
    HIGH_CONTRAST = "high_contrast", _("High contrast")
    SUNRISE = "sunrise", _("Sunrise")
    VALENTINE = "valentine", _("Valentine")
    CYBER = "cyber", _("Cyber")
    THE_ONE = "the_one", _("The One")
    METAL = "metal", _("Metal")
    FUTURE = "future", _("Future")
    SUMMER = "summer", _("Summer")
    WINTER = "winter", _("Winter")
    SPRING = "spring", _("Spring")
    AUTUMN = "autumn", _("Autumn")
    RENEE = "renee", _("Renée")

class UserProfile(SemanticColorsMixin, models.Model):
    def default_semantic_colors():
        return DEFAULT_SEMANTIC_COLORS.copy()
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    function = models.CharField(max_length=200)
    gbu = models.CharField(max_length=200)
    country = models.CharField(max_length=200)
    region = models.CharField(max_length=200)
    wants_acknowledgement = models.BooleanField(default=True)
    wants_results = models.BooleanField(default=True)
    theme = models.CharField(max_length=50, choices=Theme.choices, default=Theme.LIGHT)
    auto_seasonal = models.BooleanField(default=False)
    semantic_colors = models.JSONField(
        default= default_semantic_colors,
        blank=True,
        verbose_name=_("Semantic colors"),
        help_text=_(
            "User-defined colors for result/status indicators. "
            "Structure: {result: {safe, suspicious, dangerous, inconclusive}, "
            "status: {done, in_progress, new, failure, challenged, unknown}}. "
            "Each entry is {main: '#rrggbb'}."
        ),
    )
    avatar = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Avatar"),
        help_text=_(
            "DiceBear avatar config. Structure: {style: '<dicebear-style>', "
            "seed: '<string>'}. Empty means fall back to initials."
        ),
    )
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.user.username

class CISOProfile(SemanticColorsMixin, models.Model):
    def default_semantic_colors():
        return DEFAULT_SEMANTIC_COLORS.copy()
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    function = models.CharField(max_length=200)
    gbu = models.CharField(max_length=200)
    country = models.CharField(max_length=200)
    region = models.CharField(max_length=200)
    scope = models.CharField(max_length=200, default='Not defined')
    wants_acknowledgement = models.BooleanField(default=True)
    wants_results = models.BooleanField(default=True)
    theme = models.CharField(max_length=50, choices=Theme.choices, default=Theme.LIGHT)
    auto_seasonal = models.BooleanField(default=False)
    semantic_colors = models.JSONField(
        default=default_semantic_colors,
        blank=True,
        verbose_name=_("Semantic colors"),
        help_text=_(
            "User-defined colors for result/status indicators. "
            "Structure: {result: {safe, suspicious, dangerous, inconclusive}, "
            "status: {done, in_progress, new, failure, challenged, unknown}}. "
            "Each entry is {main: '#rrggbb'}."
        ),
    )
    avatar = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Avatar"),
        help_text=_(
            "DiceBear avatar config. Structure: {style: '<dicebear-style>', "
            "seed: '<string>'}. Empty means fall back to initials."
        ),
    )
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.user.username