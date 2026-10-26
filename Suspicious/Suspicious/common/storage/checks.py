import os

from django.core.checks import Error, Warning, register

from suspicious._config_common import settings_get

from .registry import known_providers


def unknown_provider_candidates():
    """(source, name) for every configured provider name that is not registered.
    Reads env and settings.json only, so it is safe before the DB is up."""
    candidates = {
        "env STORAGE_PROVIDER": os.environ.get("STORAGE_PROVIDER"),
        "settings.json storage.provider": settings_get("storage.provider", None),
    }
    names = {source: str(raw or "").strip().lower() for source, raw in candidates.items()}
    return [(source, name) for source, name in names.items() if name and name not in known_providers()]


@register()
def check_storage_provider(app_configs, **kwargs):
    return [
        Error(
            f"Unknown storage provider {name!r} (from {source}).",
            hint=f"Registered providers: {', '.join(known_providers())}.",
            id="storage.E001",
        )
        for source, name in unknown_provider_candidates()
    ]


_DEFAULT_BUCKETS = {
    "media_bucket": "suspicious-media",
    "avatars_bucket": "suspicious-avatars",
}
_FIXED_DEFAULT_BUCKETS = ("mail-previews", "analyzer-screenshots")


@register()
def check_gcs_default_buckets(app_configs, **kwargs):
    provider = str(os.environ.get("STORAGE_PROVIDER") or settings_get("storage.provider", None) or "").strip().lower()
    if provider != "gcs":
        return []
    used = [name for key, name in _DEFAULT_BUCKETS.items()
            if (settings_get(f"storage.s3.{key}", None) or name) == name]
    used += _FIXED_DEFAULT_BUCKETS
    return [Warning(
        f"storage.provider is gcs but default bucket names are still in use: {', '.join(used)}.",
        hint="GCS bucket names are global and can be claimed by anyone; set explicit, unique names.",
        id="storage.W001",
    )]
