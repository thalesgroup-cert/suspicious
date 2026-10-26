import os

from django.core.checks import Error, register

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
