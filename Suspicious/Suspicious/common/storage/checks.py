import os

from django.core.checks import Error, register

from suspicious._config_common import settings_get

from .registry import known_providers


@register()
def check_storage_provider(app_configs, **kwargs):
    candidates = {
        "env STORAGE_PROVIDER": os.environ.get("STORAGE_PROVIDER"),
        "settings.json storage.provider": settings_get("storage.provider", None),
    }
    errors = []
    for source, raw in candidates.items():
        name = str(raw or "").strip().lower()
        if name and name not in known_providers():
            errors.append(Error(
                f"Unknown storage provider {name!r} (from {source}).",
                hint=f"Registered providers: {', '.join(known_providers())}.",
                id="storage.E001",
            ))
    return errors
