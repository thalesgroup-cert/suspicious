import os

from django.core.checks import Error, register

from suspicious._config_common import settings_get

from .registry import DEFAULT_PROVIDER, known_providers


@register()
def check_storage_provider(app_configs, **kwargs):
    name = str(
        os.environ.get("STORAGE_PROVIDER") or settings_get("storage.provider", None) or DEFAULT_PROVIDER
    ).strip().lower()
    if name in known_providers():
        return []
    return [Error(
        f"Unknown storage provider {name!r}.",
        hint=f"Registered providers: {', '.join(known_providers())}.",
        id="storage.E001",
    )]
