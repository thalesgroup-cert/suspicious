"""Runtime-config accessor: Redis cache -> DB -> settings.json -> default.

``get_config`` resolves a single dotted key. ``get_section`` returns a whole
section dict with non-secret fields from the runtime tier (DB/json) and
secret fields overlaid from Vault, preserving the dict shape that call sites
already expect.
"""
from __future__ import annotations

import logging
from typing import Any

from django.core.cache import cache
from django.db import DatabaseError

from suspicious._config_common import settings_get
from suspicious.secrets import get_secret

logger = logging.getLogger("settings.config")

_CACHE_PREFIX = "runtimeconfig:"
_CACHE_TTL = 60  # seconds; short so admin edits propagate without restart
_SENTINEL_MISS = "__miss__"
_CACHE_NOT_SET = object()

# Leaf field names that are secrets (overlaid from Vault), keyed by section.
SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "app": ("secret_key",),
    "database": ("password",),
    "integrations.cortex": ("api_key", "webhook_secret"),
    "integrations.thehive": ("api_key",),
    "integrations.misp.instances.primary": ("api_key",),
    "integrations.misp.instances.secondary": ("api_key",),
    "integrations.watcher": ("api_key",),
    "storage.s3": ("secret_key",),
    "authentication.ldap": ("bind_password",),
    "authentication.oidc": ("client_secret",),
    "email.smtp": ("password",),
}


def invalidate_cache(key: str) -> None:
    cache.delete(_CACHE_PREFIX + key)


def get_config(key: str, default: Any = None) -> Any:
    """Resolve one dotted runtime key. DB unreachable -> default + warning."""
    cache_key = _CACHE_PREFIX + key
    cached = cache.get(cache_key, _CACHE_NOT_SET)
    if cached is not _CACHE_NOT_SET:
        return None if cached == _SENTINEL_MISS else cached

    from settings.models import RuntimeConfig

    try:
        row = RuntimeConfig.objects.filter(key=key).first()
    except DatabaseError:
        logger.warning("DB unreachable reading runtime config '%s'; using default", key)
        return default

    if row is not None:
        cache.set(cache_key, row.value, _CACHE_TTL)
        return row.value

    value = settings_get(key, _SENTINEL_MISS)
    if value is _SENTINEL_MISS or value is None:
        cache.set(cache_key, _SENTINEL_MISS, _CACHE_TTL)
        return default
    cache.set(cache_key, value, _CACHE_TTL)
    return value


def get_section(name: str) -> dict:
    """Return section ``name`` as a dict: non-secret fields from DB/json,
    secret fields overlaid from Vault. Shape matches settings.json."""
    base = get_config(name, default=None)
    if not isinstance(base, dict):
        base = settings_get(name, {}) or {}
    section = dict(base)  # shallow copy; we only overlay top-level secret leaves
    for field in SECRET_FIELDS.get(name, ()):  # overlay secrets
        section[field] = get_secret(f"{name}.{field}")
    return section
