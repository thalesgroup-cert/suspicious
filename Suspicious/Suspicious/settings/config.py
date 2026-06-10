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

# Which config sections belong to which scope. A scope's effective sections
# are its own plus everything in "shared". Drives seed_config and the config API.
SCOPE_SECTIONS: dict[str, list[str]] = {
    "shared": [
        "storage.s3", "email.smtp", "email.content", "email.links",
        "email.socials", "email.logos", "branding", "branding.assets",
    ],
    "backend": [
        "integrations.cortex", "integrations.thehive", "integrations.misp",
        "integrations.misp.instances.primary",
        "integrations.misp.instances.secondary", "integrations.watcher",
        "integrations.chromadb", "authentication.ldap",
    ],
    "feeder": [],  # phase 1: feeder consumes only "shared"
}


def _scope_for_section(section: str) -> str:
    for scope, sections in SCOPE_SECTIONS.items():
        if section in sections:
            return scope
    return "backend"


def invalidate_cache(key: str) -> None:
    # Best-effort: a cache backend outage must not break a RuntimeConfig
    # save / admin edit / seed_config run. The stale entry expires within the
    # short TTL anyway. Mirrors get_config's graceful DB-down degradation.
    try:
        cache.delete(_CACHE_PREFIX + key)
    except Exception:  # noqa: BLE001 — cache is non-critical for a write
        logger.warning("cache unavailable invalidating runtime config '%s'", key)


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


def _set_dotted(target: dict, dotted_key: str, value: Any) -> None:
    """Insert ``value`` into ``target`` at the nested location ``dotted_key``."""
    parts = dotted_key.split(".")
    node = target
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    leaf = parts[-1]
    if isinstance(node.get(leaf), dict) and isinstance(value, dict):
        node[leaf].update(value)
    else:
        node[leaf] = value


def get_scope_config(scope: str) -> dict:
    """Assemble a scope's effective sections (its own + ``shared``) into one
    nested dict, secrets overlaid from Vault via get_section. Shape matches
    settings.json."""
    sections = list(SCOPE_SECTIONS.get("shared", []))
    if scope != "shared":
        sections += SCOPE_SECTIONS.get(scope, [])
    result: dict = {}
    for section in sections:
        _set_dotted(result, section, get_section(section))
    return result
