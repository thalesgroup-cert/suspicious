"""Boot-time seeding of connector secrets from settings.json into Vault.

Operators may set connector secrets (``integrations.<name>.<field>``) in
settings.json. When Vault is configured and reachable, this module copies any
such secret that Vault does not already hold into Vault at startup — so the
file stays an easy place to set them, while Vault becomes the source of truth
and UI-driven edits are never clobbered.

Scoped to connector secret fields only: these map to ``suspicious/data/
integrations/*``, the one path the app's read-mostly AppRole is allowed to
write. Boot-critical secrets (app.secret_key, database.password) and other
non-connector secrets stay Vault/ops-seeded by design.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def seed_connector_secrets_from_settings() -> None:
    """Seed missing connector secrets from settings.json into Vault.

    Seed-if-missing: a key is written only when Vault holds no non-empty value
    for it, so existing Vault values (including UI edits) are preserved. No-ops
    when no Vault is configured or when Vault is unreachable/sealed. Never
    raises — safe to call from ``AppConfig.ready()``.
    """
    if not os.environ.get("VAULT_ADDR"):
        return

    try:
        from connectors.registry import registry
        from suspicious import secrets as sec
        from suspicious._config_common import settings_get

        seeded = 0
        for name, cls in registry.all().items():
            for field in cls.manifest.config_schema:
                if field.type != "secret":
                    continue
                key = f"integrations.{name}.{field.key}"
                value = settings_get(key, "")
                if not value:
                    continue
                if sec.get_secret(key, ""):
                    continue
                sec.set_secret(key, value)
                seeded += 1
                logger.info(
                    "Seeded connector secret '%s' into Vault from settings.json", key
                )
        if seeded:
            logger.info(
                "Auto-seeded %d connector secret(s) into Vault from settings.json",
                seeded,
            )
    except Exception:  # noqa: BLE001 — must never break app startup
        logger.warning(
            "Connector secret auto-seed skipped (Vault unavailable or misconfigured)",
            exc_info=True,
        )
