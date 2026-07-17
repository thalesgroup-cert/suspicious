"""Seed the runtime config tier into RuntimeConfig from settings.json.

Idempotent (update_or_create per section). Secret leaf fields are stripped
before seeding — they live in Vault, provisioned separately. Wired into
`make deploy` after migrate.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from suspicious._config_common import load_settings, settings_get
from settings.config import SECRET_FIELDS
from settings.models import RuntimeConfig

def _strip_secrets(section: str, value: dict) -> dict:
    secrets = set(SECRET_FIELDS.get(section, ()))
    cleaned = {k: v for k, v in value.items() if k not in secrets}
    if section == "integrations.misp":
        inst = cleaned.get("instances")
        if isinstance(inst, dict):
            cleaned["instances"] = {
                name: {k: v for k, v in conf.items() if k != "api_key"}
                for name, conf in inst.items() if isinstance(conf, dict)
            }
    return cleaned


class Command(BaseCommand):
    help = "Seed runtime config (non-secret) from settings.json into the DB."

    def handle(self, *args, **options):
        from settings.config import SCOPE_SECTIONS, _scope_for_section
        load_settings.cache_clear()
        sections = [s for group in SCOPE_SECTIONS.values() for s in group]
        seeded = 0
        for section in sections:
            raw = settings_get(section, None)
            if not isinstance(raw, dict):
                continue
            value = _strip_secrets(section, raw)
            scope = _scope_for_section(section)
            RuntimeConfig.objects.update_or_create(
                scope=scope,
                key=section,
                defaults={"value": value},
            )
            RuntimeConfig.objects.filter(key=section).exclude(scope=scope).delete()
            seeded += 1
        self.stdout.write(self.style.SUCCESS(f"Seeded {seeded} runtime config sections."))
