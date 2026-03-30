# api/utils/settings_service.py
from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()


class SettingsListSectionService:
    """
    Central handler for all list-shaped settings sections.

    create_items() now returns a dict:
        {
            "created": [id, ...],          # IDs of newly created entries
            "duplicates": ["val", ...],    # values that already existed in this list
            "watcher_conflicts": ["val"],  # values already in the paired watcher list
        }
    so callers can give the user precise feedback.
    """

    # Maps section key → (model_import_path, value_field, fk_model_path, fk_field)
    # Extend this dict as new sections are added.
    _SECTION_MAP: dict[str, dict[str, Any]] = {
        "domains_allow": {
            "model": "settings.models.AllowListDomain",
            "value_model": "domain_process.models.Domain",
            "value_field": "value",
            "fk_field": "domain",
            "watcher_model": "settings.models.WatcherLegitDomain",
            "watcher_value_field": "domain__value",
        },
        "domains_deny": {
            "model": "settings.models.DenyListDomain",
            "value_model": "domain_process.models.Domain",
            "value_field": "value",
            "fk_field": "domain",
            "watcher_model": "settings.models.WatcherMonitoredDomain",
            "watcher_value_field": "domain__value",
        },
        "campaign_domains_allow": {
            "model": "settings.models.CampaignDomainAllowList",
            "value_model": "domain_process.models.Domain",
            "value_field": "value",
            "fk_field": "domain",
            "watcher_model": None,
        },
        "emails_files_allow": {
            "model": "settings.models.AllowListFile",
            "value_model": "hash_process.models.Hash",
            "value_field": "value",
            "fk_field": "linked_file_hash",
            "watcher_model": None,
        },
        "filetypes_allow": {
            "model": "settings.models.AllowListFiletype",
            "value_model": None,          # direct CharField, no FK
            "value_field": "filetype",
            "fk_field": None,
            "watcher_model": None,
        },
    }

    @classmethod
    def _resolve(cls, dotted: str):
        """Import a class by dotted path."""
        parts = dotted.rsplit(".", 1)
        import importlib
        mod = importlib.import_module(parts[0])
        return getattr(mod, parts[1])

    @classmethod
    def list_items(cls, section: str) -> list[dict]:
        """Return all items for a section as a list of {id, value, created_at}."""
        cfg = cls._SECTION_MAP.get(section)
        if cfg is None:
            return []

        Model = cls._resolve(cfg["model"])

        if cfg["fk_field"] is None:
            # Direct CharField
            qs = Model.objects.all().order_by("-creation_date")
            return [
                {
                    "id": str(obj.pk),
                    "value": getattr(obj, cfg["value_field"]),
                    "created_at": obj.creation_date.isoformat() if hasattr(obj, "creation_date") else None,
                }
                for obj in qs
            ]

        # FK to a value model
        fk = cfg["fk_field"]
        vf = cfg["value_field"]
        qs = Model.objects.select_related(fk).order_by("-creation_date")
        return [
            {
                "id": str(obj.pk),
                "value": getattr(getattr(obj, fk), vf, ""),
                "created_at": obj.creation_date.isoformat() if hasattr(obj, "creation_date") else None,
            }
            for obj in qs
        ]

    @classmethod
    def create_items(
        cls,
        section: str,
        values: list[str],
        user,
    ) -> dict[str, Any]:
        """
        Create items for the given section.

        Returns:
            {
                "created": [int/str, ...],      IDs of newly created entries
                "duplicates": [str, ...],       values already in this list
                "watcher_conflicts": [str, ...] values already in paired watcher list
            }
        """
        cfg = cls._SECTION_MAP.get(section)
        if cfg is None:
            return {"created": [], "duplicates": [], "watcher_conflicts": []}

        Model = cls._resolve(cfg["model"])

        created_ids: list = []
        duplicates: list[str] = []
        watcher_conflicts: list[str] = []

        # Pre-fetch watcher set for conflict detection
        watcher_set: set[str] = set()
        if cfg.get("watcher_model"):
            WatcherModel = cls._resolve(cfg["watcher_model"])
            watcher_vf = cfg.get("watcher_value_field", "")
            watcher_set = set(
                WatcherModel.objects.values_list(watcher_vf, flat=True)
            )

        for raw_value in values:
            value = raw_value.strip()
            if not value:
                continue

            # Check watcher conflict first
            if watcher_set and value in watcher_set:
                watcher_conflicts.append(value)
                continue

            if cfg["fk_field"] is None:
                # Direct CharField — check for existing
                if Model.objects.filter(**{cfg["value_field"]: value}).exists():
                    duplicates.append(value)
                    continue
                try:
                    obj = Model.objects.create(**{cfg["value_field"]: value, "user": user})
                    created_ids.append(obj.pk)
                except IntegrityError:
                    duplicates.append(value)
            else:
                # FK-based — get_or_create the value model, then the list entry
                ValueModel = cls._resolve(cfg["value_model"])
                value_obj, _ = ValueModel.objects.get_or_create(
                    **{cfg["value_field"]: value}
                )
                existing = Model.objects.filter(**{cfg["fk_field"]: value_obj}).exists()
                if existing:
                    duplicates.append(value)
                    continue
                try:
                    kwargs = {cfg["fk_field"]: value_obj, "user": user}
                    obj = Model.objects.create(**kwargs)
                    created_ids.append(obj.pk)
                except IntegrityError:
                    duplicates.append(value)

        return {
            "created": created_ids,
            "duplicates": duplicates,
            "watcher_conflicts": watcher_conflicts,
        }

    @classmethod
    def delete_item(cls, section: str, item_id: str) -> str:
        """Delete a single item by pk."""
        cfg = cls._SECTION_MAP.get(section)
        if cfg is None:
            raise ValueError(f"Unknown section: {section}")
        Model = cls._resolve(cfg["model"])
        obj = Model.objects.get(pk=item_id)
        obj.delete()
        return item_id