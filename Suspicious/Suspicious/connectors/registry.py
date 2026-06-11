"""Connector discovery and registration.

Discovery sources, in order:
  1. Built-ins listed in connectors.contrib.BUILTIN_CONNECTOR_PATHS
  2. Entry points in the "suspicious.connectors" group (third-party packages)

A connector that fails to import or validate is recorded in ``errors`` and
skipped — a broken third-party package must never take the app down.
"""
from __future__ import annotations

import logging
from importlib import import_module, metadata

from connectors.base import Connector, Schedule

logger = logging.getLogger("connectors.registry")

ENTRY_POINT_GROUP = "suspicious.connectors"


class ConnectorRegistry:
    def __init__(self) -> None:
        self._classes: dict[str, type[Connector]] = {}
        self._errors: dict[str, str] = {}
        self._discovered = False

    # ── registration ──────────────────────────────────────────────────────

    def register(self, cls: type[Connector]) -> None:
        manifest = cls.manifest
        manifest.validate()
        if manifest.name in self._classes:
            raise ValueError(f"duplicate connector name {manifest.name!r}")
        self._classes[manifest.name] = cls
        self._contribute_config(manifest)
        from common.http_client import ensure_breaker
        ensure_breaker(manifest.name)
        logger.info("Registered connector %s v%s", manifest.name, manifest.version)

    @staticmethod
    def _contribute_config(manifest) -> None:
        """Make the connector's section visible to the runtime-config system:
        scope membership + Vault-overlaid secret leaves (supports dotted keys)."""
        from settings.config import SCOPE_SECTIONS, SECRET_FIELDS

        section = f"integrations.{manifest.name}"
        if section not in SCOPE_SECTIONS["backend"]:
            SCOPE_SECTIONS["backend"].append(section)
        for field in manifest.config_schema:
            if field.type != "secret":
                continue
            prefix, _, leaf = field.key.rpartition(".")
            target = f"{section}.{prefix}" if prefix else section
            existing = SECRET_FIELDS.get(target, ())
            if leaf not in existing:
                SECRET_FIELDS[target] = existing + (leaf,)

    # ── discovery ─────────────────────────────────────────────────────────

    def discover(self) -> None:
        if self._discovered:
            return
        self._discovered = True
        from connectors.contrib import BUILTIN_CONNECTOR_PATHS
        for path in BUILTIN_CONNECTOR_PATHS:
            self._load(path, builtin=True)
        try:
            entry_points = metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception:  # noqa: BLE001 — importlib metadata quirks
            entry_points = ()
        for entry_point in entry_points:
            try:
                self.register(entry_point.load())
            except Exception as exc:  # noqa: BLE001 — isolate bad plugins
                self._errors[entry_point.name] = str(exc)
                logger.exception("Failed to load connector entry point %s", entry_point.name)

    def _load(self, path: str, builtin: bool) -> None:
        module_path, _, attr = path.partition(":")
        try:
            self.register(getattr(import_module(module_path), attr))
        except Exception as exc:  # noqa: BLE001 — isolate bad connectors
            self._errors[path] = str(exc)
            logger.exception("Failed to load %s connector %s",
                             "builtin" if builtin else "external", path)

    # ── accessors ─────────────────────────────────────────────────────────

    def get(self, name: str) -> type[Connector]:
        return self._classes[name]

    def names(self) -> list[str]:
        return sorted(self._classes)

    def all(self) -> dict[str, type[Connector]]:
        return dict(self._classes)

    @property
    def errors(self) -> dict[str, str]:
        return dict(self._errors)

    def subscribers(self, event_name: str) -> list[str]:
        return [
            name for name, cls in sorted(self._classes.items())
            if event_name in cls.manifest.events
        ]

    def scheduled(self) -> list[tuple[str, Schedule]]:
        return [
            (name, schedule)
            for name, cls in sorted(self._classes.items())
            for schedule in cls.manifest.schedules
        ]

    def instantiate(self, name: str) -> Connector:
        from settings.config import get_section
        return self._classes[name](get_section(f"integrations.{name}"))


registry = ConnectorRegistry()
