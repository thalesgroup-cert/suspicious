"""Connector contract: manifest, config schema, lifecycle hooks, event payload.

This module is the public API third-party connector authors code against.
Changes to CaseEvent must be additive within a schema_version.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, ClassVar

EVENT_CASE_CREATED = "case_created"
EVENT_CASE_FINALISED = "case_finalised"
VALID_EVENTS = frozenset({EVENT_CASE_CREATED, EVENT_CASE_FINALISED})

FIELD_TYPES = frozenset({"str", "int", "bool", "url", "secret"})

_SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

CASE_EVENT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ConfigField:
    """One field of a connector's config section. ``key`` may be dotted
    (e.g. "instances.primary.api_key") to describe nested config."""
    key: str
    type: str = "str"
    required: bool = False
    default: Any = None
    help: str = ""


@dataclass(frozen=True)
class Schedule:
    """A periodic sync the connector wants. Registered into Celery beat as
    connectors.tasks.run_connector_sync(<connector name>)."""
    name: str
    interval_seconds: int


@dataclass(frozen=True)
class HealthStatus:
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class ConnectorManifest:
    name: str
    version: str
    description: str = ""
    author: str = ""
    docs_url: str = ""
    category: str = ""
    config_schema: tuple[ConfigField, ...] = ()
    events: tuple[str, ...] = ()
    schedules: tuple[Schedule, ...] = ()
    enabled_by_default: bool = False

    def validate(self) -> None:
        if not _SLUG_RE.match(self.name):
            raise ValueError(
                f"connector name {self.name!r} must match {_SLUG_RE.pattern}"
            )
        for event in self.events:
            if event not in VALID_EVENTS:
                raise ValueError(f"unknown event {event!r} in connector {self.name!r}")
        for field in self.config_schema:
            if field.type not in FIELD_TYPES:
                raise ValueError(
                    f"unknown config field type {field.type!r} for key {field.key!r}"
                )
        for schedule in self.schedules:
            if schedule.interval_seconds <= 0:
                raise ValueError(
                    f"schedule {schedule.name!r} interval must be > 0 seconds"
                )


@dataclass(frozen=True)
class CaseEvent:
    """Serializable snapshot of a case at emission time. The payload a
    connector hook receives — connectors needing more must re-fetch the
    Case by id themselves."""
    event: str
    case_id: int
    status: str
    results: str
    final_score: float | None
    confidence: float | None
    reporter_email: str
    created_at: str
    schema_version: int = CASE_EVENT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CaseEvent":
        if data.get("schema_version") != CASE_EVENT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported CaseEvent schema_version {data.get('schema_version')!r}"
            )
        return cls(**data)


class Connector(ABC):
    """Base class for all connectors. Subclasses set ``manifest`` and
    implement ``health_check`` plus whichever hooks they subscribe to."""

    manifest: ClassVar[ConnectorManifest]

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Cheap connectivity/auth probe. Must not raise — return ok=False."""

    def on_case_created(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def on_case_finalised(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def sync(self) -> None:  # pragma: no cover
        raise NotImplementedError
