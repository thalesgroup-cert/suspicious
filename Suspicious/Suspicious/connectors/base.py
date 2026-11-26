"""Connector contract: manifest, config schema, lifecycle hooks, event payload.

This module is the public API third-party connector authors code against.
Changes to CaseEvent must be additive within a schema_version.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from urllib.parse import urlsplit
from dataclasses import asdict, dataclass
from typing import Any, ClassVar

EVENT_CASE_CREATED = "case_created"
EVENT_CASE_FINALISED = "case_finalised"
EVENT_CASE_MODIFIED = "case_modified"
EVENT_CAMPAIGN_UPDATED = "campaign_updated"
VALID_EVENTS = frozenset({
    EVENT_CASE_CREATED, EVENT_CASE_FINALISED, EVENT_CASE_MODIFIED, EVENT_CAMPAIGN_UPDATED,
})

# A connector whose manifest sets ``provides`` to "analysis" is an analysis engine (Cortex
# first; see Connector.catalog/start/fetch/run). Several may be enabled at once.
PROVIDER_KIND_ANALYSIS = "analysis"
VALID_PROVIDER_KINDS = frozenset({PROVIDER_KIND_ANALYSIS})

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


URL_ERROR = "must be an http or https URL with a host and no credentials"


def _dotted_get(data: dict, dotted: str):
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def valid_url(value) -> bool:
    """http or https, a host, a valid port if any, and no user or password in it. Any space,
    control character or DEL refuses it: urlsplit drops some silently (tab, CR, LF, leading
    controls), so the value would not be the one checked."""
    if not isinstance(value, str) or any(c <= " " or c == "\x7f" for c in value):
        return False
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 -- raises ValueError on a port out of range
    except ValueError:
        return False
    return (parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
            and "@" not in parts.netloc)


def url_errors(schema, config: dict) -> dict[str, str]:
    """{field key: URL_ERROR} for every ``url`` field of ``schema`` whose value in ``config`` is
    set and not a valid_url. None and "" are left to the required check. The message never
    carries the value: a URL can hold a secret."""
    errors = {}
    for field in schema:
        if field.type != "url":
            continue
        value = _dotted_get(config if isinstance(config, dict) else {}, field.key)
        if value not in (None, "") and not valid_url(value):
            errors[field.key] = URL_ERROR
    return errors


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


class WebhookNotConfigured(Exception):
    """The connector has no webhook secret: its webhook cannot authenticate anyone."""


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
    provides: str = ""  # "analysis" for an analysis engine, "" for a plain connector

    def validate(self) -> None:
        if not _SLUG_RE.match(self.name):
            raise ValueError(
                f"connector name {self.name!r} must match {_SLUG_RE.pattern}"
            )
        if self.provides and self.provides not in VALID_PROVIDER_KINDS:
            raise ValueError(
                f"unknown provides {self.provides!r} in connector {self.name!r}"
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
    campaign_id: int | None = None  # set on campaign_updated; the triggering case is case_id

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CaseEvent":
        if data.get("schema_version") != CASE_EVENT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported CaseEvent schema_version {data.get('schema_version')!r}"
            )
        return cls(**data)


FETCH_RESULT = "result"
FETCH_GONE = "gone"
FETCH_UNKNOWN = "unknown"

DATA_TYPE_MAIL_ARCHIVE = "mail_archive"


@dataclass(frozen=True)
class CatalogEntry:
    """One analyzer an analysis engine offers."""
    id: str
    name: str
    data_types: tuple[str, ...]


@dataclass(frozen=True)
class FetchResult:
    """A job lookup. ``status`` (Waiting|InProgress|Success|Failure) is set
    when ``state`` is FETCH_RESULT."""
    state: str
    status: str = ""
    summary: dict | None = None
    full: dict | None = None
    data_type: str = ""  # the engine's own dataType for the job, as reported
    payload: dict | None = None  # engine-specific result handed to on_result


@dataclass(frozen=True)
class StartResult:
    job_id: str
    finished: FetchResult | None = None
    deferred: bool = False  # the job runs later via Connector.run, not at start


class Connector(ABC):
    """Base class for all connectors. Subclasses set ``manifest`` and
    implement ``health_check`` plus whichever hooks they subscribe to."""

    manifest: ClassVar[ConnectorManifest]
    general_purpose: ClassVar[bool] = True

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Cheap connectivity/auth probe. Must not raise — return ok=False."""

    def is_inert(self) -> bool:
        """True when the connector is enabled but cannot analyse anything until configured further."""
        return False

    def on_case_created(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def on_case_finalised(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def on_case_modified(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def on_campaign_updated(self, event: CaseEvent) -> None:  # pragma: no cover
        raise NotImplementedError

    def sync(self) -> None:  # pragma: no cover
        raise NotImplementedError

    def catalog(self, data_type: str | None = None, name: str | None = None) -> list[CatalogEntry]:  # pragma: no cover
        raise NotImplementedError

    def start(self, analyzer: CatalogEntry, data_type: str, value: str) -> StartResult | None:  # pragma: no cover
        """None means the engine refused the job."""
        raise NotImplementedError

    def fetch(self, job_id: str) -> FetchResult:  # pragma: no cover
        raise NotImplementedError

    def webhook(self, headers: dict, payload: dict) -> list[str] | None:  # pragma: no cover
        """Job ids announced; None means rejected as unauthenticated. Raises WebhookNotConfigured
        when the connector has no webhook secret at all."""
        raise NotImplementedError

    def run(self, job_id: str, data_type: str, value: str) -> FetchResult:  # pragma: no cover
        """Execute a deferred job (see StartResult.deferred)."""
        raise NotImplementedError

    def on_started(self, case, analyzer_name: str) -> None:
        """Called after a job of this engine is started for ``case``. Does nothing by default."""

    def on_result(self, case, analyzer_name: str, result: FetchResult) -> None:
        """Called when a job of this engine reaches a result for ``case``. Does nothing by default.
        A job closed without a result (stale rescue, a lost enqueue, a dead worker, an instantiation
        failure) never reaches on_result: a deferred engine must put its 'no result' state in
        on_started."""
