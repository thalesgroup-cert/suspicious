"""Fixture analysis engine: answers instantly from the value itself, for tests and dev stacks
without Cortex. Never enable it in production: it scores anything it does not recognise as safe,
so it stays inert until ``confirm_fixture`` is exactly True. No network, no database."""
from __future__ import annotations

import logging
from uuid import uuid4

from connectors.base import (
    FETCH_GONE,
    FETCH_RESULT,
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    ConfigField,
    Connector,
    ConnectorManifest,
    FetchResult,
    HealthStatus,
    StartResult,
)

logger = logging.getLogger(__name__)
INERT = "fixture engine is inert: set confirm_fixture to true (never in production)"
_MALICIOUS = ("malicious", "phish", "evil")
_SUSPICIOUS = ("suspicious",)
_BY_TYPE = CatalogEntry("reputation", "Fixture_Reputation_1_0", ("url", "domain", "ip", "hash", "mail"))
_BY_NAME = (
    CatalogEntry("yara", "Fixture_Yara_1_0", ("file", "mail_body")),
    CatalogEntry("file_info", "Fixture_FileInfo_1_0", ("file",)),
    CatalogEntry("sandbox", "Fixture_Sandbox_1_0", ("file",)),
    CatalogEntry("header", "Fixture_Header_1_0", ("mail_header",)),
)


def _level(value: str) -> str:
    text = value.lower()  # most severe marker wins
    if any(marker in text for marker in _MALICIOUS):
        return "malicious"
    return "suspicious" if any(marker in text for marker in _SUSPICIOUS) else "safe"


class FixtureEngineConnector(Connector):
    manifest = ConnectorManifest(
        name="fixture_engine",
        version="1.0.0",
        author="Thales CERT",
        category="Analysis",
        description=(
            "Fake analysis engine for tests and dev stacks without Cortex: verdicts come from "
            "markers in the analysed value. Inert until confirm_fixture is set; never enable in production."
        ),
        provides=PROVIDER_KIND_ANALYSIS,
        enabled_by_default=False,
        config_schema=(ConfigField("confirm_fixture", "bool", default=False),),
    )
    CATALOG = (_BY_TYPE, *_BY_NAME)

    def _confirmed(self) -> bool:
        return self.config.get("confirm_fixture") is True  # not "true", not 1

    def is_inert(self) -> bool:
        return not self._confirmed()

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, detail="fixture engine active (dev only)") if self._confirmed() else HealthStatus(ok=False, detail=INERT)

    def catalog(self, data_type: str | None = None, name: str | None = None) -> list[CatalogEntry]:
        if not self._confirmed():
            logger.warning(INERT)
            return []
        if name:
            return [e for e in _BY_NAME if e.name == name]
        if data_type:
            return [_BY_TYPE] if data_type in _BY_TYPE.data_types else []
        return list(self.CATALOG)

    def start(self, analyzer: CatalogEntry, data_type: str, value) -> StartResult | None:
        if not self._confirmed() or value is None or not str(value).strip():
            return None
        text = str(value)
        level = _level(text)
        finished = FetchResult(
            FETCH_RESULT, "Success",
            summary={"taxonomies": [{"level": level, "namespace": "Fixture", "predicate": "Verdict", "value": level}]},
            full={"results": [{"threat": level, "value": text}]},
            data_type=data_type,
        )
        return StartResult(job_id=f"fixture-{uuid4().hex[:24]}", finished=finished)

    def fetch(self, job_id: str) -> FetchResult:
        return FetchResult(FETCH_GONE)  # an instant engine keeps nothing
