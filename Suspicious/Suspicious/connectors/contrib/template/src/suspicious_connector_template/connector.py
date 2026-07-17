"""Template connector — copy this file (and rename the package) as the
starting point for your own Suspicious connector.

Full contract: docs/connectors.md in the Suspicious repo. The short version:

  - Subclass Connector, set a ConnectorManifest, implement health_check().
  - Only implement the hooks you subscribe to in manifest.events.
  - Every hook runs on a Celery worker with retries + a circuit breaker —
    your connector can be slow or flaky without affecting case processing.
  - Config lives under integrations.<manifest.name> and is handed to you
    as self.config in __init__; "secret" fields are Vault/settings.json-only,
    never stored in the DB or returned by the API.
"""
from __future__ import annotations

import logging

import requests

from connectors.base import (
    CaseEvent,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
)

logger = logging.getLogger("connectors.contrib.template")


class TemplateConnector(Connector):
    # CUSTOMIZE: manifest fields below. `name` is the one that matters most —
    # it's the slug everything else keys off (config section, breaker,
    # ledger, URL). Must match ^[a-z][a-z0-9_]{1,63}$.
    manifest = ConnectorManifest(
        name="template",
        version="0.1.0",
        author="you",
        description="Replace with what this connector actually does.",
        docs_url="https://example.com/docs",
        category="Ticketing",  # free text, shown in the UI connector list
        config_schema=(
            # "secret" fields are write-only from the API and masked on read —
            # manage the actual value in Vault (prod) or settings.json (dev).
            ConfigField("api_url", "url", required=True,
                        help="Base URL of the external service."),
            ConfigField("api_token", "secret", required=True),
            ConfigField("timeout_seconds", "int", default=10),
            ConfigField("verify_ssl", "bool", default=True),
        ),
        # Only list the events you actually implement a hook for below.
        events=(EVENT_CASE_CREATED, EVENT_CASE_FINALISED),
        # Remove this tuple entirely if you don't need a periodic sync().
        schedules=(Schedule(name="sync", interval_seconds=3600),),
        enabled_by_default=False,
    )

    def health_check(self) -> HealthStatus:
        """Cheap connectivity/auth probe — must never raise. Backs the
        "Test connection" button and the health chip in Settings → Connectors."""
        api_url = self.config.get("api_url")
        api_token = self.config.get("api_token")
        if not api_url or not api_token:
            return HealthStatus(ok=False, detail="api_url/api_token not configured")
        try:
            response = requests.get(
                f"{api_url.rstrip('/')}/health",
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=self.config.get("timeout_seconds", 10),
                verify=self.config.get("verify_ssl", True),
            )
            response.raise_for_status()
            return HealthStatus(ok=True, detail="reachable")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def on_case_created(self, event: CaseEvent) -> None:
        """Fires when a new case enters the pipeline. `event` is a frozen
        snapshot — re-fetch the Case by id if you need more than this."""
        # CUSTOMIZE: e.g. open a ticket, post a "new submission" message, etc.
        logger.info("case %s created (reporter=%s)", event.case_id, event.reporter_email)

    def on_case_finalised(self, event: CaseEvent) -> None:
        """Fires once scoring has produced a verdict. Can fire more than
        once for the same case (re-finalisation after late analyzer
        results) — keep this idempotent, e.g. upsert by event.case_id."""
        # CUSTOMIZE: e.g. push the verdict to a ticketing/SIEM/chat system.
        logger.info(
            "case %s finalised: %s (score=%s, confidence=%s)",
            event.case_id, event.results, event.final_score, event.confidence,
        )

    def sync(self) -> None:
        """Runs on the schedule declared in manifest.schedules, via Celery
        beat. Delete this method (and the schedules tuple above) if you
        don't need a periodic job."""
        # CUSTOMIZE: e.g. reconcile state with the external system.
        logger.info("template connector sync tick")
