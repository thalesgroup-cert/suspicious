"""MISP connector — pushes finalised cases as MISP events/objects."""
from __future__ import annotations

import logging

from case_handler.models import Case
from common.http_client import make_session
from connectors.base import (
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    EVENT_CASE_FINALISED,
)

from .service import MISPService

logger = logging.getLogger("connectors.contrib.misp")


class MISPConnector(Connector):
    manifest = ConnectorManifest(
        name="misp",
        version="1.0.0",
        author="Thales CERT",
        description="Push finalised cases (mail object, artifacts, IOCs) to MISP; "
                    "Suspicious/Dangerous verdicts also feed the secondary monthly event.",
        config_schema=(
            ConfigField("instances.primary.url", "url", required=True,
                        help="Primary MISP instance URL"),
            ConfigField("instances.primary.api_key", "secret", required=True),
            ConfigField("instances.primary.ssl_verify", "bool", default=False),
            ConfigField("instances.secondary.url", "url",
                        help="Secondary (security) MISP for monthly campaign events"),
            ConfigField("instances.secondary.api_key", "secret"),
            ConfigField("instances.secondary.ssl_verify", "bool", default=False),
        ),
        events=(EVENT_CASE_FINALISED,),
    )

    def health_check(self) -> HealthStatus:
        primary = self.config.get("instances", {}).get("primary", {})
        url, key = primary.get("url"), primary.get("api_key")
        if not url or not key:
            return HealthStatus(ok=False, detail="primary url/api_key not configured")
        try:
            response = make_session().get(
                f"{url.rstrip('/')}/servers/getVersion",
                headers={"Authorization": key, "Accept": "application/json"},
                timeout=10,
                verify=bool(primary.get("ssl_verify", False)),
            )
            response.raise_for_status()
            return HealthStatus(ok=True, detail=f"MISP {response.json().get('version', '?')}")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def on_case_finalised(self, event) -> None:
        case = Case.objects.get(pk=event.case_id)
        MISPService(primary=True).update_misp(case)
