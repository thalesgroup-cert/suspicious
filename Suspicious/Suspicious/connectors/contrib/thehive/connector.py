"""TheHive connector — config/health home for the challenge + campaign flows.

No lifecycle events: TheHive pushes are triggered by the challenge flow
(tasp/services/challenge.py) and AI phishing-campaign detection, which import
this package's modules directly. The connector gives those flows a single
config section, a health probe, and a Settings UI card."""
from __future__ import annotations

from common.http_client import make_session
from connectors.base import (
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
)


class TheHiveConnector(Connector):
    manifest = ConnectorManifest(
        name="thehive",
        version="1.0.0",
        author="Thales CERT",
        description="TheHive alerts for challenged cases and phishing campaigns.",
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("certificate_path", "str",
                        help="CA bundle path; empty = system trust store"),
        ),
    )

    def health_check(self) -> HealthStatus:
        url, key = self.config.get("url"), self.config.get("api_key")
        if not url or not key:
            return HealthStatus(ok=False, detail="url/api_key not configured")
        try:
            response = make_session().get(
                f"{url.rstrip('/')}/api/v1/user/current",
                headers={"Authorization": f"Bearer {key}"},
                timeout=10,
                verify=self.config.get("certificate_path") or True,
            )
            response.raise_for_status()
            return HealthStatus(ok=True, detail="authenticated")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))
