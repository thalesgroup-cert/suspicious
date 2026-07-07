"""Watcher connector — periodic sync of monitored/legit domains."""
from __future__ import annotations

from connectors.base import (
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
)


class WatcherConnector(Connector):
    manifest = ConnectorManifest(
        name="watcher",
        version="1.0.0",
        author="Thales CERT",
        category="Threat Intelligence",
        description="Sync monitored and legitimate domains from Watcher every 5 minutes.",
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("timeout", "int", default=10),
            ConfigField("verify_ssl", "bool", default=True),
        ),
        schedules=(Schedule("sync", 300),),
    )

    def health_check(self) -> HealthStatus:
        url, key = self.config.get("url"), self.config.get("api_key")
        if not url or not key:
            return HealthStatus(ok=False, detail="url/api_key not configured")
        try:
            import requests
            response = requests.get(
                f"{url.rstrip('/')}/api/site_monitoring/site/",
                params={"page_size": 1},
                headers={"Authorization": f"Token {key}", "Accept": "application/json"},
                timeout=int(self.config.get("timeout", 10)),
                verify=bool(self.config.get("verify_ssl", True)),
            )
            response.raise_for_status()
            return HealthStatus(ok=True, detail="reachable")
        except Exception as exc:  # noqa: BLE001 — health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def sync(self) -> None:
        from .sync import run_watcher_sync
        run_watcher_sync()
