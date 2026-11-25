"""Cortex connector: config, health and the analyzer catalogue sync.

Step 1 of the analysis-engine work: ``enabled`` gates only the sync and the
connector UI. Job starts, the webhook and reconcile still talk to Cortex
directly whatever the flag says.
"""
from __future__ import annotations

from connectors.base import (
    PROVIDER_KIND_ANALYSIS,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
)

_PLACEHOLDER_URL = "https://cortex.example.com"


class CortexConnector(Connector):
    manifest = ConnectorManifest(
        name="cortex",
        version="1.0.0",
        author="Thales CERT",
        category="Analysis",
        description=(
            "Syncs the Cortex analyzer catalogue every minute. Job starts still go to "
            "Cortex whatever the enabled flag says; gating them comes with the engine layer."
        ),
        provides=PROVIDER_KIND_ANALYSIS,
        enabled_by_default=True,
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("webhook_secret", "secret"),
            ConfigField("stale_job_timeout_seconds", "int", default=7200),
            ConfigField("analyzers.yara", "str"),
            ConfigField("analyzers.sandbox", "str"),
            ConfigField("analyzers.header", "str"),
            ConfigField("analyzers.file_info", "str"),
            ConfigField("analyzers.ai", "str"),
        ),
        schedules=(Schedule("sync", 60),),
    )

    def _missing(self) -> str:
        url = (self.config.get("url") or "").rstrip("/")
        missing = []
        if not url or url == _PLACEHOLDER_URL:
            missing.append("url")
        if not self.config.get("api_key"):
            missing.append("api_key")
        return ", ".join(missing)

    def health_check(self) -> HealthStatus:
        missing = self._missing()
        if missing:
            return HealthStatus(ok=False, detail=f"not configured: {missing}")
        try:
            import requests
            # The analyzer list needs the key (/api/status does not), so this also proves it.
            response = requests.get(
                f"{self.config['url'].rstrip('/')}/api/analyzer",
                params={"range": "all"},
                headers={"Authorization": f"Bearer {self.config['api_key']}"},
                timeout=2,
                proxies={"http": "", "https": ""},
            )
            if response.status_code in (401, 403):
                return HealthStatus(ok=False, detail=f"api key rejected (HTTP {response.status_code})")
            if not response.ok:  # any other 4xx/5xx: do not read an error page as "no analyzers"
                return HealthStatus(ok=False, detail=f"HTTP {response.status_code}")
            offered = {a.get("name") for a in response.json()}
        except Exception as exc:  # noqa: BLE001: a health check must not raise
            return HealthStatus(ok=False, detail=str(exc))
        absent = sorted(
            f"{role}={name}" for role, name in (self.config.get("analyzers") or {}).items()
            if role != "ai" and name and name not in offered
        )
        detail = f"{len(offered)} analyzers offered; {self._stats()}"
        if absent:
            return HealthStatus(ok=False, detail=f"roles not offered by Cortex: {', '.join(absent)}; {detail}")
        return HealthStatus(ok=True, detail=detail)

    @staticmethod
    def _stats() -> str:
        """Early signs of a broken webhook: old pending jobs and a quiet callback."""
        import time
        from datetime import timedelta

        from django.core.cache import cache
        from django.utils import timezone

        from cortex_job.models import Analyzer, CaseAnalyzerJob

        inactive = Analyzer.objects.filter(source="cortex", is_active=False).count()
        stuck = CaseAnalyzerJob.objects.filter(
            analyzer__source="cortex",
            status__in=CaseAnalyzerJob.PENDING_STATUSES,
            created_at__lt=timezone.now() - timedelta(minutes=30),
        ).count()
        last = cache.get("cortex_last_webhook_at")
        webhook = f"last webhook {int((time.time() - last) // 60)} min ago" if last else "no webhook seen"
        return f"{inactive} inactive, {stuck} jobs pending over 30 min, {webhook}"

    def sync(self) -> None:
        if self._missing():
            return
        from tasp.cron.sync_cortex import sync_cortex_analyzers
        sync_cortex_analyzers(strict=True)
