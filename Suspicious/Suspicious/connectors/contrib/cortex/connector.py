"""Cortex connector: the first analysis engine (catalog, start, fetch, webhook),
its health and the analyzer catalogue sync. ``enabled`` gates new job starts and
the sync; jobs already started are still fetched and their webhook still accepted.
"""
from __future__ import annotations

import hmac
import logging

from connectors.base import (
    FETCH_GONE,
    FETCH_RESULT,
    FETCH_UNKNOWN,
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    ConfigField,
    Connector,
    ConnectorManifest,
    FetchResult,
    HealthStatus,
    Schedule,
    StartResult,
    WebhookNotConfigured,
)

logger = logging.getLogger(__name__)

_PLACEHOLDER_URL = "https://cortex.example.com"


class CortexConnector(Connector):
    manifest = ConnectorManifest(
        name="cortex",
        version="1.0.0",
        author="Thales CERT",
        category="Analysis",
        description=(
            "Runs Cortex analyzers on new cases and syncs the Cortex analyzer catalogue every "
            "minute. Disabling it stops all new Cortex analysis; jobs already started still finish."
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

    def _api(self):
        """One client per connector instance (an engine instance lives for one dispatch)."""
        if getattr(self, "_client", None) is None:
            from cortex_job.cortex_utils.session_cortex_api import SessionCortexApi
            self._client = SessionCortexApi(
                self.config["url"].rstrip("/"), self.config["api_key"], proxies={"http": "", "https": ""}
            )
        return self._client

    def catalog(self, data_type: str | None = None, name: str | None = None) -> list[CatalogEntry]:
        if not data_type and not name:
            return self._full_catalog()
        try:
            api = self._api()
            found = api.analyzers.get_by_name(name) if name else api.analyzers.get_by_type(data_type)
            found = [found] if name and found else found  # None: a role Cortex does not offer
            return [
                CatalogEntry(a.id, a.name, tuple(getattr(a, "dataTypeList", None) or ()))
                for a in found or []
            ]
        except Exception as exc:  # noqa: BLE001: a failed lookup is an empty catalogue
            logger.warning("cortex catalog lookup failed: %s", type(exc).__name__)
            return []

    guarded = False  # True: _fetch_all_analyzers wraps the "cortex" breaker itself (legacy, non-strict sync)

    def _full_catalog(self) -> list[CatalogEntry]:
        """Every analyzer enabled for the org. Unlike the filtered lookups it raises on failure,
        so a failed sync is a failed sync."""
        from cortex4py.exceptions import AuthenticationError

        from tasp.cron import sync_cortex

        try:
            found = sync_cortex._fetch_all_analyzers(self._api(), guarded=self.guarded)
        except AuthenticationError as exc:
            exc.retryable = False  # a revoked or wrong API key waits for an operator, not a retry
            raise
        return [CatalogEntry(a.id, a.name, ()) for a in found]  # the sync needs no data types

    def start(self, analyzer: CatalogEntry, data_type: str, value: str) -> StartResult | None:
        if not value or not str(value).strip():
            return None
        payload = {
            "data": value,
            "dataType": "file" if data_type == "mail_body" else data_type,
            "tlp": 2,
        }
        from cortex4py.exceptions import InvalidInputError

        # Only a refusal is None: cortex4py maps a 4xx other than 401/403/404 to
        # InvalidInputError. An outage (auth, connection, timeout, 5xx) propagates.
        try:
            report = self._api().analyzers.run_by_name(analyzer.name, payload)
        except InvalidInputError as exc:
            logger.warning("Analyzer %r rejected %s input: %s", analyzer.name, data_type, type(exc).__name__)
            return None
        return StartResult(job_id=report.id) if report else None

    def fetch(self, job_id: str) -> FetchResult:
        import pybreaker
        from cortex4py.exceptions import NotFoundError

        from common.http_client import RETRY, get_breaker

        breaker = get_breaker("cortex")

        @RETRY
        def _job(api):
            with breaker.calling():
                return api.jobs.get_by_id(job_id)

        @RETRY
        def _report(api):
            with breaker.calling():
                return api.jobs.get_report(job_id)

        try:
            api = self._api()
            job = _job(api)
        except NotFoundError:
            return FetchResult(FETCH_GONE)
        except pybreaker.CircuitBreakerError:
            logger.warning("[breaker:cortex] open, fetch skipped for job %s", job_id)
            return FetchResult(FETCH_UNKNOWN)
        except Exception as exc:  # noqa: BLE001
            logger.error("Error fetching job %s: %s", job_id, type(exc).__name__)
            return FetchResult(FETCH_UNKNOWN)
        if not job:
            return FetchResult(FETCH_UNKNOWN)
        # Only a missing job is "gone"; any report failure just leaves the report absent.
        try:
            report = getattr(_report(api), "report", None) or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("No report for job %s: %s", job_id, type(exc).__name__)
            report = {}
        if not isinstance(report, dict):
            report = {}
        return FetchResult(
            FETCH_RESULT, job.status, report.get("summary"), report.get("full"),
            data_type=getattr(job, "dataType", "") or "",
        )

    def webhook(self, headers: dict, payload: dict) -> list[str] | None:
        from django.conf import settings

        secret = self.config.get("webhook_secret") or getattr(settings, "CORTEX_WEBHOOK_SECRET", "")
        if not secret:
            raise WebhookNotConfigured("webhook_secret")
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], secret):
            return None
        job_id = str(payload.get("jobId") or payload.get("job_id") or "").strip()
        return [job_id] if job_id else []
