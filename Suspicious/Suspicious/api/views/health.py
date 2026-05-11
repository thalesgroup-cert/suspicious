"""
GET /api/health/

Cheap liveness + dependency probe used by:
- Docker Compose healthcheck for the `suspicious` service
- External monitoring (Tempo trace browser sidebar, future alerting)
- Operators tailing `make status`

Subsystem probes:
- db     : `SELECT 1` against the Django default connection
- redis  : `cache.set` + `cache.get` round-trip on the Django cache (Valkey)
- cortex : HTTP HEAD against the configured Cortex base URL (informational)

HTTP status:
- 200 when db + redis are healthy (Cortex flaps must not restart the container —
  app already degrades gracefully via tenacity + circuit breaker)
- 503 when either DB or Redis is unreachable

Endpoint is unauthenticated by design — Docker healthchecks cannot present
auth, and the payload only reveals subsystem reachability, not sensitive state.

Closes audit findings O7 + R9 (`docs/superpowers/specs/2026-05-06-audit/`).
"""
from __future__ import annotations

import logging

import requests
from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


# Network probe against Cortex must be short — we never want a slow
# Cortex to drag a single healthcheck above the compose `timeout`.
_CORTEX_PROBE_TIMEOUT_S = 2.0


class HealthView(APIView):
    """Liveness + dependency status."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request, *args, **kwargs):
        db_ok = _check_db()
        redis_ok = _check_redis()
        cortex_ok = _check_cortex()

        critical_failed = [
            name for name, ok in (("db", db_ok), ("redis", redis_ok)) if not ok
        ]
        http_status = 200 if not critical_failed else 503

        body = {
            "status": "ok" if not critical_failed else "degraded",
            "checks": {
                "db": db_ok,
                "redis": redis_ok,
                # Cortex is informational; surfaced but never flips the HTTP
                # status. Tenacity + the circuit breaker absorb transient
                # Cortex outages without taking the API down.
                "cortex": cortex_ok,
            },
            "failed": critical_failed,
        }
        return JsonResponse(body, status=http_status)


def _check_db() -> bool:
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
        return True
    except Exception:
        logger.warning("health: db probe failed", exc_info=True)
        return False


def _check_redis() -> bool:
    try:
        # Independent ping key so we never clobber real cache entries.
        cache.set("health:probe", "pong", timeout=5)
        return cache.get("health:probe") == "pong"
    except Exception:
        logger.warning("health: redis probe failed", exc_info=True)
        return False


def _check_cortex() -> bool | None:
    """Return True/False on a real probe, None when Cortex isn't configured."""
    try:
        from cortex_job.cortex_utils.cortex_and_job_management import API_URL
    except Exception:  # pragma: no cover — defensive import
        return None

    url = (API_URL or "").rstrip("/")
    if not url or url == "https://cortex.example.com":
        # Default placeholder from settings.py when no Cortex is configured.
        return None

    try:
        resp = requests.get(
            f"{url}/api/status",
            timeout=_CORTEX_PROBE_TIMEOUT_S,
            proxies={"http": "", "https": ""},
        )
    except requests.RequestException:
        return False
    # 200/401/403 all mean "Cortex process is up and serving HTTP"; we
    # don't authenticate this probe so any < 500 counts as reachable.
    return resp.status_code < 500
