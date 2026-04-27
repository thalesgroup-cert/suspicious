import logging
import requests
from django.db import transaction
from cortex4py.api import Api
from cortex4py.exceptions import CortexException
from .utils import load_config
from .models import CronConfig
from cortex_job.models import Analyzer
import pybreaker
from common.http_client import get_breaker, RETRY

logger = logging.getLogger("cron.sync_cortex")
log_analyzers = logging.getLogger("tasp.cron.fetch_analyzer")
CONFIG_PATH = "/app/settings.json"

_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_all_analyzers(api):
    """Fetch all remote analyzers with retry and circuit breaker."""
    with _cortex_breaker.calling():
        return api.analyzers.find_all({}, range="all")


def sync_cortex_analyzers(config_path: str = CONFIG_PATH) -> None:
    try:
        from api.metrics import (
            cortex_calls_total,
            cortex_errors_total,
            cortex_sync_duration_seconds,
        )
        _metrics_available = True
    except Exception:
        _metrics_available = False

    if _metrics_available:
        cortex_calls_total.inc()
        _timer = cortex_sync_duration_seconds.time()
        _timer.__enter__()

    try:
        _sync_cortex_analyzers_inner(config_path)
    except Exception:
        if _metrics_available:
            cortex_errors_total.labels(error_type="unexpected").inc()
        raise
    finally:
        if _metrics_available:
            _timer.__exit__(None, None, None)


def _sync_cortex_analyzers_inner(config_path: str = CONFIG_PATH) -> None:
    try:
        from api.metrics import cortex_errors_total
        _metrics_available = True
    except Exception:
        _metrics_available = False

    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    api = Api(str(cfg.cortex.url), cfg.cortex.api_key)

    # cortex4py makes bare requests.get/post calls — no session to mount adapters on.
    # Timeout protection comes from the RETRY decorator and circuit breaker.
    try:
        remote_analyzers = _fetch_all_analyzers(api)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open — sync_cortex_analyzers skipped: %s", exc)
        if _metrics_available:
            cortex_errors_total.labels(error_type="circuit_open").inc()
        return
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        if _metrics_available:
            cortex_errors_total.labels(error_type="api").inc()
        return
    except requests.RequestException as exc:
        log_analyzers.error("Network error syncing Cortex analyzers: %s", exc)
        if _metrics_available:
            cortex_errors_total.labels(error_type="network").inc()
        return

    if not remote_analyzers:
        return

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={"analyzer_cortex_id": analyzer.id, "is_active": True},
            )
            remote_names.append(analyzer.name)
        Analyzer.objects.exclude(name__in=remote_names).update(is_active=False)
