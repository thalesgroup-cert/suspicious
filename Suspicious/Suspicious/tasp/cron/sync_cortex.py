import logging
import requests
from django.db import transaction
from cortex4py.api import Api
from cortex4py.exceptions import CortexException
from .utils import load_config
from .models import CronConfig
from cortex_job.models import Analyzer
import pybreaker
from common.http_client import TimeoutHTTPAdapter, get_breaker, RETRY

logger = logging.getLogger("cron.sync_cortex")
log_analyzers = logging.getLogger("tasp.cron.fetch_analyzer")
CONFIG_PATH = "/app/settings.json"

_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_all_analyzers(api):
    """Fetch all remote analyzers with retry and circuit breaker."""
    with _cortex_breaker:
        return api.analyzers.find_all({}, range="all")


def sync_cortex_analyzers(config_path: str = CONFIG_PATH) -> None:
    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    api = Api(str(cfg.cortex.url), cfg.cortex.api_key)

    # Mount a timeout adapter on cortex4py's internal session
    _adapter = TimeoutHTTPAdapter()
    try:
        api._Api__session.mount("https://", _adapter)
        api._Api__session.mount("http://", _adapter)
    except AttributeError:
        log_analyzers.warning(
            "Could not mount TimeoutHTTPAdapter on cortex4py session — "
            "timeout not guaranteed for Cortex calls"
        )

    try:
        remote_analyzers = _fetch_all_analyzers(api)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open — sync_cortex_analyzers skipped: %s", exc)
        return
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        return
    except requests.RequestException as exc:
        log_analyzers.error("Network error syncing Cortex analyzers: %s", exc)
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
